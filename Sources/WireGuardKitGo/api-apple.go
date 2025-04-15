/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #include <stdint.h>
// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
// }
// static int callWriteFunc(void *func, const char* data, int length)
// {
// 	return ((int(*)(const char*, int))func)(data, length);
// }
// static int callCloseFunc(void *func)
// {
// 	return ((int(*)())func)();
// }
import "C"

import (
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"
	"tun2socks"
	"unsafe"
	"wireproxy"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

var loggerFunc unsafe.Pointer
var loggerCtx unsafe.Pointer

type CLogger int

func cstring(s string) *C.char {
	b, err := unix.BytePtrFromString(s)
	if err != nil {
		b := [1]C.char{}
		return &b[0]
	}
	return (*C.char)(unsafe.Pointer(b))
}

func (l CLogger) Printf(format string, args ...interface{}) {
	if uintptr(loggerFunc) == 0 {
		return
	}
	C.callLogger(loggerFunc, loggerCtx, C.int(l), cstring(fmt.Sprintf(format, args...)))
}

type tunnelHandle struct {
	Device            *device.Device
	Logger            *device.Logger
	Vtun              *wireproxy.VirtualTun
	HealthCheckServer *http.Server
}

var tunnelHandles = make(map[int32]tunnelHandle)
var proxyHandles = make(map[int32]wireproxy.VirtualTun)

func init() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, unix.SIGUSR2)
	go func() {
		buf := make([]byte, os.Getpagesize())
		for range signals {
			n := runtime.Stack(buf, true)
			buf[n] = 0
			if uintptr(loggerFunc) != 0 {
				C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
			}
		}
	}()

	// Apple VPN extensions have a memory limit of 15MB. Conserve memory by increasing garbage
	// collection frequency and returning memory to the OS every minute.
	debug.SetGCPercent(10)
	// Limit the number of OS threads to 2.
	runtime.GOMAXPROCS(2)
	// TODO: Check if this is still needed in go 1.13, which returns memory to the OS
	// automatically.
	ticker := time.NewTicker(time.Minute * 1)
	go func() {
		for range ticker.C {
			debug.FreeOSMemory()
		}
	}()
}

//export  wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	WGSetLogger(context, loggerFn)
}

func WGSetLogger(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
}

//export  wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
	settingsStr := C.GoString(settings)
	return WGTurnOn(settingsStr, tunFd)
}

func WGTurnOn(settings string, tunFd int32) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	dupTunFd, err := unix.Dup(int(tunFd))
	if err != nil {
		logger.Errorf("Unable to dup tun fd: %v", err)
		return -1
	}

	err = unix.SetNonblock(dupTunFd, true)
	if err != nil {
		logger.Errorf("Unable to set tun fd as non blocking: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	tun, err := tun.CreateTUNFromFile(os.NewFile(uintptr(dupTunFd), "/dev/tun"), 0)
	if err != nil {
		logger.Errorf("Unable to create new tun device from fd: %v", err)
		unix.Close(dupTunFd)
		return -1
	}
	logger.Verbosef("Attaching to interface")
	dev := device.NewDevice(tun, conn.NewStdNetBind(), logger)

	err = dev.IpcSet(settings)
	if err != nil {
		logger.Errorf("Unable to set IPC settings: %v", err)
		unix.Close(dupTunFd)
		return -1
	}

	dev.Up()
	logger.Verbosef("Device started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		unix.Close(dupTunFd)
		return -1
	}
	tunnelHandles[i] = tunnelHandle{dev, logger, nil, nil}
	return i
}

//export  wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	WGTurnOff(tunnelHandle)
}

func WGTurnOff(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	delete(tunnelHandles, tunnelHandle)

	if dev.HealthCheckServer != nil {
		dev.Vtun.StopPingIPs()
		dev.HealthCheckServer.Close() // This will close the health check server
	}

	dev.Device.Close()

	if dev.Vtun != nil {
		dev.Vtun.Cancel() // This will close the proxy server
	}
}

//export  wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	settingsStr := C.GoString(settings)
	return WGSetConfig(tunnelHandle, settingsStr)
}

func WGSetConfig(tunnelHandle int32, settings string) int64 {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return 0
	}
	err := dev.Device.IpcSet(settings)
	if err != nil {
		dev.Logger.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return -1
	}
	return 0
}

//export  wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	settings := WGGetConfig(tunnelHandle)
	if settings == nil {
		return nil
	}
	return C.CString(*settings)
}

func WGGetConfig(tunnelHandle int32) *string {
	device, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return nil
	}
	settings, err := device.Device.IpcGet()
	if err != nil {
		return nil
	}
	return &settings
}

//export  wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
	WGBumpSockets(tunnelHandle)
}

func WGBumpSockets(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	go func() {
		for i := 0; i < 10; i++ {
			err := dev.Device.BindUpdate()
			if err == nil {
				dev.Device.SendKeepalivesToPeersWithCurrentKeypair()
				return
			}
			dev.Logger.Errorf("Unable to update bind, try %d: %v", i+1, err)
			time.Sleep(time.Second / 2)
		}
		dev.Logger.Errorf("Gave up trying to update bind; tunnel is likely dysfunctional")
	}()
}

//export  wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	WGDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle)
}

func WGDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.Device.DisableSomeRoamingForBrokenMobileSemantics()
}

//export  wgVersion
func wgVersion() *C.char {
	return C.CString(WGVersion())
}

func WGVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return parts[2][:7]
			}
			return dep.Version
		}
	}
	return "unknown"
}

//export  wgProxyTurnOn
func wgProxyTurnOn(configC *C.char, proxyAddressC, usernameC, passwordC *C.char, isSocks bool) int32 {
	return WGProxyTurnOn(C.GoString(configC), C.GoString(proxyAddressC), C.GoString(usernameC), C.GoString(passwordC), isSocks)
}

func WGProxyTurnOn(config, proxyAddress, username, password string, isSocks bool) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	// logger := device.NewLogger(device.LogLevelVerbose, "")

	// Append to WireGuard settings the proxy address and parse the config
	var proxyType string
	if isSocks {
		proxyType = "Socks5"
	} else {
		proxyType = "http"
	}
	config += "\n[" + proxyType + "]\nBindAddress = " + proxyAddress
	config += "\nUsername = " + username
	config += "\nPassword = " + password
	conf, err := wireproxy.ParseConfigFromString(config)
	if err != nil {
		logger.Errorf("Unable to parse config: %v", err)
		return -1
	}

	// Start the WireGuard device
	tun, err := wireproxy.StartWireguard(conf.Device, logger)
	if err != nil {
		logger.Errorf("Unable to start WireGuard: %v", err)
		return -1
	}
	logger.Verbosef("WireGuard device started")

	for _, spawner := range conf.Routines {
		go spawner.SpawnRoutine(tun)
	}

	tun.StartPingIPs()
	logger.Verbosef("Proxy server started")

	var i int32
	for i = 0; i < math.MaxInt32; i++ {
		if _, exists := tunnelHandles[i]; !exists {
			break
		}
	}
	if i == math.MaxInt32 {
		return -1
	}
	tunnelHandles[i] = tunnelHandle{tun.Dev, logger, tun, nil}
	return i
}

//export  wgStartHealthCheckServer
func wgStartHealthCheckServer(tunnelHandle int32, addressC *C.char) int32 {
	return WGStartHealthCheckServer(tunnelHandle, C.GoString(addressC))
}

func WGStartHealthCheckServer(tunnelHandle int32, address string) int32 {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		dev.Logger.Errorf("Invalid tunnel handle: %d", tunnelHandle)
		return -1
	}

	tun := dev.Vtun

	server := &http.Server{
		Addr:    address,
		Handler: tun,
	}

	// Try to listen on the given address
	listener, err := net.Listen("tcp", address)
	if err != nil {
		dev.Logger.Errorf("Unable to listen on address %s: %v", address, err)
		return -1
	}

	go func() {
		err := server.Serve(listener)
		if err != nil && err != http.ErrServerClosed {
			dev.Logger.Errorf("Unable to start health check server: %v", err)
		} else if err == http.ErrServerClosed {
			dev.Logger.Verbosef("Health check server closed")
		}
	}()

	dev.Logger.Verbosef("Health check server started")
	dev.HealthCheckServer = server
	tunnelHandles[tunnelHandle] = dev
	return tunnelHandle
}

//export  wgSuspendHealthCheckPings
func wgSuspendHealthCheckPings(tunnelHandle int32) {
	WGSuspendHealthCheckPings(tunnelHandle)
}

func WGSuspendHealthCheckPings(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.Vtun.StopPingIPs()
}

//export  wgResumeHealthCheckPings
func wgResumeHealthCheckPings(tunnelHandle int32) {
	WGResumeHealthCheckPings(tunnelHandle)
}

func WGResumeHealthCheckPings(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.Vtun.StartPingIPs()
}

//export  wgRunGC
func wgRunGC() {
	WGRunGC()
}

func WGRunGC() {
	runtime.GC()         // run GC
	debug.FreeOSMemory() // free memory to OS
}

//export  wgSetGCMemoryLimit
func wgSetGCMemoryLimit(limit int, maxThreads int) {
	WGSetGCMemoryLimit(limit, maxThreads)
}

func WGSetGCMemoryLimit(limit int, maxThreads int) {
	debug.SetGCPercent(limit)
	runtime.GOMAXPROCS(maxThreads)
}

//export  wgPrintMemoryUsage
func wgPrintMemoryUsage(tunnelHandle int32) {
	WGPrintMemoryUsage(tunnelHandle)
}

func WGPrintMemoryUsage(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	dev.Logger.Verbosef("Alloc = %v MB\n", m.Alloc/1024/1024)           // Current allocated memory
	dev.Logger.Verbosef("TotalAlloc = %v MB\n", m.TotalAlloc/1024/1024) // Total allocated (ever)
	dev.Logger.Verbosef("Sys = %v MB\n", m.Sys/1024/1024)               // Total memory obtained from OS
	dev.Logger.Verbosef("HeapAlloc = %v MB\n", m.HeapAlloc/1024/1024)   // Heap memory
	dev.Logger.Verbosef("HeapSys = %v MB\n", m.HeapSys/1024/1024)       // Heap memory requested from OS
	dev.Logger.Verbosef("NumGC = %v\n\n", m.NumGC)                      // Number of garbage collections
}

////////////// TUN2SOCKS //////////////

// C-compatible TunWriter implementation
type cTunWriter struct {
	writeFunc func([]byte) (int, error)
	closeFunc func() error
}

var (
	tunWriterMap    = make(map[int32]*cTunWriter)
	tunWriterMutex  sync.Mutex
	nextTunWriterID int32 = 1
)

func (w *cTunWriter) Write(p []byte) (int, error) {
	return w.writeFunc(p)
}

func (w *cTunWriter) Close() error {
	return w.closeFunc()
}

// NewTunWriter creates a new TunWriter instance using the provided function pointers.
// The `writeFn` pointer must point to a C function with the signature `int(const char*, int)`
// that writes data and returns the number of bytes written or a negative value on failure.
// The `closeFn` pointer must point to a C function with the signature `int()`
// that closes the writer and returns 0 on success or a negative value on failure.
// If either pointer is invalid (e.g., null), the function returns -1.
//
//export NewTunWriter
func NewTunWriter(writeFn uintptr, closeFn uintptr) int32 {
	if writeFn == 0 || closeFn == 0 {
		return -1 // Invalid function pointers
	}

	// Store the function pointers in Go-managed memory
	writeFunc := writeFn
	closeFunc := closeFn

	// Wrap the C function pointers in Go functions
	goWriteFunc := func(data []byte) (int, error) {
		if len(data) == 0 {
			return 0, fmt.Errorf("data slice is empty")
		}

		cData := (*C.char)(unsafe.Pointer(&data[0]))
		length := C.int(len(data))
		// Cast the function pointer and call it
		result := C.callWriteFunc(unsafe.Pointer(writeFunc), cData, length)
		if result < 0 {
			return 0, fmt.Errorf("write failed")
		}
		return int(result), nil
	}

	goCloseFunc := func() error {
		// Cast the function pointer and call it
		result := C.callCloseFunc(unsafe.Pointer(closeFunc))
		if result < 0 {
			return fmt.Errorf("close failed")
		}
		return nil
	}

	tunWriter := &cTunWriter{
		writeFunc: goWriteFunc,
		closeFunc: goCloseFunc,
	}

	tunWriterMutex.Lock()
	defer tunWriterMutex.Unlock()

	id := nextTunWriterID
	nextTunWriterID++
	tunWriterMap[id] = tunWriter
	return id
}

//export FreeTunWriter
func FreeTunWriter(writerID int32) {
	tunWriterMutex.Lock()
	defer tunWriterMutex.Unlock()

	delete(tunWriterMap, writerID)
}

var (
	tunnelMap    = make(map[int32]tun2socks.Tunnel)
	tunnelMutex  sync.Mutex
	nextTunnelID int32 = 1
)

//export tunConnect
func tunConnect(writerID int32, socks5Proxy *C.char, isUDPEnabled C.int) int32 {
	tunWriterMutex.Lock()
	tunWriter, exists := tunWriterMap[writerID]
	tunWriterMutex.Unlock()

	if !exists {
		return -1 // Writer not found
	}

	tunnel, err := tun2socks.Connect(tunWriter, C.GoString(socks5Proxy), isUDPEnabled != 0)
	if err != nil {
		return -1 // Return -1 to indicate an error
	}

	tunnelMutex.Lock()
	defer tunnelMutex.Unlock()

	id := nextTunnelID
	nextTunnelID++
	tunnelMap[id] = tunnel
	return id
}

//export tunDisconnectTunnel
func tunDisconnectTunnel(tunnelID int32) {
	tunnelMutex.Lock()
	defer tunnelMutex.Unlock()

	if tunnel, exists := tunnelMap[tunnelID]; exists {
		tunnel.Disconnect()
		delete(tunnelMap, tunnelID)
	}
}

//export tunWriteToTunnel
func tunWriteToTunnel(tunnelID int32, data *C.char, length C.int) int32 {
	tunnelMutex.Lock()
	defer tunnelMutex.Unlock()

	tunnel, exists := tunnelMap[tunnelID]
	if !exists {
		return -1 // Tunnel not found
	}

	goData := C.GoBytes(unsafe.Pointer(data), length)
	n, err := tunnel.Write(goData)
	if err != nil {
		return -1 // Write failed
	}
	return int32(n)
}

//export tunIsTunnelConnected
func tunIsTunnelConnected(tunnelID int32) bool {
	tunnelMutex.Lock()
	defer tunnelMutex.Unlock()

	tunnel, exists := tunnelMap[tunnelID]
	if !exists {
		return false
	}
	return tunnel.IsConnected()
}

// main is required for the c-archive build mode, but it can be empty.
func main() {}
