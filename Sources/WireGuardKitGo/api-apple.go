/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

package main

// #include <stdlib.h>
// #include <sys/types.h>
// static void callLogger(void *func, void *ctx, int level, const char *msg)
// {
// 	((void(*)(void *, int, const char *))func)(ctx, level, msg);
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
	"time"
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
		for {
			select {
			case <-signals:
				n := runtime.Stack(buf, true)
				buf[n] = 0
				if uintptr(loggerFunc) != 0 {
					C.callLogger(loggerFunc, loggerCtx, 0, (*C.char)(unsafe.Pointer(&buf[0])))
				}
			}
		}
	}()
}

//export wgSetLogger
func wgSetLogger(context, loggerFn uintptr) {
	loggerCtx = unsafe.Pointer(context)
	loggerFunc = unsafe.Pointer(loggerFn)
}

//export wgTurnOn
func wgTurnOn(settings *C.char, tunFd int32) int32 {
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

	err = dev.IpcSet(C.GoString(settings))
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

//export wgTurnOff
func wgTurnOff(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	delete(tunnelHandles, tunnelHandle)

	if dev.HealthCheckServer != nil {
		dev.HealthCheckServer.Close() // This will close the health check server
	}

	dev.Device.Close()

	if dev.Vtun != nil {
		dev.Vtun.Cancel() // This will close the proxy server
	}
}

//export wgSetConfig
func wgSetConfig(tunnelHandle int32, settings *C.char) int64 {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return 0
	}
	err := dev.Device.IpcSet(C.GoString(settings))
	if err != nil {
		dev.Logger.Errorf("Unable to set IPC settings: %v", err)
		if ipcErr, ok := err.(*device.IPCError); ok {
			return ipcErr.ErrorCode()
		}
		return -1
	}
	return 0
}

//export wgGetConfig
func wgGetConfig(tunnelHandle int32) *C.char {
	device, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return nil
	}
	settings, err := device.Device.IpcGet()
	if err != nil {
		return nil
	}
	return C.CString(settings)
}

//export wgBumpSockets
func wgBumpSockets(tunnelHandle int32) {
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

//export wgDisableSomeRoamingForBrokenMobileSemantics
func wgDisableSomeRoamingForBrokenMobileSemantics(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.Device.DisableSomeRoamingForBrokenMobileSemantics()
}

//export wgVersion
func wgVersion() *C.char {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return C.CString("unknown")
	}
	for _, dep := range info.Deps {
		if dep.Path == "golang.zx2c4.com/wireguard" {
			parts := strings.Split(dep.Version, "-")
			if len(parts) == 3 && len(parts[2]) == 12 {
				return C.CString(parts[2][:7])
			}
			return C.CString(dep.Version)
		}
	}
	return C.CString("unknown")
}

func StartWireGuardProxy(config, proxyAddress, username, password string) int32 {
	return wgProxyTurnOn(C.CString(config), C.CString(proxyAddress), C.CString(username), C.CString(password))
}

//export wgProxyTurnOn
func wgProxyTurnOn(configC *C.char, proxyAddressC, usernameC, passwordC *C.char) int32 {
	logger := &device.Logger{
		Verbosef: CLogger(0).Printf,
		Errorf:   CLogger(1).Printf,
	}
	// logger := device.NewLogger(device.LogLevelVerbose, "")

	config := C.GoString(configC)
	proxyAddress := C.GoString(proxyAddressC)
	username := C.GoString(usernameC)
	password := C.GoString(passwordC)

	// Append to WireGuard settings the proxy address and parse the config
	config += "\n[http]\nBindAddress = " + proxyAddress
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

func StartHealthCheckServer(tunnelHandle int32, addressC string) int32 {
	return wgStartHealthCheckServer(tunnelHandle, C.CString(addressC))
}

//export wgStartHealthCheckServer
func wgStartHealthCheckServer(tunnelHandle int32, addressC *C.char) int32 {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		dev.Logger.Errorf("Invalid tunnel handle: %d", tunnelHandle)
		return -1
	}

	tun := dev.Vtun
	address := C.GoString(addressC)

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
	return tunnelHandle
}

//export wgSuspendHealthCheckPings
func wgSuspendHealthCheckPings(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.Vtun.StopPingIPs()
}

//export wgResumeHealthCheckPings
func wgResumeHealthCheckPings(tunnelHandle int32) {
	dev, ok := tunnelHandles[tunnelHandle]
	if !ok {
		return
	}
	dev.Vtun.StartPingIPs()
}

func main() {

}
