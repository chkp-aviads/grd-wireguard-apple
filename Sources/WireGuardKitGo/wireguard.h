/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

// General
typedef void(*logger_fn_t)(int context, int level, const char *msg);
extern void wgSetLogger(logger_fn_t logger_fn);
extern int wgLogContextWireGuard();
extern int wgLogContextTun2Socks();
extern void wgRunGC();
extern void wgPrintMemoryUsage(int handle);
extern void wgSetGCMemoryLimit(int limit, int maxThreads);

// WireGuard
extern int wgTurnOn(const char *settings, int32_t tun_fd);
extern int wgProxyTurnOn(const char *settings, const char *proxyAddress, const char *proxyUsername, const char *proxyPassword, bool isSocks);
extern void wgTurnOff(int handle);
extern int wgStartHealthCheckServer(int handle, const char *address);
extern void wgSuspendHealthCheckPings(int handle);
extern void wgResumeHealthCheckPings(int handle);
extern int64_t wgSetConfig(int handle, const char *settings);
extern char *wgGetConfig(int handle);
extern void wgBumpSockets(int handle);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern const char *wgVersion();

// Tun2Socks
extern int tunConnect(int32_t tun_fd, const char *socks5Proxy, int isUDPEnabled);
extern void tunDisconnectTunnel(int tunnelID);
extern int tunWriteToTunnel(int tunnelID, const char *data, int length);
extern int tunIsTunnelConnected(int tunnelID);

#endif
