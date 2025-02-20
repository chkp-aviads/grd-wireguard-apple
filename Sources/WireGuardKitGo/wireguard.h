/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2018-2021 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef void(*logger_fn_t)(void *context, int level, const char *msg);
extern void wgSetLogger(void *context, logger_fn_t logger_fn);
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
extern void wgRunGC();
extern const char *wgVersion();

#endif
