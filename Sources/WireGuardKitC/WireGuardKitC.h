// SPDX-License-Identifier: MIT
// Copyright © 2018-2021 WireGuard LLC. All Rights Reserved.

#include <stdint.h>

#ifdef __OBJC__
#import <Foundation/Foundation.h>
#endif

#define CTLIOCGINFO 0xc0644e03UL

#if TARGET_OS_IOS
/* From <sys/kern_control.h> */
struct ctl_info {
    unsigned int   ctl_id;
    char        ctl_name[96];
};

struct sockaddr_ctl {
    unsigned char      sc_len;
    unsigned char      sc_family;
    unsigned short   ss_sysaddr;
    unsigned int   sc_id;
    unsigned int   sc_unit;
    unsigned int   sc_reserved[5];
};
#else
#include <sys/kern_control.h>
#endif
