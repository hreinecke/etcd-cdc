/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * common.h
 * Common definitions for NVMe-over-TCP userspace daemon
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>. All rights reserved.
 */
#ifndef __COMMON_H__
#define __COMMON_H__

#define unlikely __glibc_unlikely

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>

#include "utils.h"

extern bool fuse_debug;
extern bool configfs_debug;
extern bool etcd_debug;
extern bool http_debug;

#define NVMET_CONFIGFS "/sys/kernel/config/nvmet"
#define NOFUSE_NGUID_PREFIX "0efd376f6e756665"

extern int stopped;

#endif
