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

extern bool fuse_debug;
extern bool configfs_debug;
extern bool etcd_debug;
extern bool http_debug;

#define NVMET_CONFIGFS "/sys/kernel/config/nvmet"
#define NOFUSE_NGUID_PREFIX "0efd376f6e756665"

#define CLUSTER_MAX_SIZE 65520
#define CLUSTER_DEFAULT_SIZE 16

#define NODE_MAX_PORTS 255

#define CLUSTER_PORT_OFFSET(c) (((c)->cluster_id + 1) << 8)
#define PORT_CLUSTER_ID(p) (((p) >> 8) - 1)

extern int stopped;

#endif
