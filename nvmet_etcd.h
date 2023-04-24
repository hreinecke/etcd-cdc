/*
 * nvmet_etcd.h
 * decentralized NVMe discovery controller
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */
#ifndef _NVMET_ETCD_H
#define _NVMET_ETCD_H

#include "etcd_client.h"

int set_genctr(struct etcd_cdc_ctx *ctx, int genctr);
int process_inotify_event(struct etcd_cdc_ctx *, char *, int);
int watch_port_dir(struct etcd_cdc_ctx *);
int watch_subsys_dir(struct etcd_cdc_ctx *);
void cleanup_watcher(void);

extern int inotify_fd;
extern int debug;

#endif /* _NVMET_ETCD_H */
