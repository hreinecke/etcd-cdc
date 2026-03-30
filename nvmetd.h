/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * nvmetd.h
 *
 * Copyright (c) 2024 Hannes Reinecke <hare@suse.de>
 */
#ifndef _NVMETD_H
#define _NVMETD_H

extern bool inotify_debug;

struct watcher_ctx {
	struct etcd_ctx *etcd;
	int path_fd;
	int inotify_fd;
};

void *inotify_loop(void *arg);
int start_inotify(struct watcher_ctx *ctx);
void stop_inotify(struct watcher_ctx *ctx);

#endif /* _NVMETD_H */
