/*
 * nvmet_watcher.h
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
#ifndef _ETCD_CDC_H
#define _ETCD_CDC_H

enum kv_key_op {
	KV_KEY_OP_ADD,
	KV_KEY_OP_DELETE,
	KV_KEY_OP_GET,
	KV_KEY_OP_RANGE,
	KV_KEY_OP_WATCH,
};

struct etcd_cdc_ctx {
	char *proto;
	char *host;
	int port;
	char *hostnqn;
	char *configfs;
	char *prefix;
	int debug;
	int64_t lease;
	int ttl;
	bool disconnect_ctrls;
	struct json_tokener *tokener;
	struct json_object *resp_obj;
	void (*watch_cb)(struct etcd_cdc_ctx *, enum kv_key_op,
			 char *, const char *);
};

int process_inotify_event(struct etcd_cdc_ctx *, char *, int);
int watch_port_dir(struct etcd_cdc_ctx *);
int watch_subsys_dir(struct etcd_cdc_ctx *);
void cleanup_watcher(void);

int etcd_kv_put(struct etcd_cdc_ctx *ctx, char *key, char *value);
int etcd_kv_get(struct etcd_cdc_ctx *ctx, char *key);
int etcd_kv_range(struct etcd_cdc_ctx *ctx, char *key);
int etcd_kv_delete(struct etcd_cdc_ctx *ctx, char *key);
int etcd_kv_watch(struct etcd_cdc_ctx *ctx, char *key);

int etcd_lease_grant(struct etcd_cdc_ctx *ctx);
int etcd_lease_keepalive(struct etcd_cdc_ctx *ctx);
int etcd_lease_revoke(struct etcd_cdc_ctx *ctx);

extern int inotify_fd;
extern int debug;

#endif /* _ETCD_CDC_H */
