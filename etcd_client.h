#ifndef _ETCD_CLIENT_H
#define _ETCD_CLIENT_H

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

struct etcd_cdc_ctx *etcd_init(void);
struct etcd_cdc_ctx *etcd_dup(struct etcd_cdc_ctx *ctx);
void etcd_exit(struct etcd_cdc_ctx *ctx);
int etcd_kv_put(struct etcd_cdc_ctx *ctx, char *key, char *value);
int etcd_kv_get(struct etcd_cdc_ctx *ctx, char *key, char *value);
int etcd_kv_range(struct etcd_cdc_ctx *ctx, char *key);
int etcd_kv_delete(struct etcd_cdc_ctx *ctx, char *key);
int etcd_kv_watch(struct etcd_cdc_ctx *ctx, char *key);

int etcd_lease_grant(struct etcd_cdc_ctx *ctx);
int etcd_lease_keepalive(struct etcd_cdc_ctx *ctx);
int etcd_lease_revoke(struct etcd_cdc_ctx *ctx);

#endif /* _ETCD_CLIENT_H */
