#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <uuid/uuid.h>

#include "common.h"
#include "nvme.h"
#include "firmware.h"
#include "etcd/client.h"
#include "etcd/backend.h"

struct key_value_template {
	const char *key;
	const char *value;
};

int etcd_set_discovery_nqn(struct etcd_ctx *ctx, const char *buf,
			   size_t buf_len)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/discovery_nqn", ctx->prefix);
	if (ret < 0)
		return ret;
	ret = etcd_kv_store(ctx, key, buf, buf_len);
	free(key);
	return ret;
}

int etcd_get_discovery_nqn(struct etcd_ctx *ctx, char *buf, size_t buf_len)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/discovery_nqn", ctx->prefix);
	if (ret < 0)
		return ret;

	ret = etcd_kv_get(ctx, key, buf, buf_len);
	free(key);
	return ret;
}

static int _count_key_range(struct etcd_ctx *ctx, char *key, int *num)
{
	struct etcd_kv *kvs;
	int val = 0, ret, i;

	ret = etcd_kv_range(ctx, key, &kvs);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		if (!strncmp(kv->key, key, strlen(key)))
			val++;
	}
	etcd_kv_free(kvs, ret);
	*num = val;
	return 0;
}

int etcd_count_root(struct etcd_ctx *ctx, const char *root, int *nlinks)
{
	struct etcd_kv *kvs;
	char *key, *attr;
	int ret, num = 0, i;
	bool skip_referrals = false;

	ret = asprintf(&key, "%s/%s", ctx->prefix, root);
	if (ret < 0)
		return ret;
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;

	if (!strcmp(root, "hosts"))
		attr = "dhchap_key";
	else if (!strcmp(root, "subsystems"))
		attr = "attr_allow_any_host";
	else if (!strcmp(root, "ports")) {
		attr = "addr_traddr";
		skip_referrals = true;
	} else if (!strcmp(root, "cluster"))
		attr = "node_name";
	else
		return -EINVAL;

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];
		const char *p;

		if (skip_referrals && strstr(kv->key, "/referrals/"))
			continue;
		p = strrchr(kv->key, '/');
		if (p) {
			p++;
			if (!strcmp(p, attr))
				num++;
		}
	}
	etcd_kv_free(kvs, ret);
	*nlinks = num;
	return 0;
}

int etcd_fill_root(struct etcd_ctx *ctx, const char *root,
		   void *buf, fuse_fill_dir_t filler)
{
	struct etcd_kv *kvs;
	char *key, *val, *attr, *p;
	int ret, key_offset, i;
	bool skip_referrals = false;

	ret = asprintf(&key, "%s/%s/", ctx->prefix, root);
	if (ret < 0)
		return ret;

	if (!strcmp(root, "hosts"))
		attr = "dhchap_hash";
	else if (!strcmp(root, "subsystems"))
		attr = "attr_allow_any_host";
	else if (!strcmp(root, "ports")) {
		attr = "addr_traddr";
		skip_referrals = true;
	} else if (!strcmp(root, "cluster"))
		attr = "node_name";
	else
		return -EINVAL;

	key_offset = strlen(key);
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0) {
		free(key);
		return ret;
	}

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		if (skip_referrals && strstr(kv->key, "/referrals/"))
			continue;
		p = strrchr(kv->key, '/');
		if (p) {
			p++;
			if (!strcmp(p, attr)) {
				val = strdup(kv->key + key_offset);
				p = strchr(val, '/');
				if (p)
					*p = '\0';
				filler(buf, val, NULL, 0, FUSE_FILL_DIR_PLUS);
				free(val);
			}
		}
	}
	etcd_kv_free(kvs, ret);
	return 0;
}

int etcd_fill_host_dir(struct etcd_ctx *ctx, void *buf, fuse_fill_dir_t filler)
{
	return etcd_fill_root(ctx, "hosts", buf, filler);
}

int etcd_fill_host(struct etcd_ctx *ctx, const char *nqn,
		   void *buf, fuse_fill_dir_t filler)
{
	struct etcd_kv *kvs;
	int i, ret;
	char *key;

	ret = asprintf(&key, "%s/hosts/%s",
		       ctx->prefix, nqn);
	if (ret < 0)
		return ret;

	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];
		char *p;

		p = strrchr(kv->key, '/');
		if (p)
			filler(buf, p + 1, NULL, 0, FUSE_FILL_DIR_PLUS);
	}
	etcd_kv_free(kvs, ret);
	return 0;
}

#define NUM_HOST_ATTRS 4
static struct key_value_template host_template[NUM_HOST_ATTRS] = {
	{ .key = "dhchap_key", .value = "" },
	{ .key = "dhchap_hash", .value = "sha(256)" },
	{ .key = "dhchap_dhgroup", .value = "" },
	{ .key = "dhchap_ctrl_key", .value = "" },
};

int etcd_add_host(struct etcd_ctx *ctx, const char *nqn)
{
	int ret, i;

	for (i = 0; i < NUM_HOST_ATTRS; i++) {
		struct key_value_template *kv = &host_template[i];
		char *key;

		ret = asprintf(&key, "%s/hosts/%s/%s",
			       ctx->prefix, nqn, kv->key);
		if (ret < 0)
			return ret;
		ret = etcd_kv_store(ctx, key, (char *)kv->value,
				    strlen(kv->value));
		free(key);
		if (ret < 0)
			return -errno;
	}
	return 0;
}

int etcd_test_host(struct etcd_ctx *ctx, const char *nqn)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/hosts/%s/dhchap_hash",
		       ctx->prefix, nqn);
	if (ret < 0)
		return ret;

	ret = etcd_kv_get(ctx, key, NULL, 0);
	free(key);
	return ret;
}

int etcd_get_host_attr(struct etcd_ctx *ctx, const char *nqn,
		       const char *attr, char *value, size_t value_len)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/hosts/%s/%s",
		       ctx->prefix, nqn, attr);
	if (ret < 0)
		return ret;

	ret = etcd_kv_get(ctx, key, value, value_len);
	free(key);
	return ret;
}

int etcd_set_host_attr(struct etcd_ctx *ctx, const char *nqn,
		       const char *attr, const char *value, size_t value_len)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/hosts/%s/%s",
		       ctx->prefix, nqn, attr);
	if (ret < 0)
		return ret;

	ret = etcd_kv_update(ctx, key, value, value_len);
	free(key);
	return ret < 0 ? -errno : 0;
}

int etcd_del_host(struct etcd_ctx *ctx, const char *nqn)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/hosts/%s/", ctx->prefix, nqn);
	if (ret < 0)
		return ret;

	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

#define NUM_PORT_ATTRS 7
static struct key_value_template port_template[NUM_PORT_ATTRS] = {
	{ .key = "addr_trtype", .value = "" },
	{ .key = "addr_adrfam", .value = "" },
	{ .key = "addr_traddr", .value = "" },
	{ .key = "addr_trsvcid", .value = "" },
	{ .key = "addr_treq", .value = "not specified" },
	{ .key = "addr_tsas", .value = "none" },
	{ .key = "addr_node", .value = "" },
};

int etcd_fill_port_dir(struct etcd_ctx *ctx, void *buf, fuse_fill_dir_t filler)
{
	return etcd_fill_root(ctx, "ports", buf, filler);
}

int etcd_fill_port(struct etcd_ctx *ctx, const char *port,
		   void *buf, fuse_fill_dir_t filler)
{
	int i;

	for (i = 0; i < NUM_PORT_ATTRS; i++) {
		struct key_value_template *kv = &port_template[i];

		filler(buf, kv->key, NULL, 0, FUSE_FILL_DIR_PLUS);
	}
	filler(buf, "ana_groups", NULL, 0, FUSE_FILL_DIR_PLUS);
	filler(buf, "subsystems", NULL, 0, FUSE_FILL_DIR_PLUS);
	filler(buf, "referrals", NULL, 0, FUSE_FILL_DIR_PLUS);
	return 0;
}

int etcd_add_port(struct etcd_ctx *ctx, const char *port,
		  const char *traddr, const char *trsvcid)
{
	int ret, i;

	for (i = 0; i < NUM_PORT_ATTRS; i++) {
		struct key_value_template *kv = &port_template[i];
		char *key;
		const char *value;

		ret = asprintf(&key, "%s/ports/%s/%s",
			       ctx->prefix, port, kv->key);
		if (ret < 0)
			return ret;
		value = kv->value;
		if (!strcmp(kv->key, "addr_traddr")) {
			if (traddr)
				value = traddr;
		} else if (!strcmp(kv->key, "addr_trsvcid")) {
			if (trsvcid)
				value = trsvcid;
		}
		ret = etcd_kv_store(ctx, key, value, strlen(value));
		free(key);
		if (ret < 0)
			return -errno;
	}
	return 0;
}

int etcd_test_port(struct etcd_ctx *ctx, const char *port)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%s/addr_trtype",
		       ctx->prefix, port);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, NULL, 0);
	free(key);
	return ret;
}

int etcd_set_port_attr(struct etcd_ctx *ctx, const char *port,
		       const char *attr, const char *value, size_t value_len)
{
	unsigned long portid;
	char *key, *eptr;
	int ret = -ENOENT;

	/* Do not allow to set an invalid node value */
	if (!strcmp(attr, "addr_node")) {
		ret = etcd_test_cluster(ctx, value);
		if (ret < 0)
			return -EINVAL;
	}

	errno = 0;
	portid = strtoul(port, &eptr, 10);
	if (errno || portid > UINT_MAX)
		return -ERANGE;

	/*
	 * Only allow to modify 'addr_traddr' if 'addr_node' is set
	 * to the local node.
	 */
	if (!strcmp(attr, "addr_traddr")) {
		ret = etcd_validate_port(ctx, portid);
		if (ret < 0)
			return ret;
	}
	ret = asprintf(&key, "%s/ports/%lu/%s",
		       ctx->prefix, portid, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_update(ctx, key, value, value_len);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_port_attr(struct etcd_ctx *ctx, const char *port,
		       const char *attr, char *value, size_t value_len)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%s/%s",
		       ctx->prefix, port, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value, value_len);
	free(key);
	return ret;
}

int etcd_del_port(struct etcd_ctx *ctx, const char *port)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%s/", ctx->prefix, port);
	if (ret < 0)
		return ret;

	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

int etcd_validate_port(struct etcd_ctx *ctx, unsigned int portid)
{
	char *key, value[1024];
	int ret = 0;

	ret = asprintf(&key, "%s/ports/%u/device_node",
		       ctx->prefix, portid);
	if (ret < 0)
		return -ENOMEM;
	ret = etcd_kv_get(ctx, key, value, sizeof(value));
	if (ret < 0) {
		free(key);
		return ret;
	}
	if (!strlen(value))
		return -ENOENT;
	if (strcmp(ctx->node_name, value))
		ret = -EREMOTE;
	else
		ret = 0;
	return ret;
}

int etcd_count_ana_groups(struct etcd_ctx *ctx, const char *port, int *ngrps)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%s/ana_groups",
		       ctx->prefix, port);
	if (ret < 0)
		return ret;

	ret = _count_key_range(ctx, key, ngrps);
	free(key);
	return ret;
}

int etcd_fill_ana_groups(struct etcd_ctx *ctx, const char *port,
			 void *buf, fuse_fill_dir_t filler)
{
	struct etcd_kv *kvs;
	char *key, *val, *p;
	int ret, key_offset, i;

	ret = asprintf(&key, "%s/ports/%s/ana_groups/",
		       ctx->prefix, port);
	if (ret < 0)
		return ret;

	key_offset = strlen(key);
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		p = strrchr(kv->key, '/');
		if (p) {
			p++;
			if (!strcmp(p, "ana_state")) {
				val = strdup(kv->key + key_offset);
				p = strchr(val, '/');
				if (p)
					*p = '\0';
				filler(buf, val, NULL, 0, FUSE_FILL_DIR_PLUS);
				free(val);
			}
		}
	}
	etcd_kv_free(kvs, ret);
	return 0;
}

int etcd_add_ana_group(struct etcd_ctx *ctx, const char *port,
		       int ana_grpid, int ana_state)
{
	char *key, *value;
	int ret;

	ret = asprintf(&key, "%s/ports/%s/ana_groups/%d/ana_state",
		       ctx->prefix, port, ana_grpid);
	if (ret < 0)
		return ret;
	switch(ana_state) {
	case NVME_ANA_OPTIMIZED:
		value = "optimized";
		break;
	case NVME_ANA_NONOPTIMIZED:
		value = "non-optimized";
		break;
	case NVME_ANA_INACCESSIBLE:
		value = "inaccessible";
		break;
	case NVME_ANA_PERSISTENT_LOSS:
		value = "persistent-loss";
		break;
	case NVME_ANA_CHANGE:
		value = "change";
		break;
	default:
		return -EINVAL;
	}
	ret = etcd_kv_store(ctx, key, value, strlen(value));
	free(key);
	return ret;
}

int etcd_get_ana_group(struct etcd_ctx *ctx, const char *port,
		       int ana_grpid, char *ana_state, size_t ana_state_len)
{
	int ret = -ENOENT;
	char *key;

	ret = asprintf(&key, "%s/ports/%s/ana_groups/%d/ana_state",
		       ctx->prefix, port, ana_grpid);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, ana_state, ana_state_len);
	free(key);
	return ret;
}

int etcd_set_ana_group(struct etcd_ctx *ctx, const char *port,
		       const char *ana_grp, const char *ana_state,
		       size_t ana_state_len)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%s/ana_groups/%s/ana_state",
		       ctx->prefix, port, ana_grp);
	if (ret < 0)
		return ret;

	if (strcmp(ana_state, "optimized") &&
	    strcmp(ana_state, "non-optimized") &&
	    strcmp(ana_state, "inaccessible") &&
	    strcmp(ana_state, "persistent-loss") &&
	    strcmp(ana_state, "change"))
		return -EINVAL;

	ret = etcd_kv_update(ctx, key, ana_state, ana_state_len);
	free(key);
	return ret;
}

int etcd_del_ana_group(struct etcd_ctx *ctx, const char *port, int ana_grpid)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%s/ana_groups/%d/ana_state",
		       ctx->prefix, port, ana_grpid);
	if (ret < 0)
		return ret;
	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

#define NUM_SUBSYS_ATTRS 11
static struct key_value_template subsys_template[NUM_SUBSYS_ATTRS] = {
	{ .key = "attr_allow_any_host", .value = "1" },
	{ .key = "attr_firmware", .value = "" },
	{ .key = "attr_ieee_oui", .value = "851255" },
	{ .key = "attr_model", .value = "nofuse" },
	{ .key = "attr_serial", .value = "nofuse" },
	{ .key = "attr_version", .value = "2.0" },
	{ .key = "attr_type", .value = "nvm" },
	{ .key = "attr_qid_max", .value = "" },
	{ .key = "attr_pi_enable", .value = "0" },
	{ .key = "attr_cntlid_min", .value = "1" },
	{ .key = "attr_cntlid_max", .value = "65519" },
};

int etcd_fill_subsys_dir(struct etcd_ctx *ctx, void *buf,
			 fuse_fill_dir_t filler)
{
	return etcd_fill_root(ctx, "subsystems", buf, filler);
}

int etcd_fill_subsys(struct etcd_ctx *ctx, const char *subsys,
		     void *buf, fuse_fill_dir_t filler)
{
	int i;

	for (i = 0; i < NUM_SUBSYS_ATTRS; i++) {
		struct key_value_template *kv = &subsys_template[i];

		filler(buf, kv->key, NULL, 0, FUSE_FILL_DIR_PLUS);
	}
	filler(buf, "allowed_hosts", NULL, 0, FUSE_FILL_DIR_PLUS);
	filler(buf, "namespaces", NULL, 0, FUSE_FILL_DIR_PLUS);
	return 0;
}

int etcd_add_subsys(struct etcd_ctx *ctx, const char *nqn, const char *type)
{
	int ret, i;

	for (i = 0; i < NUM_SUBSYS_ATTRS; i++) {
		struct key_value_template *kvt = &subsys_template[i];
		char *key;

		ret = asprintf(&key, "%s/subsystems/%s/%s",
			       ctx->prefix, nqn, kvt->key);
		if (ret < 0)
			return ret;

		if (!strcmp(kvt->key, "attr_type")) {
			ret = etcd_kv_store(ctx, key, type, strlen(type));
		} else if (!strcmp(kvt->key, "attr_firmware")) {
			ret = etcd_kv_store(ctx, key, firmware_rev,
					    strlen(firmware_rev));
		} else {
			ret = etcd_kv_store(ctx, key, kvt->value,
					    strlen(kvt->value));
		}
		free(key);
		if (ret < 0)
			return -errno;
	}
	return 0;
}

int etcd_test_subsys(struct etcd_ctx *ctx, const char *nqn)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/attr_allow_any_host",
		       ctx->prefix, nqn);
	if (ret < 0)
		return false;
	ret = etcd_kv_get(ctx, key, NULL, 0);
	free(key);
	return ret;
}

int etcd_set_subsys_attr(struct etcd_ctx *ctx, const char *subsysnqn,
			 const char *attr, const char *value, size_t value_len)
{
	char *key;
	int ret = -ENOENT;

	if (!strcmp(attr, "attr_cntlid_min") ||
	    !strcmp(attr, "attr_cntlid_max"))
		return -EPERM;

	ret = asprintf(&key, "%s/subsystems/%s/%s",
		       ctx->prefix, subsysnqn, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_update(ctx, key, value, value_len);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_subsys_attr(struct etcd_ctx *ctx, const char *nqn,
			 const char *attr, char *value, size_t value_len)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/%s",
		       ctx->prefix, nqn, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value, value_len);
	free(key);
	return ret;
}

int etcd_del_subsys(struct etcd_ctx *ctx, const char *nqn)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/", ctx->prefix, nqn);
	if (ret < 0)
		return ret;

	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

int etcd_fill_subsys_port(struct etcd_ctx *ctx, const char *port,
			  void *buf, fuse_fill_dir_t filler)
{
	struct etcd_kv *kvs;
	char *key, *val;
	int ret, num = 0, i;

	ret = asprintf(&key, "%s/ports/%s/subsystems",
		       ctx->prefix, port);
	if (ret < 0)
		return ret;

	ret = etcd_kv_range(ctx, key, &kvs);
	if (ret < 0) {
		free(key);
		return ret;
	}

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		if (!strncmp(kv->key, key, strlen(key))) {
			val = strrchr(kv->key, '/');
			if (val) {
				val++;
				filler(buf, val, NULL, 0, FUSE_FILL_DIR_PLUS);
				num++;
			}
		}
	}
	etcd_kv_free(kvs, ret);
	free(key);
	printf("%s: %d elements\n", __func__, num);
	return 0;
}

int etcd_add_subsys_port(struct etcd_ctx *ctx, const char *subsysnqn,
			 const char *port)
{
	char *key, value[1024];
	int ret;

	/* Only allow to create symlink if 'addr_node' is set */
	ret = etcd_get_port_attr(ctx, port, "addr_node",
				 value, sizeof(value));
	if (ret >= 0 && !strlen(value))
		return -EPERM;

	ret = asprintf(&key, "%s/ports/%s/subsystems/%s",
		       ctx->prefix, port, subsysnqn);
	if (ret < 0)
		return ret;
	ret = sprintf(value, "../../../subsystems/%s", subsysnqn);
	ret = etcd_kv_store(ctx, key, value, ret);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_subsys_port(struct etcd_ctx *ctx, const char *subsysnqn,
			 const char *port, char *value, size_t value_len)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%s/subsystems/%s",
		       ctx->prefix, port, subsysnqn);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value, value_len);
	free(key);
	return ret;
}

int etcd_del_subsys_port(struct etcd_ctx *ctx, const char *subsysnqn,
			 const char *port)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%s/subsystems/%s",
		       ctx->prefix, port, subsysnqn);
	if (ret < 0)
		return ret;
	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

int etcd_fill_host_subsys(struct etcd_ctx *ctx, const char *subsysnqn,
			  void *buf, fuse_fill_dir_t filler)
{
	struct etcd_kv *kvs;
	char *key, *val;
	int ret, num = 0, i;

	ret = asprintf(&key, "%s/subsystems/%s/allowed_hosts",
		       ctx->prefix, subsysnqn);
	if (ret < 0)
		return ret;

	ret = etcd_kv_range(ctx, key, &kvs);
	if (ret < 0) {
		free(key);
		return ret;
	}

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		if (!strncmp(kv->key, key, strlen(key))) {
			val = strrchr(kv->key, '/');
			if (val) {
				val++;
				filler(buf, val, NULL, 0, FUSE_FILL_DIR_PLUS);
				num++;
			}
		}
	}
	etcd_kv_free(kvs, ret);
	free(key);
	printf("%s: %d elements\n", __func__, num);
	return 0;
}

int etcd_count_host_subsys(struct etcd_ctx *ctx, const char *subsysnqn,
			   int *nhosts)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/allowed_hosts",
		       ctx->prefix, subsysnqn);
	if (ret < 0)
		return ret;

	ret = _count_key_range(ctx, key, nhosts);
	free(key);
	return ret;
}

int etcd_add_host_subsys(struct etcd_ctx *ctx, const char *hostnqn,
			 const char *subsysnqn)
{
	char *key, *value;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/allowed_hosts/%s",
		       ctx->prefix, subsysnqn, hostnqn);
	if (ret < 0)
		return ret;
	ret = asprintf(&value, "../../../hosts/%s", hostnqn);
	if (ret < 0) {
		free(key);
		return ret;
	}
	ret = etcd_kv_store(ctx, key, value, ret);
	free(value);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_host_subsys(struct etcd_ctx *ctx, const char *hostnqn,
			 const char *subsysnqn, char *value, size_t value_len)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/allowed_hosts/%s",
		       ctx->prefix, subsysnqn, hostnqn);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value, value_len);
	free(key);
	return ret;
}

int etcd_del_host_subsys(struct etcd_ctx *ctx, const char *hostnqn,
			 const char *subsysnqn)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/allowed_hosts/%s",
		       ctx->prefix, subsysnqn, hostnqn);
	if (ret < 0)
		return ret;
	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

#define NUM_NS_ATTRS 8
static struct key_value_template ns_template[NUM_NS_ATTRS] = {
	{ .key = "device_eui64", .value = "" },
	{ .key = "device_nguid", .value = "" },
	{ .key = "device_uuid", .value = "" },
	{ .key = "device_path", .value = "" },
	{ .key = "device_node", .value = "" },
	{ .key = "ana_grpid", .value = "1" },
	{ .key = "enable", .value = "0" },
};

int etcd_fill_namespace_dir(struct etcd_ctx *ctx, const char *subsysnqn,
			    void *buf, fuse_fill_dir_t filler)
{
	struct etcd_kv *kvs;
	char *key, *val, *p;
	int ret, key_offset, i;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/",
		       ctx->prefix, subsysnqn);
	if (ret < 0)
		return ret;

	key_offset = strlen(key);
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		p = strrchr(kv->key, '/');
		if (p) {
			p++;
			if (!strcmp(p, "device_uuid")) {
				val = strdup(kv->key + key_offset);
				p = strchr(val, '/');
				if (p)
					*p = '\0';
				filler(buf, val, NULL, 0, FUSE_FILL_DIR_PLUS);
				free(val);
			}
		}
	}
	etcd_kv_free(kvs, ret);
	return 0;
}

int etcd_fill_namespace(struct etcd_ctx *ctx, const char *subsysnqn, int nsid,
			void *buf, fuse_fill_dir_t filler)
{
	int i;

	for (i = 0; i < NUM_NS_ATTRS; i++) {
		struct key_value_template *kv = &ns_template[i];

		filler(buf, kv->key, NULL, 0, FUSE_FILL_DIR_PLUS);
	}
	return 0;
}

int etcd_count_namespaces(struct etcd_ctx *ctx, const char *subsysnqn, int *nns)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces",
		       ctx->prefix, subsysnqn);
	if (ret < 0)
		return ret;

	ret = _count_key_range(ctx, key, nns);
	free(key);
	return ret;
}

int etcd_add_namespace(struct etcd_ctx *ctx, const char *subsysnqn, int nsid)
{
	char *key;
	int ret, i;
	uuid_t uuid;
	char uuid_str[65], nguid_str[33], eui64_str[33];
	unsigned int nguid1, nguid2;

	uuid_generate(uuid);
	uuid_unparse(uuid, uuid_str);

	memcpy(&nguid1, &uuid[8], 4);
	memcpy(&nguid2, &uuid[12], 4);
	sprintf(nguid_str, "%08x%08x%s",
		nguid1, nguid2, NOFUSE_NGUID_PREFIX);

	sprintf(eui64_str, "0efd37%hhx%08x",
		uuid[11], nguid2);

	for (i = 0; i < NUM_NS_ATTRS; i++) {
		struct key_value_template *kv = &ns_template[i];
		const char *value;

		ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/%s",
			       ctx->prefix, subsysnqn, nsid, kv->key);
		if (ret < 0)
			continue;

		if (!strcmp(kv->key, "device_nguid"))
			value = nguid_str;
		else if (!strcmp(kv->key, "device_eui64"))
			value = eui64_str;
		else if (!strcmp(kv->key, "device_uuid"))
			value = uuid_str;
		else
			value = kv->value;
		if (value)
			ret = etcd_kv_store(ctx, key, value,
					    strlen(value));
		free(key);
	}
	return ret;
}

int etcd_test_namespace(struct etcd_ctx *ctx, const char *subsysnqn, int nsid)
{
	char *key, value[1024];
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/enable",
		       ctx->prefix, subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value, sizeof(value));
	free(key);
	if (ret < 0)
		return ret;
	if (!strcmp(value, "0"))
		ret = 0;
	else if (!strcmp(value, "1"))
		ret = 1;
	else
		ret = -EINVAL;
	return ret;
}

int etcd_set_namespace_attr(struct etcd_ctx *ctx, const char *subsysnqn,
			    int nsid, const char *attr,
			    const char *value, size_t value_len)
{
	char *key;
	int ret = -ENOENT;

	/* Do not allow to change attributes if the namespace is enabled */
	if (strcmp(attr, "enable")) {
		ret = etcd_test_namespace(ctx, subsysnqn, nsid);
		if (ret == 1) {
			fprintf(stderr, "%s: subsys %s nsid %d is enabled\n",
				__func__, subsysnqn, nsid);
			return -EPERM;
		}
		if (ret < 0) {
			printf("%s: subsys %s nsid %d enable error %d\n",
			       __func__, subsysnqn, nsid, ret);
			return ret;
		}
	}
	/*
	 * Do not allow to set 'device_path' if 'device_node' is not set
	 */
	if (!strcmp(attr, "device_path")) {
		char node[1024];
		ret = etcd_get_namespace_attr(ctx, subsysnqn, nsid,
					      "device_node", node,
					      sizeof(node));
		if (ret < 0 && strlen(node) == 0) {
			fprintf(stderr,
				"%s: subsys %s nsid %d validation error %d\n",
				__func__, subsysnqn, nsid, ret);
			return -EPERM;
		}
		printf("%s: subsys %s nsid %d validation ok\n",
		       __func__, subsysnqn, nsid);
		ret = 0;
	}
	/*
	 * Do not allow to enable it if 'device_path' is not set
	 */
	if (!strcmp(attr, "enable") && strcmp(value, "0")) {
		char node[1024];
		ret = etcd_get_namespace_attr(ctx, subsysnqn, nsid,
					      "device_path", node,
					      sizeof(node));
		if (ret < 0 && strlen(node) == 0) {
			fprintf(stderr,
				"%s: subsys %s nsid %d validation error %d\n",
				__func__, subsysnqn, nsid, ret);
			return -EPERM;
		}
		printf("%s: subsys %s nsid %d validation ok\n",
		       __func__, subsysnqn, nsid);
		ret = 0;
	}
	/*
	 * Do not allow to set 'device_node' to an invalid node value
	 */
	if (!strcmp(attr, "device_node")) {
		ret = etcd_test_cluster(ctx, value);
		if (ret < 0)
			return -EINVAL;
	}
	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/%s",
		       ctx->prefix, subsysnqn, nsid, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_update(ctx, key, value, value_len);
	free(key);
	if (ret < 0) {
		printf("%s: subsys %s nsid %d attr error %d\n",
		       __func__, subsysnqn, nsid, ret);
		return -errno;
	}
	return 0;
}

int etcd_get_namespace_attr(struct etcd_ctx *ctx, const char *subsysnqn,
			    int nsid, const char *attr,
			    char *value, size_t value_len)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/%s",
		       ctx->prefix, subsysnqn, nsid, attr);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, value, value_len);
	free(key);
	return ret;
}

int etcd_set_namespace_anagrp(struct etcd_ctx *ctx, const char *subsysnqn,
			      int nsid, int ana_grpid)
{
	char *key, *value;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/ana_grpid",
		       ctx->prefix, subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = asprintf(&value, "%d", ana_grpid);
	if (ret < 0) {
		free(key);
		return ret;
	}
	ret = etcd_kv_update(ctx, key, value, ret);
	free(value);
	free(key);
	if (ret < 0)
		return -errno;
	return 0;
}

int etcd_get_namespace_anagrp(struct etcd_ctx *ctx, const char *subsysnqn,
			      int nsid, int *ana_grpid)
{
	struct etcd_kv *kvs;
	int ret, i;
	char *key;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/ana_grpid",
		       ctx->prefix, subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		if (!strcmp(kv->key, "ana_grpid")) {
			unsigned long val;
			char *eptr = NULL;

			val = strtoul(kv->value, &eptr, 10);
			if (val == ULONG_MAX || kv->value == eptr)
				ret = -ERANGE;
			else {
				*ana_grpid = val;
				ret = 0;
			}
		}
	}
	etcd_kv_free(kvs, ret);
	return ret;
}

int etcd_del_namespace(struct etcd_ctx *ctx, const char *subsysnqn, int nsid)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/",
		       ctx->prefix, subsysnqn, nsid);
	if (ret < 0)
		return ret;

	ret = etcd_kv_delete(ctx, key);
	free(key);
	return ret;
}

int etcd_validate_namespace(struct etcd_ctx *ctx, const char *subsysnqn,
			    int nsid)
{
	char *key, value[1024];
	int ret = 0;

	ret = asprintf(&key, "%s/subsystems/%s/namespaces/%d/device_node",
		       ctx->prefix, subsysnqn, nsid);
	if (ret < 0)
		return -ENOMEM;
	ret = etcd_kv_get(ctx, key, value, sizeof(value));
	if (ret < 0) {
		free(key);
		return ret;
	}
	if (!strlen(value))
		return -ENOENT;
	if (strcmp(ctx->node_name, value))
		ret = -EREMOTE;
	return ret;
}

int etcd_count_subsys_port(struct etcd_ctx *ctx, const char *port, int *nsubsys)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/ports/%s/subsystems",
		       ctx->prefix, port);
	if (ret < 0)
		return ret;

	ret = _count_key_range(ctx, key, nsubsys);
	free(key);
	return ret;
}

int etcd_fill_cluster_dir(struct etcd_ctx *ctx, void *buf,
			  fuse_fill_dir_t filler)
{
	return etcd_fill_root(ctx, "cluster", buf, filler);
}

int etcd_fill_cluster(struct etcd_ctx *ctx, const char *node,
		      void *buf, fuse_fill_dir_t filler)
{
	struct etcd_kv *kvs;
	int i, ret;
	char *key;

	ret = asprintf(&key, "%s/cluster/%s",
		       ctx->prefix, node);
	if (ret < 0)
		return ret;

	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;

	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];
		char *p;

		p = strrchr(kv->key, '/');
		if (p)
			filler(buf, p + 1, NULL, 0, FUSE_FILL_DIR_PLUS);
	}
	etcd_kv_free(kvs, ret);
	return 0;
}

int etcd_test_cluster(struct etcd_ctx *ctx, const char *node)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/cluster/%s/node_name",
		       ctx->prefix, node);
	if (ret < 0)
		return ret;
	ret = etcd_kv_get(ctx, key, NULL, 0);
	free(key);
	return ret;
}

int etcd_count_cluster(struct etcd_ctx *ctx)
{
	char *key;
	struct etcd_kv *kvs;
	int num_nodes = 0, ret, i;

	ret = asprintf(&key, "%s/cluster", ctx->prefix);
	if (ret)
		return -ENOMEM;
	ret = etcd_kv_range(ctx, key, &kvs);
	if (ret < 0) {
		free(key);
		return ret;
	}
	for (i = 0; i < ret; i++) {
		const char *attr = strrchr(kvs[i].value, '/');

		if (attr && !strcmp(attr, "/node_name"))
			num_nodes++;
	}
	etcd_kv_free(kvs, ret);
	free(key);
	return num_nodes;
}

int etcd_get_cluster_attr(struct etcd_ctx *ctx, const char *node,
			  const char *attr, char *value, size_t value_len)
{
	char *key;
	int ret;

	ret = asprintf(&key, "%s/cluster/%s/%s",
		       ctx->prefix, node, attr);
	if (ret < 0)
		return ret;

	ret = etcd_kv_get(ctx, key, value, value_len);
	free(key);
	return ret;
}

int etcd_set_cluster_id(struct etcd_ctx *ctx)
{
	char key[256], value[32];
	long cluster_id = -1;
	int ret, num_kvs, i, node_num = 0;
	struct etcd_kv *kvs;

	sprintf(key, "%s/cluster/", ctx->prefix);
	ret = etcd_kv_range(ctx, key, &kvs);
	if (ret < 0)
		return -ENOMEM;
	num_kvs = ret;
	for (i = 0; i < num_kvs; i++) {
		const char *attr = strrchr(kvs[i].key, '/');

		if (!attr)
			continue;

		/* check the lowest cluster id to use as offset */
		if (cluster_id == -1 && !strcmp(attr, "/cluster_id")) {
			unsigned long id;
			char *eptr;

			errno = 0;
			id = strtoul(kvs[i].value, &eptr, 10);
			node_num = id + 1;
		}
			
		if (strcmp(attr, "/node_name"))
			continue;
		if (!strcmp(kvs[i].value, ctx->node_name)) {
			cluster_id = node_num % ctx->cluster_size;
			break;
		}
		node_num++;
	}
	if (cluster_id < 0)
		return -ENOENT;

	sprintf(key, "%s/cluster/%s/cluster_id", ctx->prefix, ctx->node_id);
	sprintf(value, "%ld", cluster_id);
	ret = etcd_kv_store(ctx, key, value, strlen(value));
	if (ret < 0) {
		fprintf(stderr, "%s: node %s failed to store cluster id\n",
			__func__, ctx->node_name);
	}
	ctx->cluster_id = cluster_id;
	return ret;
}
