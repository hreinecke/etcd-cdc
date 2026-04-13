/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * configfs.c
 * configfs functions for nvmet-etcd
 *
 * Copyright (c) 2025 Hannes Reinecke <hare@suse.de>
 *
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/types.h>
#include <fcntl.h>

#include "common.h"
#include "etcd/client.h"
#include "configfs.h"
#include "etcd/backend.h"
#include "list.h"

/*
 * ana/<grpid>/optimized/<portid>: node_name
 * ana/<grpid>/non_optimized/<portid>: node_name
 * ana/<grpid>/inaccessible/<portid>: node_name
 * ana/<grpid>/persistent_loss/<portid>: node_name
 * ana/<grpid>/subsystems/<subsys>/<nsid>/enabled: 0/1
 */

int update_ana_namespace(struct etcd_ctx *ctx, unsigned int ana_grpid,
			 const char *subsys, const char *ns, bool enabled)
{
	char value[16];
	int ret;
	char *key;

	ret = asprintf(&key, "%s/ana/%u/subsystems/%s/nsid/%s/enabled",
		       ctx->prefix, ana_grpid, subsys, ns);
	if (ret < 0)
		return -ENOMEM;

	ret = etcd_kv_get(ctx, key, value, sizeof(value));
	if (ret < 0) {
		sprintf(value, "%d", enabled ? 1 : 0);
		ret = etcd_kv_store(ctx, key, value, strlen(value));
		if (ret < 0)
			fprintf(stderr,
				"%s: subsys %s ns %s failed to add grpid %u\n",
				__func__, subsys, ns, ana_grpid);
	} else if ((value[0] == '0' && enabled) ||
		   (value[1] == '1' && !enabled)) {
		sprintf(value, "%d", enabled ? 1 : 0);
		ret = etcd_kv_update(ctx, key, value, strlen(value));
		if (ret < 0)
			fprintf(stderr,
				"%s: subsys %s ns %s failed to update grpid %u\n",
				__func__, subsys, ns, ana_grpid);
	}
	free(key);
	return ret < 0 ? ret : 0;
}

int update_ana_port(struct etcd_ctx *ctx, unsigned int grpid,
		    unsigned int portid, char *state)
{
	char *key, value[256];
	int ret;

	portid |= ctx->cluster_id << 8;
	ret = asprintf(&key, "%s/ana/%u/%s/%u",
		       ctx->prefix, grpid, state, portid);

	ret = etcd_kv_get(ctx, key, value, sizeof(value));
	if (ret < 0) {
		ret = etcd_kv_store(ctx, key, ctx->node_name,
				    strlen(ctx->node_name));
		if (ret < 0) {
			fprintf(stderr,
				"%s: failed to add port %u to ana group %u\n",
				__func__, portid, grpid);
			free(key);
			return ret;
		}
		printf("%s: add new port %u to ana group %u\n",
		       __func__, portid, grpid);
		ret = 0;
	}
	free(key);
	return ret;
}

int read_attr(char *attr_path, char *value, size_t value_len)
{
	int fd, len;
	char *p;

	fd = open(attr_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s', error %d\n",
			attr_path, errno);
		return -1;
	}
	len = read(fd, value, value_len);
	if (len < 0)
		memset(value, 0, value_len);
	else {
		p = &value[len - 1];
		while (isspace(*p)) {
			*p = '\0';
			p--;
			len--;
			if (p == value)
				break;
		}
		if (!strcmp(value, "(null)")) {
			memset(value, 0, value_len);
			len = 0;
		}
	}
	close(fd);
	return len;
}

int write_attr(char *attr_path, char *value, size_t value_len)
{
	int fd, len;

	fd = open(attr_path, O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Failed to open '%s', error %d\n",
			attr_path, errno);
		return -errno;
	}
	len = write(fd, value, value_len);
	if (len < 0)
		len = -errno;

	close(fd);
	return len;
}

char *path_to_key(struct etcd_ctx *ctx, const char *dirname, const char *attr)
{
	const char *prefix = dirname + strlen(ctx->configfs) + 1;
	char *key;
	int ret;

	if (!strncmp(prefix, "ports", 5)) {
		unsigned long portid;
		char *suffix;

		errno = 0;
		portid = strtoul(prefix + 6, &suffix, 10);
		if (errno || portid > NODE_MAX_PORTS)
			return NULL;
		portid += ctx->cluster_id << 8;
		ret = asprintf(&key, "%s/ports/%lu%s/%s",
			       ctx->prefix, portid, suffix, attr);
	} else
		ret = asprintf(&key, "%s/%s/%s", ctx->prefix, prefix, attr);
	if (ret < 0)
		return NULL;
	return key;
}

int configfs_update_key(struct etcd_ctx *ctx,
			const char *dirname, const char *attr)
{
	struct stat st;
	char *pathname, value[1024], old[1024], *key;
	int ret;

	memset(value, 0, sizeof(value));
	ret = asprintf(&pathname, "%s/%s", dirname, attr);
	if (ret < 0)
		return ret;
	if (!strcmp(attr, "device_node")) {
		/* Synthetic attribute, not present in configfs */
		strcpy(value, ctx->node_name);
		ret = 0;
		goto store_key;
	}
	/* Do not modify cntlid settings */
	if (!strcmp(attr, "attr_cntlid_min") ||
	    !strcmp(attr, "attr_cntlid_max")) {
		free(pathname);
		return 0;
	}

	ret = lstat(pathname, &st);
	if (ret < 0) {
		fprintf(stderr, "%s: attr %s error %d\n",
			__func__, pathname, errno);
		free(pathname);
		return -errno;
	}
	if (!(st.st_mode & (S_IRUSR | S_IRGRP | S_IROTH))) {
		printf("%s: skip attr %s, not readable\n",
		       __func__, pathname);
		free(pathname);
		return 0;
	}
	if ((st.st_mode & S_IFMT) == S_IFLNK) {
		ret = readlink(pathname, value, sizeof(value));
	} else if ((st.st_mode & S_IFMT) == S_IFREG) {
		ret = read_attr(pathname, value, sizeof(value));
	} else {
		if ((st.st_mode & S_IFMT) != S_IFDIR)
			fprintf(stderr, "%s: skip unhandled attr %s mode %x\n",
				__func__, pathname, (st.st_mode & S_IFMT));
		free(pathname);
		return 0;
	}

store_key:
	key = path_to_key(ctx, dirname, attr);
	if (!key) {
		free(pathname);
		return -ENOMEM;
	}
	if (ret < 0) {
		fprintf(stderr, "%s: %s value error %d\n",
			__func__, key, ret);
		free(key);
		goto out_free;
	}

	memset(old, 0, sizeof(old));
	ret = etcd_kv_get(ctx, key, old, sizeof(old));
	if (ret < 0) {
		if (ret != -ENOENT) {
			fprintf(stderr, "%s: key %s create error %d\n",
				__func__, key, ret);
			free(key);
			goto out_free;
		}
		if (!strlen(value)) {
			if (configfs_debug)
				printf("%s: empty key %s, not uploading\n",
				       __func__, key);
			ret = 0;
			free(key);
			goto out_free;
		}
		if (configfs_debug)
			printf("%s: upload key %s value '%s'\n", __func__,
			       key, value);

		ret = etcd_kv_store(ctx, key, value, strlen(value));
		if (ret < 0) {
			fprintf(stderr, "%s: key %s create error %d\n",
				__func__, key, ret);
		} else
			ret = strlen(value);
	} else if (strcmp(old, value)) {
		if (configfs_debug)
			printf("%s: update key %s value '%s'\n", __func__,
			       key, value);

		if (!strlen(value))
			ret = etcd_kv_delete(ctx, key);
		else
			ret = etcd_kv_update(ctx, key, value, strlen(value));
		if (ret < 0)
			fprintf(stderr, "%s: key %s update error %d\n",
				__func__, key, ret);
		else
			ret = strlen(value);
	}
	free(key);
out_free:
	free(pathname);
	return ret;
}

static int configfs_upload_key(struct etcd_ctx *ctx, const char *dir,
			       const char *file)
{
	char *dirname;
	DIR *sd;
	struct dirent *se;
	int ret;

	ret = asprintf(&dirname, "%s/%s", dir, file);
	if (ret < 0)
		return -ENOMEM;

	ret = 0;
	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", dirname);
		free(dirname);
		return -errno;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		if (configfs_debug) {
			char *type_name;

			if (se->d_type == DT_DIR)
				type_name = "dir";
			else if (se->d_type == DT_LNK)
				type_name = "link";
			else if (se->d_type == DT_REG)
				type_name = "file";
			else
				type_name = "unknown";
			printf("%s: checking %s %s %s\n",
			       __func__, type_name, dirname, se->d_name);
		}
		if (!strcmp(se->d_name, "passthru"))
			continue;

		/* Set 'device_node' prior to setting 'device_path' */
		if (!strcmp(se->d_name, "device_path")) {
			ret = configfs_update_key(ctx, dirname,
						  "device_node");
			if (ret < 0)
				break;
		}
		ret = configfs_update_key(ctx, dirname, se->d_name);
		if (ret < 0)
			break;

		if (se->d_type == DT_DIR) {
			ret = configfs_upload_key(ctx, dirname, se->d_name);
			if (ret < 0)
				break;
		}
	}

	closedir(sd);
	free(dirname);
	return ret < 0 ? ret : 0;
}

int upload_configfs(struct etcd_ctx *ctx)
{
	int ret;

	ret = configfs_upload_key(ctx, ctx->configfs, "ports");
	if (ret < 0) {
		if (configfs_debug)
			fprintf(stderr,
				"failed to upload port configuration\n");
		return ret;
	}
	ret = configfs_upload_key(ctx, ctx->configfs, "hosts");
	if (ret < 0) {
		if (configfs_debug)
			fprintf(stderr,
				"failed to upload hosts configuration\n");
		return ret;
	}
	ret = configfs_upload_key(ctx, ctx->configfs, "subsystems");
	if (ret < 0) {
		if (configfs_debug)
			fprintf(stderr,
				"failed to upload subsystem configuration\n");
	}
	return ret;
}

static int configfs_download_keys(struct etcd_ctx *ctx, const char *dir)
{
	struct etcd_kv *kvs;
	char *key;
	int ret, i;

	ret = asprintf(&key, "%s/%s/", ctx->prefix, dir);
	if (ret < 0)
		return ret;
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;
	for (i = 0; i < ret; i++) {
		struct etcd_kv *kv = &kvs[i];

		etcd_watch_cb(ctx, kv);
	}
	etcd_kv_free(kvs, ret);
	return 0;
}

int download_configfs(struct etcd_ctx *ctx)
{
	int ret;

	ret = configfs_download_keys(ctx, "hosts");
	if (ret < 0) {
		if (configfs_debug)
			fprintf(stderr,
				"failed to download hosts configuration\n");
		return ret;
	}
	ret = configfs_download_keys(ctx, "subsystems");
	if (ret < 0) {
		if (configfs_debug)
			fprintf(stderr,
				"failed to download subsystem configuration\n");
		return ret;
	}
	ret = configfs_download_keys(ctx, "ports");
	if (ret < 0) {
		if (configfs_debug)
			fprintf(stderr,
				"failed to download port configuration\n");
	}
	return ret;
}

static int validate_cntlid(struct etcd_ctx *ctx, char *subsys,
			   char *value, bool cntlid_max)
{
	unsigned long cntlid, cntlid_min, new_cntlid;
	unsigned int cluster_spacing;
	char *eptr;
	int ret = 0;

	cluster_spacing = (CLUSTER_MAX_SIZE / ctx->cluster_size);
	errno = 0;
	cntlid = strtoul(value, &eptr, 10);
	if (errno || cntlid == ULONG_MAX) {
		fprintf(stderr, "%s: %s parse error on %s\n",
			__func__, subsys, value);
		return -ERANGE;
	}
	cntlid_min = ctx->cluster_id * cluster_spacing;
	if (cntlid_max) {
		new_cntlid = cntlid_min + (cluster_spacing - 1);
	} else {
		new_cntlid = cntlid_min;
	}
	/* Controller ID 0 is invalid, so the first cntlid is '1' */
	if (cntlid == 1)
		cntlid = 0;

	if (cntlid == new_cntlid)
		return 0;

	fprintf(stderr, "%s: subsys %s cntlid_%s should be %lu\n",
		__func__, subsys, cntlid_max ? "max" : "min",
		new_cntlid);
	ret = sprintf(value, "%lu", new_cntlid);
	return ret;
}

static int validate_ana_grpid(struct etcd_ctx *ctx, const char *subsys,
			      const char *ns)
{
	unsigned long ana_grpid;
	char *path, value[1024], *eptr;
	bool ns_enabled = false;
	int ret;

	ret = asprintf(&path, "%s/subsystems/%s/namespaces/%s/enable",
		       ctx->configfs, subsys, ns);
	if (ret < 0)
		return -ENOMEM;

	ret = read_attr(path, value, sizeof(value));
	free(path);
	if (ret < 0)
		return -ENOENT;

	if (strcmp(value, "1"))
		ns_enabled = true;

	ret = asprintf(&path, "%s/subsystems/%s/namespaces/%s/ana_grpid",
		       ctx->configfs, subsys, ns);
	if (ret < 0)
		return -errno;

	ret = read_attr(path, value, sizeof(value));
	free(path);
	if (ret < 0)
		return ret;

	ana_grpid = strtoul(value, &eptr, 10);
	if (ana_grpid == ULONG_MAX || value == eptr) {
		fprintf(stderr, "subsys %s ns %s grpid %s parse error\n",
			subsys, ns, value);
		return -ERANGE;
	}
	return update_ana_namespace(ctx, ana_grpid, subsys, ns,
				   ns_enabled);
}

static int validate_namespaces(struct etcd_ctx *ctx, const char *subsys)
{
	DIR *sd;
	struct dirent *se;
	char *dirname;
	int ret;

	printf("%s: validating namespaces for subsys %s\n",
	       __func__, subsys);
	ret = asprintf(&dirname, "%s/subsystems/%s/namespaces",
		       ctx->configfs, subsys);
	if (ret < 0)
		return -ENOMEM;

	ret = 0;
	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", dirname);
		free(dirname);
		return -errno;
	}
	while ((se = readdir(sd))) {
		unsigned long nsid;

		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		if (se->d_type != DT_DIR)
			continue;

		printf("%s: validating subsys %s ns %s\n",
		       __func__, subsys, se->d_name);
		errno = 0;
		nsid = strtoul(se->d_name, NULL, 10);
		if (errno || nsid == ULONG_MAX) {
			fprintf(stderr, "%s: parse error on ns '%s'\n",
				__func__, se->d_name);
			continue;
		}

		ret = etcd_validate_namespace(ctx, subsys, nsid);
		if (ret < 0) {
			if (ret == -EREMOTE) {
				fprintf(stderr,
					"%s: subsys %s namespace %lu is remote\n",
					__func__, subsys, nsid);
				ret = 0;
				continue;
			} else if (ret != -ENOENT) {
				fprintf(stderr,
					"%s: subsys %s namespce %lu error %d\n",
					__func__, subsys, nsid, ret);
				continue;
			}
			/* Namespace is not registered with etcd */
			printf("%s: subsys %s namespace %lu is valid\n",
			       __func__, subsys, nsid);
			ret = 0;
		}
		ret = validate_ana_grpid(ctx, subsys, se->d_name);
		if (ret < 0)
			break;
		ret = 0;
	}
	closedir(sd);
	free(dirname);
	return ret;
}

int validate_cntlid_range(struct etcd_ctx *ctx, char *dirname, char *subsys)
{
	char *path, value[64];
	int ret;

	ret = asprintf(&path, "%s/%s/attr_cntlid_min",
		       dirname, subsys);
	if (ret < 0)
		return -ENOMEM;

	ret = read_attr(path, value, sizeof(value));
	if (ret < 0) {
		if (configfs_debug)
			fprintf(stderr, "%s: failed to read '%s', error %d\n",
				__func__, path, ret);
		free(path);
		return ret;
	}
	if (validate_cntlid(ctx, subsys, value, false) > 0) {
		ret = write_attr(path, value, strlen(value));
		if (ret < 0) {
			fprintf(stderr,
				"%s: failed to update %s to '%s', error %d\n",
				__func__, path, value, ret);
			free(path);
			return ret;
		}
	}
	free(path);

	ret = asprintf(&path, "%s/%s/attr_cntlid_max",
		       dirname, subsys);
	if (ret < 0)
		return -ENOMEM;

	ret = read_attr(path, value, sizeof(value));
	if (ret < 0) {
		free(path);
		return ret;
	}
	if (validate_cntlid(ctx, subsys, value, true) > 0) {
		ret = write_attr(path, value, strlen(value));
		if (ret < 0) {
			fprintf(stderr,
				"%s: failed to update %s, error %d\n",
				__func__, path, ret);
		}
	}
	free(path);
	return ret;
}

int validate_ana_port(struct etcd_ctx *ctx, unsigned int portid)
{
	DIR *sd;
	struct dirent *se;
	char *dirname;
	int ret, errors = 0;

	ret = asprintf(&dirname, "%s/ports/%u/ana_groups",
		       ctx->configfs, portid);
	if (ret < 0)
		return -ENOMEM;
	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "%s: Cannot open %s\n",
			__func__, dirname);
		free(dirname);
		return -errno;
	}
	while ((se = readdir(sd))) {
		char state[64], *eptr, *path;
		unsigned long ana_grpid;

		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		if (se->d_type != DT_DIR)
			continue;
		errno = 0;
		ana_grpid = strtoul(se->d_name, &eptr, 10);
		if (errno || ana_grpid == UINT_MAX)
			continue;

		ret = asprintf(&path, "%s/%s/ana_state",
			       dirname, se->d_name);
		if (ret < 0)
			continue;
		ret = read_attr(path, state, sizeof(state));
		free(path);
		if (ret < 0)
			continue;
		ret = update_ana_port(ctx, ana_grpid, portid, state);
		if (ret < 0)
			errors++;
	}
	closedir(sd);
	return errors ? -EINVAL : 0;
}

/**
 * validate_cluster -- Validate local settings
 *
 * The local nvmet configfs settings need to be compatible with the cluster
 * to allow for a merge of the local configuration with the existing
 * cluster settings.
 * - The cluster boundary is given by the max number of cntlids divided
 *   by the size of the cluster (ie the possible number of nodes in the cluster)
 * - The cluster id is derived from the 'cntlid_min' subsystem setting.
 *   The 'cntlid_min' setting needs to fall on a cluster boundary, and
 *   the cluster id is the cntlid_min setting divided by the cluster boundary.
 * - 'cntlid_min'/'cntlid_max' settings need to be identical for all
 *   local subsystems
 * - the 'cntlid_max' setting need to fall on a cluster boundary - 1,
 *   and needs to be at the end of the current cluster boundary.
 *
 * The port ids needs to be divided per cluster id; all port ids not
 * in the range of the local cluster node will be rejected.
 */
int configfs_validate_cluster(struct etcd_ctx *ctx)
{
	int ret, errors = 0;
	DIR *sd;
	struct dirent *se;
	char *dirname;

	ret = asprintf(&dirname, "%s/subsystems", ctx->configfs);
	if (ret < 0)
		return -ENOMEM;

	ret = 0;
	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", dirname);
		free(dirname);
		return -errno;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;

		if (se->d_type != DT_DIR)
			continue;
		ret = validate_cntlid_range(ctx, dirname, se->d_name);
		if (ret < 0)
			errors++;
		ret = validate_namespaces(ctx, se->d_name);
		if (ret < 0)
			errors++;
	}
	closedir(sd);
	free(dirname);
	if (ret < 0) {
		fprintf(stderr, "%s: validation failed with error %d\n",
			__func__, ret);
		return ret;
	}
	if (errors) {
		fprintf(stderr, "%s: %d errors during validation\n",
			__func__, errors);
		return -EINVAL;
	}

	ret = asprintf(&dirname, "%s/ports", ctx->configfs);
	if (ret < 0)
		return -ENOMEM;

	ret = 0;
	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", dirname);
		free(dirname);
		return -errno;
	}
	while ((se = readdir(sd))) {
		unsigned long portid;
		char *eptr;

		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;

		if (se->d_type != DT_DIR)
			continue;

		errno = 0;
		portid = strtoul(se->d_name, &eptr, 10);
		if (errno || portid > UINT_MAX) {
			fprintf(stderr, "%s: failed to parse port '%s'\n",
				__func__, se->d_name);
			ret = -ERANGE;
			break;
		}
		ret = validate_ana_port(ctx, portid);
		if (ret < 0)
			break;
	}
	closedir(sd);
	free(dirname);
	return ret;
}

int configfs_load_ana(struct etcd_ctx *ctx)
{
	struct etcd_kv *kvs;
	char *key;
	int ret, num_kvs, i;

	ret = asprintf(&key, "%s/ports", ctx->prefix);
	if (ret < 0)
		return ret;

	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;
	num_kvs = ret;
	ret = 0;
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv =&kvs[i];
		char *attr, *p, *eptr;
		unsigned long portid, ana_grpid;

		attr = kv->key + strlen(ctx->prefix) + 7;
		p = strrchr(attr, '/');
		if (!p || strcmp(p, "/ana_state"))
			continue;
		portid = strtoul(attr, &eptr, 10);
		if (portid == ULONG_MAX || attr == eptr) {
			ret = -ERANGE;
			break;
		}

		if (!strcmp(eptr, "/ana_groups/"))
			continue;
		p = eptr + strlen("/ana_groups/");
		ana_grpid = strtoul(p, &eptr, 10);
		if (ana_grpid == ULONG_MAX || p == eptr) {
			ret = -ERANGE;
			break;
		}
		printf("%s: parsing %s portid %lu ana grpid %lu\n",
		       __func__, kv->key, portid, ana_grpid);
		ret = update_ana_port(ctx, ana_grpid, portid, kv->value);
		if (ret < 0)
			break;
	}
	etcd_kv_free(kvs, num_kvs);
	return ret;
}

int configfs_purge_ports(struct etcd_ctx *ctx)
{
	unsigned int min_portid, max_portid;
	char *min_key, *max_key;
	int ret;

	min_portid = ctx->cluster_id << 8;
	max_portid = min_portid + NODE_MAX_PORTS;
	ret = asprintf(&min_key, "%s/ports/%u", ctx->prefix, min_portid);
	if (ret < 0)
		return -ENOMEM;
	ret = asprintf(&max_key, "%s/ports/%u", ctx->prefix, max_portid);
	if (ret < 0) {
		free(min_key);
		return -ENOMEM;
	}
		
	ret = etcd_kv_delete_range(ctx, min_key, max_key);
	free(max_key);
	free(min_key);
	return ret;
}

int configfs_purge_subsystems(struct etcd_ctx *ctx)
{
	struct etcd_kv *kvs;
	char *key;
	int num_kvs, ret, i, num_nodes;

	ret = etcd_count_cluster(ctx);
	if (ret < 0)
		return ret;
	num_nodes = ret;

	ret = asprintf(&key, "%s/subsystems", ctx->prefix);
	if (ret < 0)
		return ret;
	ret = etcd_kv_range(ctx, key, &kvs);
	free(key);
	if (ret < 0)
		return ret;
	num_kvs = ret;
	for (i = 0; i < num_kvs; i++) {
		struct etcd_kv *kv = &kvs[i];
		char value[1024], *p;

		p = strrchr(kv->key, '/');
		if (strcmp(p, "/attr_cntlid_min"))
			continue;
		if (!kv->value)
			continue;
		if (num_nodes == 0) {
			strcpy(value, kv->key);
			p = strrchr(value, '/');
			*p = '\0';
			if (configfs_debug)
				printf("%s: delete subsystem '%s'\n",
				       __func__, value);
			ret = etcd_kv_delete(ctx, value);
			if (ret < 0) {
				if (configfs_debug)
					fprintf(stderr,
						"%s: failed to delete %s\n",
						__func__, value);
			}
		}
	}
	etcd_kv_free(kvs, ret);
	return ret;
}

int configfs_register(struct etcd_ctx *ctx)
{
	char name_key[256];
	char value[256];
	int ret;

	sprintf(name_key, "%s/cluster/%s/node_name",
		ctx->prefix, ctx->node_id);
	strcpy(value, ctx->node_name);
	ret = etcd_kv_store(ctx, name_key, value, strlen(value));
	if (ret < 0) {
		fprintf(stderr, "%s: node %s register error %d\n",
			__func__, ctx->node_id, ret);
		return ret;
	}
	ret = etcd_set_cluster_id(ctx);
	if (ret < 0) {
		etcd_kv_delete(ctx, name_key);
	}
	if (configfs_debug)
		printf("%s: using cluster id %u\n",
		       __func__, ctx->cluster_id);
	return ret;
}

int configfs_unregister(struct etcd_ctx *ctx)
{
	char name_key[256];
	int ret;

	sprintf(name_key, "%s/cluster/%s/",
		ctx->prefix, ctx->node_id);
	ret = etcd_kv_delete(ctx, name_key);
	if (ret < 0) {
		fprintf(stderr, "%s: node %s unregister error %d\n",
			__func__, ctx->node_id, ret);
	}
	return ret;
}
