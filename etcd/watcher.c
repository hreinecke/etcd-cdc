/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * etcd_watcher.c
 * Watch etcd keys and push updates into nvmet configfs
 *
 * Copyright (c) 2025 Hannes Reinecke <hare@suse.de>
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>

#include "common.h"
#include "nvme.h"
#include "etcd/client.h"
#include "etcd/backend.h"
#include "configfs.h"

static int parse_port(char *key, unsigned int *portid, char **attr)
{
	char *port, *s, *eptr;
	unsigned long p;

	port = strtok_r(key, "/", &s);
	if (!port)
		return -EINVAL;
	errno = 0;
	p = strtoul(port, &eptr, 10);
	if (errno || p > UINT_MAX)
		return -ERANGE;

	*portid = p;
	*attr = strtok_r(NULL, "/", &s);
	return 0;
}

static int parse_subsys_nsid(char *key, char **subsysnqn, int *nsid,
			     char **attr)
{
	char *ns, *p, *s;
	unsigned long _nsid;
	int ret = -EINVAL;

	*subsysnqn = strtok_r(key, "/", &s);
	if (!*subsysnqn)
		goto out;
	*attr = strtok_r(NULL, "/", &s);
	if (!*attr)
		goto out;

	if (!strcmp(*attr, "namespaces")) {
		ns = strtok_r(NULL, "/", &s);
		if (!*ns)
			goto out;
		_nsid = strtoul(ns, NULL, 10);
		if (_nsid == ULONG_MAX) {
			ret = -ERANGE;
			goto out;
		}
		*nsid = _nsid;
		*attr = strtok_r(NULL, "/", &s);
		if (!attr)
			goto out;
		p = strtok_r(NULL, "/", &s);
		if (p)
			goto out;
		ret = 0;
	} else {
		*nsid = -1;
		ret = 0;
	}

out:
	if (ret < 0) {
		*subsysnqn = NULL;
		*nsid = -1;
		*attr = NULL;
	}
	return ret;
}

static int create_value(const char *path, char *value)
{
	char *parent, *ptr;
	struct stat st;
	int ret;

	/* Trying to create path */
	parent = strdup(path);
	ptr = strrchr(parent, '/');
	if (!ptr) {
		printf("%s: invalid parent %s\n",
		       __func__, parent);
		ret = -EINVAL;
		goto out;
	}
	*ptr = '\0';
	ret = stat(parent, &st);
	if (!ret) {
		/* Parent is present */
		ptr = strrchr(parent, '/');
		if (!strcmp(ptr, "/subsystems") ||
		    !strcmp(ptr, "/allowed_hosts")) {
			/* Need to create a symlink */
			printf("%s: symlink %s to %s\n",
			       __func__, path, value);
			ret = symlink(value, path);
			if (ret < 0) {
				printf("%s: error %d creating %s\n",
				       __func__, errno, path);
				ret = -ENOLINK;
			}
			goto out;
		}
		/* Parent is present, error */
		printf("%s: parent %s existing\n",
		       __func__, parent);
		ret = -EEXIST;
		goto out;
	}
	if (errno != ENOENT) {
		printf("%s: error %d accessing parent %s\n",
		       __func__, errno, parent);
		ret = -EPERM;
		goto out;
	}
	printf("%s: create parent %s\n", __func__, parent);
	ret = mkdir(parent, 0755);
	if (ret < 0) {
		printf("%s: error %d creating parent %s\n",
		       __func__, errno, parent);
		ret = -EPERM;
	}
out:
	free(parent);
	return ret;
}

int delete_value(const char *path, unsigned int mode)
{
	char *parent, *ptr;
	struct stat st;
	size_t offset;
	int ret;

	/* Symlinks can be removed directly. */
	if (mode == S_IFLNK) {
		ret = unlink(path);
		if (ret < 0) {
			printf("%s: unlink %s error %d\n",
			       __func__, path, errno);
			ret = -errno;
		}
		return ret;
	}

	/* For other attributes the parent needs to be deleted */
	parent = strdup(path);
	ptr = strrchr(parent, '/');
	if (!ptr) {
		printf("%s: invalid parent %s\n",
		       __func__, parent);
		free(parent);
		return -EINVAL;
	}
	*ptr = '\0';
	ret = stat(parent, &st);
	if (ret < 0) {
		/* already deleted ... */
		if (errno == ENOENT) {
			ret = 0;
			goto out;
		}
		printf("%s: error %d accessing %s\n",
		       __func__, errno, parent);
		ret = -errno;
		goto out;
	}
	offset = strlen(parent) - 12;
	if (!strcmp(parent + offset, "ana_groups/1")) {
		printf("%s: skip ana group 1\n", __func__);
		ret = 0;
		goto out;
	}
	ret = rmdir(parent);
	if (ret < 0) {
		printf("%s: error %d deleting parent %s\n",
		       __func__, errno, parent);
		ret = -errno;
	}
out:
	free(parent);
	return ret;
}

static int update_key_to_value(const char *path, char *value)
{
	int fd, ret;
	char buf[256];

	fd = open(path, O_RDWR);
	if (fd < 0) {
		printf("%s: error opening %s\n",
		       __func__, path);
		return -errno;
	}
	memset(buf, 0, sizeof(buf));
	ret = read(fd, buf, 256);
	if (ret < 0) {
		printf("%s: error reading %s\n", __func__, path);
		ret = -errno;
		goto out_close;
	}
	/* Remove newlines from 'buf' */
	if (ret > 0) {
		buf[ret] = '\0';
		if (buf[ret - 1] == '\n') {
			buf[ret - 1] = '\0';
			ret --;
		}
	}
	if (!strcmp(buf, value))
		goto out_close;

	printf("%s: update from %s (size %d) to %s\n",
	       __func__, buf, ret, value);
	ret = write(fd, value, strlen(value));
	if (ret < 0) {
		printf("%s: failed to update %s, error %d\n",
		       __func__, path, errno);
		/* reset to original value */
		if (write(fd, buf, strlen(buf)) < 0) {
			printf("%s: failed to reset %s, error %d\n",
			       __func__, path, errno);
		}
		ret = -errno;
	}

out_close:
	close(fd);
	return ret;
}

static int validate_key(struct etcd_ctx *ctx, struct etcd_kv *kv)
{
	int ret = 0;
	char *key = kv->key + strlen(ctx->prefix) + 1, *attr;

	if (!strncmp(key, "ports", 5)) {
		char *arg = strdup(key + 6);
		unsigned int portid;

		ret = parse_port(arg, &portid, &attr);
		if (ret < 0) {
			free(arg);
			return ret;
		}

		if (!strcmp(attr, "addr_node")) {
			/* Skip updates to 'addr_node' */
			free(arg);
			return -EINVAL;
		}
		ret = etcd_validate_port(ctx, portid);
		free(arg);
	}
	if (!strncmp(key, "subsystems", 10)) {
		int nsid = -1;
		char *subsys;
		char *arg = strdup(key + 11);

		ret = parse_subsys_nsid(arg, &subsys, &nsid, &attr);
		if (ret < 0) {
			printf("%s: failed to parse subsystem '%s'\n",
			       __func__, arg);
			free(arg);
			return ret;
		}
		if (nsid < 0) {
			free(arg);
			return 0;
		}
		if (!strcmp(attr, "device_node")) {
			/* Skip updates to 'device_node' */
			free(arg);
			return -EINVAL;
		}
		/* Only store 'enable' or 'device_path' values if
		 * running on the local node */
		if (!strcmp(attr, "enable") ||
		    !strcmp(attr, "device_path")) {
			ret = etcd_validate_namespace(ctx, subsys, nsid);
			if (ret < 0)
				printf("%s: failed to validate subsys '%s' nsid %d\n",
				       __func__, subsys, nsid);
		}
		free(arg);
	}
	return ret;
}

char *key_to_attr(struct etcd_ctx *ctx, char *key)
{
	const char *attr = key + strlen(ctx->prefix) + 1;
	char *path;
	int ret;

	if (!strncmp(attr, "cluster", strlen("cluster")))
		return NULL;

	if (!strcmp(attr, "cntlid_min") ||
	    !strcmp(attr, "cntlid_max"))
		return NULL;

	ret = asprintf(&path, "%s/%s", ctx->configfs, attr);
	if (ret < 0) {
		printf("%s: out of memory\n", __func__);
		return NULL;
	}
	return path;
}

void etcd_watch_cb(void *arg, struct etcd_kv *kv)
{
	struct etcd_ctx *ctx = arg;
	struct stat st;
	char *path;
	int ret;

	if (kv->deleted)
		printf("%s: delete key %s\n",
		       __func__, kv->key);
	else
		printf("%s: add key %s value %s\n", __func__,
		       kv->key, kv->value);

	path = key_to_attr(ctx, kv->key);
	if (!path) {
		printf("%s: invalid path for key %s\n",
		       __func__, kv->key);
		return;
	}
	ret = lstat(path, &st);
	if (ret < 0) {
		if (errno != ENOENT) {
			printf("%s: error %d accessing %s\n",
			       __func__, errno, path);
			goto out_free;
		}
		if (kv->deleted)
			/* KV deleted and path not present, all done */
			goto out_free;
		ret = validate_key(ctx, kv);
		if (ret < 0) {
			printf("%s: skip key %s creation\n",
			       __func__, kv->key);
			goto out_free;
		}
		ret = create_value(path, kv->value);
		if (ret < 0) {
			/*
			 * If the symlink could not be created
			 * -ENOLINK is returned, and we should
			 * delete the KV key to indicate the error.
			 */
			if (ret == -ENOLINK)
				etcd_kv_delete(ctx, kv->key);
			goto out_free;
		}
		/* retry, should succeed now */
		ret = lstat(path, &st);
		if (ret < 0) {
			printf("%s: error %d accessing %s\n",
			       __func__, errno, path);
			goto out_free;
		}
	}
	if (kv->deleted) {
		ret = delete_value(path, (st.st_mode & S_IFMT));
	} else if ((st.st_mode & S_IFMT) == S_IFREG) {
		if (kv->value)
			ret = update_key_to_value(path, kv->value);
	} else if ((st.st_mode & S_IFMT) == S_IFLNK) {
		/* All done in create_value() */
		ret = 0;
	} else {
		printf("%s: unhandled attribute type for %s\n",
		       __func__, path);
		ret = -EINVAL;
	}
out_free:
	free(path);
}
