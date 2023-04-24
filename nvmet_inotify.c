/*
 * nvmet_inotify.c
 * inotify watcher for nvmet configfs
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
#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <sys/types.h>
#include <fcntl.h>

#include <sys/inotify.h>

#include "list.h"

#include "nvmet_etcd.h"

LIST_HEAD(dir_watcher_list);

enum watcher_type {
	TYPE_PORT_DIR,		/* ports */
	TYPE_PORT,		/* ports/<port> */
	TYPE_PORT_SUBSYS_DIR,	/* ports/<port>/subsystems */
	TYPE_PORT_SUBSYS,	/* ports/<port>/subsystems/<subsys> */
	TYPE_SUBSYS_DIR,	/* subsystems */
	TYPE_SUBSYS,		/* subsystems/<subsys> */
	TYPE_SUBSYS_HOSTS_DIR,	/* subsystems/<subsys>/allowed_hosts */
	TYPE_SUBSYS_HOST,	/* subsystems/<subsys>/allowed_hosts/<host> */
};

struct dir_watcher {
	struct list_head entry;
	enum watcher_type type;
	int wd;
	char dirname[FILENAME_MAX];
};

/* TYPE_PORT */
struct nvmet_port {
	struct dir_watcher watcher;
	char port_id[256];
	char trtype[256];
	char traddr[256];
	char trsvcid[256];
};

/* TYPE_PORT_SUBSYS */
struct nvmet_port_subsys {
	struct dir_watcher watcher;
	struct nvmet_port *port;
	char subsysnqn[256];
};

/* TYPE_SUBSYS_HOST */
struct nvmet_subsys_host {
	struct dir_watcher watcher;
	struct nvmet_port_subsys *subsys;
	char hostnqn[256];
};

static struct nvmet_port *find_port_from_subsys(char *port_subsys_dir)
{
	struct dir_watcher *watcher;

	list_for_each_entry(watcher, &dir_watcher_list, entry) {
		if (watcher->type != TYPE_PORT)
			continue;
		if (strncmp(watcher->dirname, port_subsys_dir,
			    strlen(watcher->dirname)))
			continue;
		return container_of(watcher, struct nvmet_port, watcher);
	}
	fprintf(stderr, "No port found for subsys %s\n", port_subsys_dir);
	return NULL;
}

static struct nvmet_port_subsys *find_subsys_from_host(char *subsys_host_dir)
{
	char subnqn[256], *p;
	struct dir_watcher *watcher;
	struct nvmet_port_subsys *port_subsys;

	p = strchr(subsys_host_dir, '/');
	do {
		if (!p)
			break;
		p++;
		if (!strncmp(p, "subsystems", 10)) {
			strncpy(subnqn, p + 11, 256);
			break;
		}
	} while ((p = strchr(p, '/')));
	if (!strlen(subnqn)) {
		fprintf(stderr, "Invalid subsys path %s\n", subsys_host_dir);
		return NULL;
	}
	p = strchr(subnqn, '/');
	if (p)
		*p = '\0';

	list_for_each_entry(watcher, &dir_watcher_list, entry) {
		if (watcher->type != TYPE_PORT_SUBSYS)
			continue;
		port_subsys = container_of(watcher, struct nvmet_port_subsys,
					   watcher);
		if (strcmp(port_subsys->subsysnqn, subnqn))
			continue;
		return port_subsys;
	}
	return NULL;
}

void set_genctr(struct etcd_cdc_ctx *ctx, int genctr)
{
	char key[1024];
	char value[1024];

	sprintf(key, "%s/discovery/genctr", ctx->prefix);
	sprintf(value, "%d", genctr);

	if (etcd_kv_put(ctx, key, value) < 0) {
		fprintf(stderr, "cannot add key %s, error %d\n",
			key, errno);
	}
	printf("Updated key %s: %s\n", key, value);
}

static void update_genctr(struct etcd_cdc_ctx *ctx)
{
	char key[1024];
	char value[1024], *eptr;
	int genctr = 1;

	sprintf(key, "%s/discovery/genctr", ctx->prefix);
	if (etcd_kv_get(ctx, key) < 0) {
		printf("cannot get key %s, errno %d\n",
		       key, errno);
		return;
	}
	if (etcd_kv_value(ctx, key, value) < 0) {
		fprintf(stderr, "key %s not found\n", key);
		return;
	}
	genctr = strtoul(value, &eptr, 10);
	if (eptr == value) {
		fprintf(stderr, "key %s invalid value %s\n",
			key, value);
		genctr = 1;
	} else {
		genctr++;
	}
	set_genctr(ctx, genctr);
}

static void gen_host_kv_key(struct etcd_cdc_ctx *ctx,
			    struct nvmet_subsys_host *host, enum kv_key_op op)
{
	struct nvmet_port_subsys *subsys = host->subsys;
	struct nvmet_port *port;
	char key[1024];
	char value[1024];

	if (!subsys)
		return;
	port = subsys->port;
	if (!port)
		return;

	sprintf(key, "%s/%s/%s/%s", ctx->prefix,
		host->hostnqn, subsys->subsysnqn, port->port_id);
	if (op == KV_KEY_OP_ADD) {
		sprintf(value,"trtype=%s,traddr=%s",
			port->trtype, port->traddr);
		if (strlen(port->trsvcid)) {
			strcat(value,",trsvcid=");
			strcat(value, port->trsvcid);
		}
		printf("add key %s: %s\n", key, value);
		if (etcd_kv_put(ctx, key, value) < 0) {
			fprintf(stderr, "cannot add key %s, error %d\n",
				key, errno);
			return;
		}
	} else {
		printf("delete key %s\n", key);
		if (etcd_kv_delete(ctx, key) < 0) {
			fprintf(stderr, "cannot remove key %s, error %d\n",
				key, errno);
			return;
		}
	}
	update_genctr(ctx);
}

static void gen_subsys_kv_key(struct etcd_cdc_ctx *ctx,
			      struct nvmet_port_subsys *subsys,
			      enum kv_key_op op)
{
	struct dir_watcher *watcher;
	struct nvmet_subsys_host *host;

	list_for_each_entry(watcher, &dir_watcher_list, entry) {
		if (watcher->type != TYPE_SUBSYS_HOST)
			continue;
		host = container_of(watcher, struct nvmet_subsys_host, watcher);
		if (op == KV_KEY_OP_ADD && !host->subsys) {
			host->subsys = find_subsys_from_host(watcher->dirname);
#ifdef DEBUG
			if (host->subsys)
				printf("updated subsys for host %s\n",
				       host->hostnqn);
#endif
		}
		if (host->subsys == subsys) {
			gen_host_kv_key(ctx, host, op);
			if (op == KV_KEY_OP_DELETE)
				host->subsys = NULL;
		}
	}
}

static struct dir_watcher *add_watch(struct dir_watcher *watcher, int flags)
{
	struct dir_watcher *tmp;

	INIT_LIST_HEAD(&watcher->entry);
	list_for_each_entry(tmp, &dir_watcher_list, entry) {
		if (tmp->type != watcher->type)
			continue;
		if (strcmp(tmp->dirname, watcher->dirname))
			continue;
		return tmp;
	}
	watcher->wd = inotify_add_watch(inotify_fd, watcher->dirname,
					flags);
	if (watcher->wd < 0) {
		fprintf(stderr,
			"failed to add inotify watch to '%s', error %d\n",
			watcher->dirname, errno);
		return watcher;
	}
#ifdef DEBUG
	printf("add inotify watch %d type %d to %s\n",
	       watcher->wd, watcher->type, watcher->dirname);
#endif
	list_add(&watcher->entry, &dir_watcher_list);
	return 0;
}

static int remove_watch(struct dir_watcher *watcher)
{
	int ret;

	ret = inotify_rm_watch(inotify_fd, watcher->wd);
	if (ret < 0)
		fprintf(stderr, "Failed to remove inotify watch on '%s'\n",
			watcher->dirname);
#ifdef DEBUG
	printf("remove inotify watch %d type %d from '%s'\n",
	       watcher->wd, watcher->type, watcher->dirname);
#endif
	list_del_init(&watcher->entry);
	return ret;
}

static int watch_directory(char *dirname, enum watcher_type type, int flags)
{
	struct dir_watcher *watcher, *tmp;

	watcher = malloc(sizeof(struct dir_watcher));
	if (!watcher) {
		fprintf(stderr, "Failed to allocate dirwatch\n");
		return -1;
	}
	strcpy(watcher->dirname, dirname);
	watcher->type = type;
	tmp = add_watch(watcher, flags);
	if (tmp) {
		if (tmp == watcher)
			free(watcher);
		return -1;
	}
 	return 0;
}

static int port_read_attr(char *ports_dir, struct nvmet_port *port, char *attr)
{
	char attr_path[PATH_MAX + 1];
	char *attr_buf, *p;
	int fd, len;

	if (!strcmp(attr, "trtype"))
		attr_buf = port->trtype;
	else if (!strcmp(attr, "traddr"))
		attr_buf = port->traddr;
	else if (!strcmp(attr, "trsvcid"))
		attr_buf = port->trsvcid;
	else {
		fprintf(stderr, "Port %s: Invalid attribute '%s'\n",
			port->port_id, attr);
		return -1;
	}

	sprintf(attr_path, "%s/%s/addr_%s", ports_dir, port->port_id, attr);
	fd = open(attr_path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Port %s: Failed to open '%s', error %d\n",
			port->port_id, attr_path, errno);
		return -1;
	}
	len = read(fd, attr_buf, 256);
	if (len < 0)
		memset(attr_buf, 0, 256);
	else {
		p = &attr_buf[len - 1];
		if (*p == '\n')
			*p = '\0';
	}
	close(fd);
	return len;
}

static struct nvmet_port *update_port(char *ports_dir, char *port_id)
{
	struct nvmet_port *port;

	port = malloc(sizeof(struct nvmet_port));
	if (!port) {
		fprintf(stderr, "Port %s: Failed to allocate port\n",
			port_id);
		return NULL;
	}
	strcpy(port->port_id, port_id);
	port_read_attr(ports_dir, port, "trtype");
	port_read_attr(ports_dir, port, "traddr");
	port_read_attr(ports_dir, port, "trsvcid");
	return port;
}

static void watch_port_subsys(struct etcd_cdc_ctx *ctx,
			      char *port_subsys_dir, char *subsysnqn)
{
	struct nvmet_port_subsys *subsys;
	struct dir_watcher *watcher;

	subsys = malloc(sizeof(struct nvmet_port_subsys));
	if (!subsys) {
		fprintf(stderr, "Failed to allocate subsys %s\n",
			subsysnqn);
		return;
	}
	strcpy(subsys->subsysnqn, subsysnqn);
	strcpy(subsys->watcher.dirname, port_subsys_dir);
	strcat(subsys->watcher.dirname, "/");
	strcat(subsys->watcher.dirname, subsysnqn);
	subsys->watcher.type = TYPE_PORT_SUBSYS;
	watcher = add_watch(&subsys->watcher, IN_DELETE_SELF);
	if (watcher) {
		if (watcher == &subsys->watcher)
			free(subsys);
		return;
	}
	subsys->port = find_port_from_subsys(port_subsys_dir);
	gen_subsys_kv_key(ctx, subsys, KV_KEY_OP_ADD);
}
	
static void watch_port(struct etcd_cdc_ctx *ctx,
		       char *ports_dir, char *port_id)
{
	struct nvmet_port *port;
	struct dir_watcher *watcher;
	char subsys_dir[PATH_MAX + 1];
	DIR *sd;
	struct dirent *se;

	port = update_port(ports_dir, port_id);
	if (!port)
		return;

	strcpy(subsys_dir, ports_dir);
	strcat(subsys_dir, "/");
	strcat(subsys_dir, port_id);
	strcpy(port->watcher.dirname, subsys_dir);
	port->watcher.type = TYPE_PORT;
	watcher = add_watch(&port->watcher, IN_DELETE_SELF);
	if (watcher) {
		if (watcher == &port->watcher)
			free(port);
		return;
	}

	strcat(subsys_dir, "/subsystems");
	watch_directory(subsys_dir, TYPE_PORT_SUBSYS_DIR,
			IN_CREATE | IN_DELETE | IN_DELETE_SELF);

	sd = opendir(subsys_dir);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", subsys_dir);
		return;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		watch_port_subsys(ctx, subsys_dir, se->d_name);
	}
	closedir(sd);
}

static void watch_subsys_hosts(struct etcd_cdc_ctx *ctx,
			       char *hosts_dir, char *hostnqn)
{
	struct nvmet_subsys_host *host;
	struct dir_watcher *watcher;

	host = malloc(sizeof(struct nvmet_subsys_host));
	if (!host) {
		fprintf(stderr, "Cannot allocate %s\n", hostnqn);
		return;
	}
	strcpy(host->hostnqn, hostnqn);
	strcpy(host->watcher.dirname, hosts_dir);
	strcat(host->watcher.dirname, "/");
	strcat(host->watcher.dirname, hostnqn);
	host->watcher.type = TYPE_SUBSYS_HOST;

	watcher = add_watch(&host->watcher, IN_DELETE_SELF);
	if (watcher) {
		if (watcher == &host->watcher)
			free(host);
		return;
	}
	host->subsys = find_subsys_from_host(hosts_dir);
	gen_host_kv_key(ctx, host, KV_KEY_OP_ADD);
}

static void watch_subsys(struct etcd_cdc_ctx *ctx,
			 char *subsys_dir, char *subnqn)
{
	char hosts_dir[PATH_MAX + 1];
	DIR *hd;
	struct dirent *he;

	sprintf(hosts_dir, "%s/%s/allowed_hosts",
		subsys_dir, subnqn);
	watch_directory(hosts_dir, TYPE_SUBSYS_HOSTS_DIR,
			IN_CREATE | IN_DELETE | IN_DELETE_SELF);
	hd = opendir(hosts_dir);
	if (!hd) {
		fprintf(stderr, "Cannot open %s\n", hosts_dir);
		return;
	}
	while ((he = readdir(hd))) {
		if (!strcmp(he->d_name, ".") ||
		    !strcmp(he->d_name, ".."))
			continue;
		watch_subsys_hosts(ctx, hosts_dir, he->d_name);
	}
	closedir(hd);
}

static void
display_inotify_event(struct inotify_event *ev)
{
#ifdef DEBUG
	printf("inotify wd = %d; ", ev->wd);
	if (ev->cookie > 0)
		printf("cookie = %4d; ", ev->cookie);

	printf("mask = ");

	if (ev->mask & IN_ISDIR)
		printf("IN_ISDIR ");

	if (ev->mask & IN_CREATE)
		printf("IN_CREATE ");

	if (ev->mask & IN_DELETE)
		printf("IN_DELETE ");

	if (ev->mask & IN_DELETE_SELF)
		printf("IN_DELETE_SELF ");

	if (ev->mask & IN_MOVE_SELF)
		printf("IN_MOVE_SELF ");
	if (ev->mask & IN_MOVED_FROM)
		printf("IN_MOVED_FROM ");
	if (ev->mask & IN_MOVED_TO)
		printf("IN_MOVED_TO ");

	if (ev->mask & IN_IGNORED)
		printf("IN_IGNORED ");
	if (ev->mask & IN_Q_OVERFLOW)
		printf("IN_Q_OVERFLOW ");
	if (ev->mask & IN_UNMOUNT)
		printf("IN_UNMOUNT ");

	if (ev->len > 0)
		printf("name = %s", ev->name);
	printf("\n");
#endif
}

int process_inotify_event(struct etcd_cdc_ctx *ctx,
			  char *iev_buf, int iev_len)
{
	struct inotify_event *ev;
	struct dir_watcher *tmp_watcher, *watcher = NULL;
	struct nvmet_subsys_host *host;
	struct nvmet_port_subsys *subsys;
	int ev_len;

	ev = (struct inotify_event *)iev_buf;
	display_inotify_event(ev);
	ev_len = sizeof(struct inotify_event) + ev->len;
	if (ev->mask & IN_IGNORED)
		return ev_len;

	list_for_each_entry(tmp_watcher, &dir_watcher_list, entry) {
		if (tmp_watcher->wd == ev->wd) {
			watcher = tmp_watcher;
			break;
		}
	}
	if (!watcher) {
#ifdef DEBUG
		printf("No watcher for wd %d\n", ev->wd);
#endif
		return ev_len;
	}
	if (ev->mask & IN_CREATE) {
		char subdir[FILENAME_MAX + 1];

		sprintf(subdir, "%s/%s", watcher->dirname, ev->name);
#ifdef DEBUG
		if (ev->mask & IN_ISDIR)
			printf("mkdir %s\n", subdir);
		else
			printf("link %s\n", subdir);
#endif
		switch (watcher->type) {
		case TYPE_PORT_DIR:
			watch_port(ctx, watcher->dirname, ev->name);
			break;
		case TYPE_PORT_SUBSYS_DIR:
			watch_port_subsys(ctx, watcher->dirname, ev->name);
			break;
		case TYPE_SUBSYS_DIR:
			watch_subsys(ctx, watcher->dirname, ev->name);
			break;
		case TYPE_SUBSYS_HOSTS_DIR:
			watch_subsys_hosts(ctx, watcher->dirname, ev->name);
			break;
		default:
			fprintf(stderr, "Unhandled create type %d\n",
				watcher->type);
			break;
		}
	} else if (ev->mask & IN_DELETE_SELF) {
		struct nvmet_port *port;

#ifdef DEBUG
		printf("rmdir %s type %d\n", watcher->dirname, watcher->type);
#endif
		/* Watcher is already removed */
		list_del_init(&watcher->entry);
		switch (watcher->type) {
		case TYPE_PORT:
			port = container_of(watcher,
					    struct nvmet_port, watcher);
			free(port);
			break;
		default:
			free(watcher);
			break;
		}
	} else if (ev->mask & IN_DELETE) {
		char subdir[FILENAME_MAX + 1];

		sprintf(subdir, "%s/%s", watcher->dirname, ev->name);
#ifdef DEBUG
		if (ev->mask & IN_ISDIR)
			printf("rmdir %s\n", subdir);
		else
			printf("unlink %s\n", subdir);
#endif
		list_for_each_entry(tmp_watcher, &dir_watcher_list, entry) {
			if (strcmp(tmp_watcher->dirname, subdir))
				continue;
			watcher = tmp_watcher;
		}
		if (watcher) {
			remove_watch(watcher);
			switch (watcher->type) {
			case TYPE_SUBSYS_HOST:
				host = container_of(watcher,
						    struct nvmet_subsys_host,
						    watcher);
				gen_host_kv_key(ctx, host, KV_KEY_OP_DELETE);
				host->subsys = NULL;
				free(host);
				break;
			case TYPE_PORT_SUBSYS:
				subsys = container_of(watcher,
						      struct nvmet_port_subsys,
						      watcher);
				gen_subsys_kv_key(ctx, subsys, KV_KEY_OP_DELETE);
				subsys->port = NULL;
				free(subsys);
				break;
			default:
				fprintf(stderr, "Unhandled delete type %d\n",
					watcher->type);
				free(watcher);
				break;
			}
		}
	}
	return ev_len;
}

int watch_port_dir(struct etcd_cdc_ctx *ctx)
{
	char ports_dir[PATH_MAX + 1];
	DIR *pd;
	struct dirent *pe;

	strcpy(ports_dir, ctx->configfs);
	strcat(ports_dir, "/ports");
	watch_directory(ports_dir, TYPE_PORT_DIR,
			IN_CREATE | IN_DELETE_SELF);

	pd = opendir(ports_dir);
	if (!pd) {
		fprintf(stderr, "Cannot open %s\n", ports_dir);
		return -1;
	}
	while ((pe = readdir(pd))) {
		if (!strcmp(pe->d_name, ".") ||
		    !strcmp(pe->d_name, ".."))
			continue;
		watch_port(ctx, ports_dir, pe->d_name);
	}
	closedir(pd);
	return 0;
}

int watch_subsys_dir(struct etcd_cdc_ctx *ctx)
{
	char subsys_dir[PATH_MAX + 1];
	DIR *sd;
	struct dirent *se;

	strcpy(subsys_dir, ctx->configfs);
	strcat(subsys_dir, "/subsystems");
	watch_directory(subsys_dir, TYPE_SUBSYS_DIR,
			IN_CREATE | IN_DELETE_SELF);

	sd = opendir(subsys_dir);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", subsys_dir);
		return -1;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		watch_subsys(ctx, subsys_dir, se->d_name);
	}
	closedir(sd);
	return 0;
}

void cleanup_watcher(void)
{
	struct dir_watcher *watcher, *tmp_watch;

    	list_for_each_entry_safe(watcher, tmp_watch, &dir_watcher_list, entry) {
		remove_watch(watcher);
		free(watcher);
	}
}
