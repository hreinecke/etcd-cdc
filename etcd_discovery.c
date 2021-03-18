/*
 * etcd_discovery.c
 * Discover subsystems by watching keys in etcd
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include <json-c/json.h>
#include <libnvme.h>

#include "list.h"
#include "etcd_cdc.h"

static char *default_host = "localhost";
static char *default_proto = "http";
static char *default_prefix = "nvmet";

LIST_HEAD(disc_db_list);

struct disc_db_entry {
	struct list_head entry;
	char *subsys;
	char *port_id;
	struct nvme_fabrics_config cfg;
};

static void parse_discovery_response(struct etcd_cdc_ctx *ctx,
				     struct json_object *resp_obj)
{
	json_object_object_foreach(resp_obj, key, val_obj) {
		char *key_save, *k, *subsys, *port_id;
		struct disc_db_entry *disc_entry = NULL, *tmp;
		char *addr, *a, *addr_save;
		char *traddr = NULL, *trtype = NULL, *trsvcid = NULL;

		if (strncmp(key, ctx->prefix, strlen(ctx->prefix))) {
			fprintf(stderr, "Skip invalid prefix '%s'\n", key);
			continue;
		}
		k = strtok_r(key + strlen(ctx->prefix), "/", &key_save);
		if (!k || !strlen(k)) {
			fprintf(stderr, "Skip invalid key '%s'\n", key);
			continue;
		}
		subsys = k;
		k = strtok_r(NULL, "/", &key_save);
		if (!k || !strlen(k)) {
			fprintf(stderr, "Skip invalid key '%s'\n", key);
			continue;
		}
		port_id = k;
		disc_entry = NULL;
		list_for_each_entry(tmp, &disc_db_list, entry) {
			if (!strcmp(tmp->subsys, subsys) &&
			    !strcmp(tmp->port_id, port_id)) {
				disc_entry = tmp;
				break;
			}
		}
		if (!disc_entry) {
			disc_entry = malloc(sizeof(struct disc_db_entry));
			if (!disc_entry) {
				fprintf(stderr,
					"Cannot allocate discovery entry\n");
				continue;
			}
			memset(disc_entry, 0, sizeof(struct disc_db_entry));
			INIT_LIST_HEAD(&disc_entry->entry);
			disc_entry->subsys = strdup(subsys);
			disc_entry->port_id = strdup(port_id);
			if (ctx->debug)
				printf("Creating subsys %s port %s\n",
				       disc_entry->subsys, disc_entry->port_id);
			list_add(&disc_entry->entry, &disc_db_list);
		}
		addr = strdup(json_object_get_string(val_obj));
		a = strtok_r(addr, ",", &addr_save);
		while (a && strlen(a)) {
			if (!strncmp(a, "trtype=", 7))
				trtype = a + 7;
			else if (!strncmp(a, "traddr=", 7))
				traddr = a + 7;
			else if (!strncmp(a, "trsvcid=", 8))
				trsvcid = a + 8;
			a = strtok_r(NULL, ",", &addr_save);
		}
		if (!trtype || !traddr) {
			fprintf(stderr, "invalid entry %s\n",
				json_object_get_string(val_obj));
			continue;
		}
		disc_entry->cfg.transport = strdup(trtype);
		disc_entry->cfg.traddr = strdup(traddr);
		if (trsvcid)
			disc_entry->cfg.trsvcid = strdup(trsvcid);
		free(addr);
	}
}		

static int match_address(struct nvme_fabrics_config *cfg, nvme_ctrl_t c)
{
	char *addr;
	char *p, *save;
	int match = 0;

	addr = strdup(nvme_ctrl_get_address(c));
	p = strtok_r(addr, "/", &save);
	while (p) {
		char *a = p;
		p = strtok_r(NULL, "/", &save);
		if (!strncmp(a, "traddr=", 7) &&
		    strncmp(a + 7, cfg->traddr, strlen(cfg->traddr))) {
			printf("traddr mismatch %s %s\n", a + 7, cfg->traddr);
			return 0;
		}
		if (cfg->trsvcid &&
		    !strncmp(a, "trsvcid=", 8) &&
		    strncmp(a + 8, cfg->trsvcid, strlen(cfg->trsvcid))) {
			printf("trsvcid mismatch %s %s\n", a + 8, cfg->trsvcid);
			return 0;
		}
		if (cfg->host_traddr &&
		    !strncmp(a, "host_traddr=", 12) &&
		    strncmp(a + 12, cfg->host_traddr,
			    strlen(cfg->host_traddr))) {
			printf("host_traddr mismatch %s %s\n",
			       a + 12, cfg->host_traddr);
			return 0;
		}
		match++;
	}
	free(addr);
	return match;
}			
	
static nvme_ctrl_t find_ctrl(struct etcd_cdc_ctx *ctx, nvme_root_t nvme_root,
			     struct nvme_fabrics_config *cfg)
{
	nvme_subsystem_t subsys;

	if (ctx->debug)
		printf("looking for %s trtype %s traddr=%s trsvcid=%s\n",
		       cfg->nqn, cfg->transport, cfg->traddr, cfg->trsvcid);
	nvme_for_each_subsystem(nvme_root, subsys) {
		nvme_ctrl_t c;

		nvme_subsystem_for_each_ctrl(subsys, c) {
			printf("Checking %s %s trtype %s addr %s\n",
			       nvme_ctrl_get_name(c),
			       nvme_ctrl_get_subsysnqn(c),
			       nvme_ctrl_get_transport(c),
			       nvme_ctrl_get_address(c));
			if (strcmp(cfg->nqn,
				   nvme_ctrl_get_subsysnqn(c))) {
				if (ctx->debug)
					printf("subsys mismatch\n");
				continue;
			}
			if (strcmp(cfg->transport,
				   nvme_ctrl_get_transport(c))) {
				if (ctx->debug)
					printf("transport mismatch\n");
				continue;
			}
			if (!match_address(cfg, c)) {
				if (ctx->debug)
					printf("address mismatch\n");
				continue;
			}
			printf("Matching controller %s\n",
			       nvme_ctrl_get_name(c));
			return c;
		}
	}
	return NULL;
}
			
static void exec_discovery(struct etcd_cdc_ctx *ctx, nvme_root_t root,
			  char *hostnqn)
{
	struct disc_db_entry *disc_entry;

	list_for_each_entry(disc_entry, &disc_db_list, entry) {
		nvme_ctrl_t c;

		disc_entry->cfg.hostnqn = hostnqn;
		disc_entry->cfg.nqn = disc_entry->subsys;

		c = find_ctrl(ctx, root, &disc_entry->cfg);
		if (c) {
			if (ctx->debug)
				printf("Skip existing controller %s\n",
				       nvme_ctrl_get_name(c));
			continue;
		}
		c = nvmf_add_ctrl(&disc_entry->cfg);
		if (!c)
			fprintf(stderr,
				"Failed to create connection, error %d\n", errno);
		else
			printf("Created controller %s\n",
			       nvme_ctrl_get_name(c));
	}
}

int main(int argc, char **argv)
{
	struct option getopt_arg[] = {
		{"port", required_argument, 0, 'p'},
		{"host", required_argument, 0, 'h'},
		{"ssl", no_argument, 0, 's'},
		{"etcd_prefix", required_argument, 0, 'e'},
		{"verbose", no_argument, 0, 'v'},
	};
	char c;
	int getopt_ind;
	struct etcd_cdc_ctx *ctx;
	nvme_root_t nvme_root;
	struct disc_db_entry *disc_entry, *tmp;
	char *hostnqn;
	char *prefix = default_prefix;
	int ret = 0;

	ctx = malloc(sizeof(struct etcd_cdc_ctx));
	if (!ctx) {
		fprintf(stderr, "cannot allocate context\n");
		exit(1);
	}
	memset(ctx, 0, sizeof(struct etcd_cdc_ctx));
	ctx->host = default_host;
	ctx->proto = default_proto;
	ctx->port = 2379;
	ctx->resp_obj = json_object_new_object();

	while ((c = getopt_long(argc, argv, "e:p:h:sv",
				getopt_arg, &getopt_ind)) != -1) {
		switch (c) {
		case 'e':
			prefix = optarg;
			break;
		case 'h':
			ctx->host = optarg;
			break;
		case 'p':
			ctx->port = atoi(optarg);
			break;
		case 's':
			ctx->proto = "https";
			break;
		case 'v':
			ctx->debug++;
			break;
		}
	}

	hostnqn = nvmf_hostnqn_from_file();
	if (!hostnqn) {
		fprintf(stderr, "no host NQN found\n");
		exit(1);
	}

	ctx->prefix = malloc(strlen(prefix) + NVMF_NQN_SIZE + 3);
	if (!ctx->prefix) {
		fprintf(stderr, "failed to allocate key\n");
		exit(1);
	}
	sprintf(ctx->prefix, "%s/%s/", prefix, hostnqn);
	if (ctx->debug)
		printf("Using key %s\n", ctx->prefix);
	nvme_root = nvme_scan();

	ret = etcd_kv_range(ctx, ctx->prefix);
	if (ret)
		fprintf(stderr, "Failed to retrieve discovery information\n");
	else {
		parse_discovery_response(ctx, ctx->resp_obj);
		exec_discovery(ctx, nvme_root, hostnqn);
	}

	json_object_put(ctx->resp_obj);
	ctx->resp_obj = json_object_new_object();

	etcd_kv_watch(ctx, ctx->prefix);
	if (!ret) {
		json_object_object_foreach(ctx->resp_obj,
					   key_obj, val_obj)
			printf("%s: %s\n", key_obj,
			       json_object_get_string(val_obj));
	}

	nvme_free_tree(nvme_root);
	list_for_each_entry_safe(disc_entry, tmp, &disc_db_list, entry) {
		list_del_init(&disc_entry->entry);
		free(disc_entry->subsys);
		free(disc_entry->port_id);
		free(disc_entry);
	}
	free(ctx->prefix);
	free(ctx);
	return ret < 0 ? 1 : 0;
}
	
