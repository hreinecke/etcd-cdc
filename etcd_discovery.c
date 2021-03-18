#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

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
		char *save, *p, *subsys, *port_id, *attr;
		struct disc_db_entry *disc_entry = NULL, *tmp;

		if (strncmp(key, ctx->prefix, strlen(ctx->prefix))) {
			fprintf(stderr, "Skip invalid prefix '%s'\n", key);
			continue;
		}
		p = strtok_r(key + strlen(ctx->prefix), "/", &save);
		if (!p || !strlen(p)) {
			fprintf(stderr, "Skip invalid key '%s'\n", key);
			continue;
		}
		subsys = p;
		p = strtok_r(NULL, "/", &save);
		if (!p || !strlen(p)) {
			fprintf(stderr, "Skip invalid key '%s'\n", key);
			continue;
		}
		port_id = p;
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
			disc_entry->subsys = strdup(subsys);
			disc_entry->port_id = strdup(port_id);
		}
		p = strtok_r(NULL, "/", &save);
		if (!p || !strlen(p)) {
			fprintf(stderr, "Skip invalid key '%s'\n", key);
			continue;
		}
		attr = p;
		if (!strcmp(attr, "trtype")) {
			disc_entry->cfg.transport =
				strdup(json_object_get_string(val_obj));
		} else if (!strcmp(attr, "traddr")) {
			disc_entry->cfg.traddr =
				strdup(json_object_get_string(val_obj));
		} else if (!strcmp(attr, "trsvcid")) {
			disc_entry->cfg.trsvcid =
				strdup(json_object_get_string(val_obj));
		} else if (!strcmp(attr, "host_traddr")) {
			disc_entry->cfg.host_traddr =
				strdup(json_object_get_string(val_obj));
		}
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
		if (!strncmp(p, "traddr=", 7) &&
		    strcmp(p + 7, cfg->traddr))
			return 0;
		if (cfg->trsvcid &&
		    !strncmp(p, "trsvcid=", 8) &&
		    strcmp(p + 8, cfg->trsvcid))
			return 0;
		if (cfg->host_traddr &&
		    !strncmp(p, "host_traddr=", 12) &&
		    strcmp(p + 12, cfg->host_traddr))
			return 0;
		p = strtok_r(NULL, "/", &save);
		match++;
	}
	free(addr);
	return match;
}			
	
static nvme_ctrl_t find_ctrl(nvme_root_t nvme_root,
			     struct nvme_fabrics_config *cfg)
{
	nvme_subsystem_t subsys;

	nvme_for_each_subsystem(nvme_root, subsys) {
		nvme_ctrl_t c;

		nvme_subsystem_for_each_ctrl(subsys, c) {
			if (strcmp(cfg->nqn,
				   nvme_ctrl_get_subsysnqn(c)))
				continue;
			if (strcmp(cfg->transport,
				   nvme_ctrl_get_transport(c)))
				continue;
			if (!match_address(cfg, c))
				continue;
			printf("Use existing controller %s\n",
			       nvme_ctrl_get_name(c));
			return c;
		}
	}
	return NULL;
}
			
static void exec_connect(struct etcd_cdc_ctx *ctx, nvme_root_t root,
			 struct disc_db_entry *disc_entry,
			 struct nvmf_discovery_log *disc_log)
{
	int i, numrec = le64_to_cpu(disc_log->numrec);
	bool discover;

	for (i = 0; i < numrec; i++) {
		struct nvmf_disc_log_entry *e = &disc_log->entries[i];
		nvme_ctrl_t c;

		c = find_ctrl(root, &disc_entry->cfg);
		if (c)
			continue;
		c = nvmf_connect_disc_entry(e, &disc_entry->cfg, &discover);
		if (!c)
			fprintf(stderr, "Failed to connect\n");
	}
}
			 
static void exec_discovery(struct etcd_cdc_ctx *ctx, nvme_root_t root,
			  char *hostnqn)
{
	struct disc_db_entry *disc_entry;
	int ret;

	list_for_each_entry(disc_entry, &disc_db_list, entry) {
		struct nvmf_discovery_log *log;
		nvme_ctrl_t c;
		bool created = false;

		disc_entry->cfg.hostnqn = hostnqn;
		disc_entry->cfg.nqn = NVME_DISC_SUBSYS_NAME;

		c = find_ctrl(root, &disc_entry->cfg);
		if (!c) {
			c = nvmf_add_ctrl(&disc_entry->cfg);
			created = true;
		}
		if (!c) {
			fprintf(stderr, "no discovery controller found\n");
			continue;
		}
		ret = nvmf_get_discovery_log(c, &log, 4);
		if (!ret)
			exec_connect(ctx, root, disc_entry, log);
		if (!created)
			continue;
		nvme_ctrl_disconnect(c);
		nvme_free_ctrl(c);
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

	ctx->prefix = malloc(strlen(prefix) + strlen(hostnqn) + 3);
	if (!ctx->prefix) {
		fprintf(stderr, "failed to allocate key\n");
		exit(1);
	}
	sprintf(ctx->prefix, "%s/%s/", prefix, hostnqn);

	nvme_root = nvme_scan();

	ret = etcd_kv_range(ctx, ctx->prefix);
	if (ret)
		fprintf(stderr, "Failed to retrieve discovery information\n");
	else {
		parse_discovery_response(ctx, ctx->resp_obj);
		exec_discovery(ctx, nvme_root, hostnqn);
	}
	
	json_object_put(ctx->resp_obj);
	nvme_free_tree(nvme_root);
	free(ctx->prefix);
	free(ctx);
	return ret < 0 ? 1 : 0;
}
	
