/*
 * etcd_tool.c
 * Utility to query and modify etcd key-value store
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
#include <string.h>
#include <getopt.h>
#include <stdlib.h>

#include "etcd_cdc.h"

int main(int argc, char **argv)
{
	struct option getopt_arg[] = {
		{"port", required_argument, 0, 'p'},
		{"host", required_argument, 0, 'h'},
		{"ssl", no_argument, 0, 's'},
		{"verbose", no_argument, 0, 'v'},
	};
	char c;
	int getopt_ind;
	struct etcd_cdc_ctx *ctx;
	enum kv_key_op op = KV_KEY_OP_RANGE;
	char *key = "nvmet/";
	char *value = NULL;

	ctx = malloc(sizeof(struct etcd_cdc_ctx));
	if (!ctx) {
		fprintf(stderr, "cannot allocate context\n");
		exit(1);
	}
	ctx->host = "localhost";
	ctx->proto = "http";
	ctx->port = 2379;
	while ((c = getopt_long(argc, argv, "p:h:sv",
				getopt_arg, &getopt_ind)) != -1) {
		switch (c) {
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
	if (optind < argc) {
		if (!strcmp(argv[optind], "get"))
			op = KV_KEY_OP_GET;
		else if (!strcmp(argv[optind], "put"))
			op = KV_KEY_OP_ADD;
		else if (!strcmp(argv[optind], "range"))
			op = KV_KEY_OP_RANGE;
		else if (!strcmp(argv[optind], "delete"))
			op = KV_KEY_OP_DELETE;
		else {
			fprintf(stderr, "Invalid op '%s', must be either "
				"'get', 'put', 'range', or 'delete'\n",
				argv[optind]);
			return 1;
		}	
		optind++;
	}
	if (optind < argc) {
		key = argv[optind];
		optind++;
	}
	switch (op) {
	case KV_KEY_OP_GET:
		if (optind < argc) {
			fprintf(stderr, "excess arguments for 'get'\n");
			exit(1);
		}
		etcd_kv_get(ctx, key);
		break;
	case KV_KEY_OP_ADD:
		if (optind == argc) {
			fprintf(stderr, "value for 'put' is missing\n");
			return 1;
		}
		value = argv[optind];
		optind++;
		if (optind < argc) {
			fprintf(stderr, "excess arguments for 'put'\n");
			exit(1);
		}
		etcd_kv_put(ctx, key, value);
		break;
	case KV_KEY_OP_RANGE:
		if (optind < argc) {
			fprintf(stderr, "excess arguments for 'range'\n");
			exit(1);
		}
		etcd_kv_range(ctx, key);
		break;
	case KV_KEY_OP_DELETE:
		if (optind < argc) {
			fprintf(stderr, "excess arguments for 'delete'\n");
			exit(1);
		}
		etcd_kv_delete(ctx, key);
		break;
	default:
		fprintf(stderr, "Invalid OP %d\n", op);
		break;
	}
	return 0;
}
