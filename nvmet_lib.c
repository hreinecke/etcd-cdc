#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <json-c/json.h>
#include "etcd_client.h"
#include "nvmet_common.h"

void set_genctr(struct etcd_cdc_ctx *ctx, int genctr)
{
	char key[1024];
	char value[1024];

	sprintf(key, "%s/%s/%s/genctr",
		ctx->prefix, NVME_DISC_SUBSYS_NAME, ctx->discovery_nqn);
	sprintf(value, "%d", genctr);

	if (etcd_kv_put(ctx, key, value, false) < 0) {
		fprintf(stderr, "cannot add key %s, error %d\n",
			key, errno);
	}
	printf("Updated key %s: %s\n", key, value);
}

void nvmet_etcd_discovery_nqn(struct etcd_cdc_ctx *ctx)
{
	char key[1024];
	struct json_object *resp;

	sprintf(key, "%s/%s", ctx->prefix,
		NVME_DISC_SUBSYS_NAME);
	resp = etcd_kv_range(ctx, key);
	if (resp) {
		struct json_object_iterator obj_iter, obj_iter_end;

		obj_iter = json_object_iter_begin(resp);
		obj_iter_end = json_object_iter_end(resp);

		while (!json_object_iter_equal(&obj_iter, &obj_iter_end)) {
			const char *_key;
			char *p;
			_key = json_object_iter_peek_name(&obj_iter);

			if (strncmp(key, _key, strlen(key))) {
				fprintf(stderr,
					"parse error (discovery_nqn), key %s\n",
					_key);
				json_object_iter_next(&obj_iter);
				continue;
			}
			p = (char *)_key + strlen(key);
			if (*p != '/') {
				fprintf(stderr,
					"parse error (discovery_nqn), key %s\n",
					_key);
				json_object_iter_next(&obj_iter);
				continue;
			}
			p++;
			if (ctx->discovery_nqn)
				free(ctx->discovery_nqn);
			ctx->discovery_nqn = strdup(p);
			p = strchr(ctx->discovery_nqn, '/');
			if (p)
				*p = '\0';
			break;
		}
		json_object_put(resp);
	}
	if (!ctx->discovery_nqn) {
		uuid_t uuid;
		char uuid_str[38];

		ctx->discovery_nqn = malloc(70);
		uuid_generate_random(uuid);
		uuid_unparse(uuid, uuid_str);
		sprintf(ctx->discovery_nqn, NVMF_UUID_FMT, uuid_str);
	}
}
