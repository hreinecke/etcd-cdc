
#include <json-c/json.h>
#include "nvmet_common.h"
#include "nvmet_tcp.h"

static int nvmf_discovery_genctr = 2;

static int parse_discovery_response(char *prefix, char *hostnqn,
		struct nvmf_disc_rsp_page_entry *entry,
		char *key, const char *value)
{
	char *key_parse, *key_save, *k, *eptr;
	char *addr, *a, *addr_save;
	char *traddr = NULL, *trtype = NULL, *trsvcid = NULL;
	unsigned char port;

	printf("Parsing key %s\n", key);
	/* key format: <prefix>/<hostnqn>/<subnqn>/<portid> */
	key_parse = strdup(key);
	k = strtok_r(key_parse, "/", &key_save);
	if (!k || !strlen(k)) {
		fprintf(stderr, "parse error (prefix) on key '%s'\n", key);
		free(key_parse);
		return 0;
	}
	if (strncmp(k, prefix, strlen(prefix))) {
		fprintf(stderr, "Skip invalid prefix '%s'\n", k);
		free(key_parse);
		return 0;
	}
	k = strtok_r(NULL, "/", &key_save);
	if (!k) {
		fprintf(stderr, "parse error (hostnqn) on key '%s'\n", key);
		free(key_parse);
		return 0;
	}
#if 0
	if (strlen(k) && strcmp(hostnqn, k)) {
		fprintf(stderr, "Skip invalid hostnqn host '%s'\n", k);
		free(key_parse);
		return 0;
	}
#endif
	k = strtok_r(NULL, "/", &key_save);
	if (!k || !strlen(k)) {
		fprintf(stderr, "parse error (subnqn) on key '%s'\n", key);
		free(key_parse);
		return 0;
	}
	memset(entry, 0, sizeof(*entry));
	strncpy(entry->subnqn, k, NVMF_NQN_FIELD_LEN);
	k = strtok_r(NULL, "/", &key_save);
	if (!k || !strlen(k)) {
		fprintf(stderr, "parse error (port) on key '%s'\n", key);
		free(key_parse);
		return 0;
	}
	port = strtoul(k, &eptr, 10);
	if (eptr == k) {
		fprintf(stderr, "Skip invalid portid '%s'\n", k);
		free(key_parse);
		return 0;
	}
	entry->portid = port;
	entry->cntlid = htole16(NVME_CNTLID_DYNAMIC);
	entry->asqsz = 32;
	entry->subtype = NVME_NQN_NVM;
	free(key_parse);
	printf("Parsing value %s\n", value);
	addr = strdup(value);
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
		fprintf(stderr, "invalid entry %s\n", value);
		return 0;
	}
	entry->adrfam = NVMF_ADDR_FAMILY_IP4;
	if (!strcmp(trtype, "tcp")) {
		entry->trtype = NVMF_TRTYPE_TCP;
	} else if (!strcmp(trtype, "fc")) {
		entry->trtype = NVMF_TRTYPE_FC;
	} else if (!strcmp(trtype, "rdma")) {
		entry->trtype = NVMF_TRTYPE_RDMA;
	} else if (!strcmp(trtype, "loop")) {
		entry->trtype = NVMF_TRTYPE_LOOP;
	} else {
		fprintf(stderr, "invalid trtype %s\n", trtype);
		return 0;
	}
	memcpy(entry->traddr, traddr, NVMF_NQN_FIELD_LEN);
	if (trsvcid)
		memcpy(entry->trsvcid, trsvcid, NVMF_TRSVCID_SIZE);
	free(addr);
	return 1;
}

static int calc_num_recs(struct json_object *obj)
{
	struct json_object_iterator obj_iter, obj_iter_end;
	int numrec = 0;

	obj_iter = json_object_iter_begin(obj);
	obj_iter_end = json_object_iter_end(obj);

	while (!json_object_iter_equal(&obj_iter, &obj_iter_end)) {
		numrec++;
		json_object_iter_next(&obj_iter);
	}
	return numrec;
}

u8 *nvmet_etcd_disc_log(struct etcd_cdc_ctx *ctx, char *hostnqn, int *num_rec)
{
	int ret, num_recs = 0;
	struct nvmf_disc_rsp_page_hdr *hdr;
	struct nvmf_disc_rsp_page_entry entry;
	void *log_buf;
	unsigned char *log_ptr;
	size_t log_len;

	if (!ctx->resp_obj)
		ctx->resp_obj = json_object_new_object();

	ret = etcd_kv_range(ctx, ctx->prefix);
	if (ret) {
		fprintf(stderr, "etcd_kv_range failed, error %d\n", ret);
		return NULL;
	}
	if (ctx->debug)
		printf("keylist:\n%s\n",
		       json_object_to_json_string_ext(ctx->resp_obj,
					JSON_C_TO_STRING_PRETTY));
	num_recs = calc_num_recs(ctx->resp_obj);
	printf("Found %u records\n", num_recs);
	log_len = sizeof(hdr) + (num_recs * sizeof(entry));
	log_buf = malloc(log_len);
	memset(log_buf, 0, log_len);
	hdr = (struct nvmf_disc_rsp_page_hdr *)log_buf;
	hdr->recfmt = 0;
	hdr->genctr = nvmf_discovery_genctr++;

	log_ptr = log_buf;
	log_ptr += sizeof(*hdr);

	json_object_object_foreach(ctx->resp_obj, key, val_obj) {
		if (!json_object_is_type(val_obj, json_type_string))
			continue;
		memset(&entry, 0, sizeof(entry));
		if (!parse_discovery_response(ctx->prefix, hostnqn,
					      &entry, key,
					      json_object_get_string(val_obj)))
			continue;
		num_recs++;
		memcpy(log_ptr, &entry, sizeof(entry));
		log_ptr += sizeof(entry);
	}
	ctx->resp_obj = NULL;
	hdr->numrec = num_recs;
	*num_rec = num_recs;
	return log_buf;
}
