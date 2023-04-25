
#include <json-c/json.h>
#include "nvmet_common.h"
#include "nvmet_tcp.h"

static int nvmf_discovery_genctr = 1;

static int parse_etcd_kv(char *prefix, char *hostnqn,
		struct nvmf_disc_rsp_page_entry *entry,
		char *key, const char *value)
{
	char *key_parse, *key_save, *k, *eptr;
	char *addr, *a, *addr_save;
	char *traddr = NULL, *trtype = NULL, *trsvcid = NULL;
	int traddr_len;
	unsigned char port;

	printf("Parsing key %s\n", key);
	/* key format: <prefix>/<hostnqn>/<subnqn>/<portid> */
	key_parse = strdup(key);
	k = strtok_r(key_parse, "/", &key_save);
	if (!k || !strlen(k)) {
		fprintf(stderr, "parse error (prefix) on key '%s'\n", key);
		free(key_parse);
		return -EINVAL;
	}
	if (strncmp(k, prefix, strlen(prefix))) {
		fprintf(stderr, "Skip invalid prefix '%s'\n", k);
		free(key_parse);
		return -EINVAL;
	}
	k = strtok_r(NULL, "/", &key_save);
	if (!k) {
		fprintf(stderr, "parse error (hostnqn) on key '%s'\n", key);
		free(key_parse);
		return -EINVAL;
	}
#if 0
	if (strlen(k) && strcmp(hostnqn, k)) {
		fprintf(stderr, "Skip invalid hostnqn host '%s'\n", k);
		free(key_parse);
		return -EINVAL;
	}
#endif
	k = strtok_r(NULL, "/", &key_save);
	if (!k || !strlen(k)) {
		fprintf(stderr, "parse error (subnqn) on key '%s'\n", key);
		free(key_parse);
		return -EINVAL;
	}
	memset(entry, 0, sizeof(*entry));
	strncpy(entry->subnqn, k, NVMF_NQN_FIELD_LEN);
	k = strtok_r(NULL, "/", &key_save);
	if (!k || !strlen(k)) {
		fprintf(stderr, "parse error (port) on key '%s'\n", key);
		free(key_parse);
		return -EINVAL;
	}
	port = strtoul(k, &eptr, 10);
	if (eptr == k) {
		fprintf(stderr, "Skip invalid portid '%s'\n", k);
		free(key_parse);
		return -EINVAL;
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
		return -EINVAL;
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
		return -EINVAL;
	}
	memset(entry->traddr, 0, NVMF_NQN_FIELD_LEN);
	traddr_len = strlen(traddr);
	if (traddr_len > NVMF_NQN_FIELD_LEN)
		traddr_len = NVMF_NQN_FIELD_LEN;
	memcpy(entry->traddr, traddr, traddr_len);
	if (trsvcid) {
		int trsvcid_len = strlen(trsvcid);

		if (trsvcid_len > NVMF_TRSVCID_SIZE)
			trsvcid_len = NVMF_TRSVCID_SIZE;
		memcpy(entry->trsvcid, trsvcid, trsvcid_len);
	}
	free(addr);
	return 0;
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

int nvmet_etcd_genctr(struct etcd_cdc_ctx *ctx)
{
	char key[1024];
	int ret, genctr;
	struct json_object *rev_obj;

	sprintf(key, "%s/%s/genctr",
		ctx->prefix, NVME_DISC_SUBSYS_NAME);
	ret = etcd_kv_revision(ctx, key);
	if (ret < 0) {
		fprintf(stderr, "etcd_kv_revision failed, error %d\n", ret);
		return -1;
	}
	rev_obj = json_object_object_get(ctx->resp_obj, "revision");
	if (!rev_obj) {
		fprintf(stderr, "parse error, 'revision' not found\n");
		return -1;
	}
	genctr = json_object_get_int(rev_obj);
	return genctr;
}

u8 *nvmet_etcd_disc_log(struct etcd_cdc_ctx *ctx, char *hostnqn, size_t *len)
{
	int ret, num_recs = 0, genctr;
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
	log_len = sizeof(struct nvmf_disc_rsp_page_hdr) +
		(num_recs * sizeof(entry));
	log_buf = malloc(log_len);
	memset(log_buf, 0, log_len);
	hdr = (struct nvmf_disc_rsp_page_hdr *)log_buf;
	hdr->recfmt = 1;
	genctr = nvmet_etcd_genctr(ctx);
	if (genctr < 0)
		genctr = nvmf_discovery_genctr;
	hdr->genctr = htole64(genctr);

	log_ptr = log_buf;
	log_ptr += sizeof(struct nvmf_disc_rsp_page_hdr);
	log_len = sizeof(struct nvmf_disc_rsp_page_hdr);

	num_recs = 0;
	json_object_object_foreach(ctx->resp_obj, key, val_obj) {
		if (!json_object_is_type(val_obj, json_type_string))
			continue;
		memset(&entry, 0, sizeof(entry));
		if (parse_etcd_kv(ctx->prefix, hostnqn,
				  &entry, key,
				  json_object_get_string(val_obj)) < 0)
			continue;
		num_recs++;
		memcpy(log_ptr, &entry, sizeof(entry));
		log_ptr += sizeof(entry);
		log_len += sizeof(entry);
	}

	ctx->resp_obj = NULL;
	hdr->numrec = htole64(num_recs);
	*len = log_len;
	return log_buf;
}
