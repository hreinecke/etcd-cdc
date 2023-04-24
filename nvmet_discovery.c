
#include <json-c/json.h>
#include "nvmet_common.h"
#include "nvmet_tcp.h"

static int nvmf_discovery_genctr = 1;

static int parse_discovery_response(char *prefix, char *hostnqn,
		struct nvmf_disc_rsp_page_entry *entry,
		char *key, const char *value)
{
	char *key_save, *k, *eptr;
	char *addr, *a, *addr_save;
	char *traddr = NULL, *trtype = NULL, *trsvcid = NULL;
	unsigned char port;

	/* key format: <prefix>/<hostnqn>/<subnqn>/<portid> */
	k = strtok_r(key, "/", &key_save);
	if (!k || !strlen(k)) {
		fprintf(stderr, "Skip invalid key '%s'\n", key);
		return 0;
	}
	if (strncmp(k, prefix, strlen(prefix))) {
		fprintf(stderr, "Skip invalid prefix '%s'\n", key);
		return 0;
	}
	k = strtok_r(NULL, "/", &key_save);
	if (!k) {
		fprintf(stderr, "Skip invalid key '%s'\n", key);
		return 0;
	}
	if (strlen(k) && strcmp(hostnqn, k)) {
		fprintf(stderr, "Skip entry for host '%s'\n", k);
		return 0;
	}
	k = strtok_r(NULL, "/", &key_save);
	if (!k || !strlen(k)) {
		fprintf(stderr, "Skip invalid key '%s'\n", key);
		return 0;
	}
	memset(entry, 0, sizeof(*entry));
	strncpy(entry->subnqn, k, NVMF_NQN_FIELD_LEN);
	k = strtok_r(NULL, "/", &key_save);
	if (!k || !strlen(k)) {
		fprintf(stderr, "Skip invalid key '%s'\n", key);
		return 0;
	}
	port = strtoul(k, &eptr, 10);
	if (eptr == k) {
		fprintf(stderr, "Skip invalid portid '%s'\n", k);
		return 0;
	}
	entry->portid = port;
	entry->cntlid = htole16(NVME_CNTLID_DYNAMIC);
	entry->asqsz = 32;
	entry->subtype = NVME_NQN_NVM;
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
		struct json_object *val_obj;

		val_obj = json_object_iter_peek_value(&obj_iter);
		if (json_object_is_type(val_obj, json_type_string))
			numrec++;
		json_object_iter_next(&obj_iter);
	}
	return numrec;
}

u8 *nvmet_etcd_disc_log(struct etcd_cdc_ctx *ctx, char *hostnqn, int *num_rec)
{
	int ret;
	struct nvmf_disc_rsp_page_hdr hdr;
	struct nvmf_disc_rsp_page_entry entry;
	unsigned char *log_buf, *log_ptr;
	size_t log_len;

	ret = etcd_kv_range(ctx, ctx->prefix);
	if (ret) {
		fprintf(stderr, "etcd_kv_range failed, error %d\n", ret);
		return NULL;
	}
	hdr.recfmt = 0;
	hdr.numrec = calc_num_recs(ctx->resp_obj);
	hdr.genctr = nvmf_discovery_genctr++;
	printf("Found %llu DLPEs", hdr.numrec);

	log_len = sizeof(hdr) + hdr.numrec * sizeof(entry);
	log_buf = malloc(log_len);
	memset(log_buf, 0, log_len);
	memcpy(log_buf, &hdr, sizeof(hdr));
	log_ptr = log_buf;
	log_ptr += sizeof(hdr);

	json_object_object_foreach(ctx->resp_obj, key, val_obj) {
		if (!json_object_is_type(val_obj, json_type_string))
			continue;
		memset(&entry, 0, sizeof(entry));
		if (!parse_discovery_response(ctx->prefix, hostnqn,
					      &entry, key,
					      json_object_get_string(val_obj)))
			continue;
		memcpy(log_ptr, &entry, sizeof(entry));
		log_ptr += sizeof(entry);
	}
	
	*num_rec = hdr.numrec;
	return log_buf;
}
