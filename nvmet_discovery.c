
#include <json-c/json.h>
#include "nvmet_common.h"
#include "nvmet_tcp.h"

static int nvmf_discovery_genctr = 1;

static int parse_etcd_kv(char *prefix, char *hostnqn,
		struct nvmf_disc_rsp_page_entry *entry,
		const char *key, const char *value)
{
	char *key_parse, *key_save, *k, *eptr;
	char *addr, *a, *addr_save;
	char *traddr = NULL, *trtype = NULL, *trsvcid = NULL, *adrfam;
	int traddr_len;
	int subtype = NVME_NQN_NVM;
	unsigned char port;

	if (hostnqn && !strcmp(hostnqn, NVME_DISC_SUBSYS_NAME))
		subtype = NVME_NQN_CUR;
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
	if (!hostnqn) {
		if (strlen(k)) {
			fprintf(stderr, "Skip invalid hostnqn host '%s'\n", k);
			free(key_parse);
			return -EINVAL;
		}
	} else if (strcmp(hostnqn, k)) {
		fprintf(stderr, "Skip invalid hostnqn host '%s'\n", k);
		free(key_parse);
		return -EINVAL;
	}

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
	/* skip genctr */
	if (!strcmp(k, "genctr")) {
		fprintf(stderr, "Skip genctr\n");
		free(key_parse);
		return -EINVAL;
	}
	port = strtoul(k, &eptr, 10);
	if (eptr != k)
		entry->portid = port;

	entry->cntlid = htole16(NVME_CNTLID_DYNAMIC);
	entry->asqsz = 32;
	entry->subtype = subtype;
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
		else if (!strncmp(a, "adrfam=", 7))
			adrfam = a + 7;
		a = strtok_r(NULL, ",", &addr_save);
	}
	if (!trtype || !traddr) {
		fprintf(stderr, "invalid entry %s\n", value);
		free(addr);
		return -EINVAL;
	}
	entry->adrfam = NVMF_ADDR_FAMILY_IP4;
	if (adrfam) {
		if (!strcmp(adrfam, "ipv4")) {
			entry->adrfam = NVMF_ADDR_FAMILY_IP4;
		} else if (!strcmp(adrfam, "ipv6")) {
			entry->adrfam = NVMF_ADDR_FAMILY_IP6;
		} else if (!strcmp(adrfam, "fc")) {
			entry->adrfam = NVMF_ADDR_FAMILY_FC;
		} else if (!strcmp(adrfam, "ib")) {
			entry->adrfam = NVMF_ADDR_FAMILY_IB;
		}
	}
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
		free(addr);
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

void *disc_log_entries(struct etcd_cdc_ctx *ctx, char *hostnqn,
		       int port_id_offset, int *num_recs)
{
	char prefix[256];
	struct nvmf_disc_rsp_page_entry entry;
	struct json_object *resp;
	struct json_object_iterator obj_iter, obj_iter_end;
	void *log_buf;
	u8 *log_ptr;
	size_t log_len;
	int entries = 0;

	sprintf(prefix, "%s/", ctx->prefix);
	if (hostnqn)
		strcat(prefix, hostnqn);
	strcat(prefix, "/");
	resp = etcd_kv_range(ctx, prefix);
	if (!resp) {
		fprintf(stderr, "etcd_kv_range failed, error %d\n", errno);
		return NULL;
	}
	if (ctx->debug)
		printf("keylist:\n%s\n",
		       json_object_to_json_string_ext(resp,
					JSON_C_TO_STRING_PRETTY));
	entries = calc_num_recs(resp);
	printf("Found %u records\n", entries);
	log_len = entries * sizeof(entry);
	log_buf = malloc(log_len);
	memset(log_buf, 0, log_len);
	log_ptr = log_buf;
	entries = 0;

	obj_iter = json_object_iter_begin(resp);
	obj_iter_end = json_object_iter_end(resp);

	while (!json_object_iter_equal(&obj_iter, &obj_iter_end)) {
		const char *key;
		struct json_object *val_obj;

		key = json_object_iter_peek_name(&obj_iter);
		val_obj = json_object_iter_peek_value(&obj_iter);
		if (!json_object_is_type(val_obj, json_type_string)) {
			json_object_iter_next(&obj_iter);
			continue;
		}
		memset(&entry, 0, sizeof(entry));
		if (parse_etcd_kv(ctx->prefix, hostnqn,
				  &entry, key,
				  json_object_get_string(val_obj)) < 0) {
			json_object_iter_next(&obj_iter);
			continue;
		}
		entry.portid = entries + port_id_offset;
		entries++;
		memcpy(log_ptr, &entry, sizeof(entry));
		log_ptr += sizeof(entry);
		json_object_iter_next(&obj_iter);
	}
	json_object_put(resp);

	*num_recs = entries;
	return log_buf;
}

u8 *nvmet_etcd_disc_log(struct etcd_cdc_ctx *ctx, char *hostnqn, size_t *len)
{
	int genctr;
	int num_host_entries = 0, num_wildcard_entries = 0, num_discovery_entries = 0, num_recs;
	struct nvmf_disc_rsp_page_hdr *hdr;
	struct nvmf_disc_rsp_page_entry entry;
	void *host_entries, *wildcard_entries, *discovery_entries, *log_buf;
	unsigned char *log_ptr;
	size_t log_len, entry_len;

	num_recs = 0;
	host_entries = disc_log_entries(ctx, hostnqn, num_recs,
					&num_host_entries);
	if (host_entries) {
		printf("Found %u host records\n", num_host_entries);
		num_recs += num_host_entries;
	}
	wildcard_entries = disc_log_entries(ctx, NULL, num_recs,
					    &num_wildcard_entries);
	if (wildcard_entries) {
		printf("Found %u wildcard records\n", num_wildcard_entries);
		num_recs += num_wildcard_entries;
	}
	discovery_entries = disc_log_entries(ctx, NVME_DISC_SUBSYS_NAME,
					     num_recs,
					     &num_discovery_entries);
	if (discovery_entries) {
		printf("Found %u discovery records\n", num_discovery_entries);
		num_recs += num_discovery_entries;
	}
	log_len = sizeof(struct nvmf_disc_rsp_page_hdr) +
		(num_recs * sizeof(entry));
	log_buf = malloc(log_len);
	memset(log_buf, 0, log_len);
	hdr = (struct nvmf_disc_rsp_page_hdr *)log_buf;
	hdr->recfmt = 1;
	genctr = nvmet_etcd_get_genctr(ctx);
	if (genctr < 0)
		genctr = nvmf_discovery_genctr;
	hdr->genctr = htole64(genctr);
	hdr->numrec = htole64(num_recs);

	log_ptr = log_buf;
	log_ptr += sizeof(struct nvmf_disc_rsp_page_hdr);

	if (host_entries) {
		entry_len = sizeof(entry) * num_host_entries;
		memcpy(log_ptr, host_entries, entry_len);
		log_ptr += entry_len;
		free(host_entries);
	}
	if (wildcard_entries) {
		entry_len = sizeof(entry) * num_wildcard_entries;
		memcpy(log_ptr, wildcard_entries, entry_len);
		log_ptr += entry_len;
		free(wildcard_entries);
	}
	if (discovery_entries) {
		entry_len = sizeof(entry) * num_discovery_entries;
		memcpy(log_ptr, discovery_entries, entry_len);
		log_ptr += entry_len;
		free(discovery_entries);
	}
	*len = log_len;
	return log_buf;
}
