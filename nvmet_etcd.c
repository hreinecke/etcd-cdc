/*
 * nvmet_etcd.c
 * etcd v3 REST API implementation
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
#include <errno.h>
#include <curl/curl.h>
#include <curl/easy.h>
#include <json-c/json.h>

#include "b64/cencode.h"
#include "b64/cdecode.h"

#include "etcd_cdc.h"

static char *base64_encode(const char *str, int str_len)
{
	int encoded_size = str_len * 2;
	base64_encodestate state;
	char *encoded_str = malloc(encoded_size), *p;
	int len;

	if (!encoded_str)
		return NULL;
	base64_init_encodestate(&state);
	p = encoded_str;
	len = base64_encode_block(str, str_len, p, &state);
	p += len;
	len = base64_encode_blockend(p, &state);
	p += len;
	*p = '\0';
	p--;
	if (*p == '\n')
	    *p = '\0';
	return encoded_str;
}

static char *base64_decode(const char *encoded_str)
{
	base64_decodestate state;
	char *str = malloc(strlen(encoded_str)), *p;
	int len;

	if (!str)
		return NULL;

	base64_init_decodestate(&state);
	p = str;
	len = base64_decode_block(encoded_str, strlen(encoded_str),
				  p, &state);
	p += len;
	*p = '\0';

	return str;
}

static size_t
etcd_parse_set_response(void *ptr, size_t size, size_t nmemb, void *arg)
{
	struct json_object *etcd_resp;
	struct etcd_cdc_ctx *ctx = arg;

	etcd_resp = json_tokener_parse(ptr);
	if (!etcd_resp) {
		fprintf(stderr, "Invalid response '%s'\n", (char *)ptr);
		return 0;
	}
	if (ctx->debug)
		printf("%s\n", json_object_to_json_string_ext(etcd_resp,
							      JSON_C_TO_STRING_PRETTY));
	json_object_put(etcd_resp);
	return size * nmemb;
}

static size_t
etcd_parse_range_response (void *ptr, size_t size, size_t nmemb, void *arg)
{
	struct json_object *etcd_resp, *kvs_obj;
	int i;

	etcd_resp = json_tokener_parse(ptr);
	if (!etcd_resp) {
		fprintf(stderr, "Invalid response '%s'\n", (char *)ptr);
		return 0;
	}
	kvs_obj = json_object_object_get(etcd_resp, "kvs");
	if (!kvs_obj) {
		fprintf(stderr, "Invalid response, 'kvs' not found; resp '%s'\n",
			json_object_to_json_string(etcd_resp));
		goto out;
	}
	for (i = 0; i < json_object_array_length(kvs_obj); i++) {
		struct json_object *kv_obj, *key_obj, *value_obj;
		char *key_str, *value_str;

		kv_obj = json_object_array_get_idx(kvs_obj, i);
		key_obj = json_object_object_get(kv_obj, "key");
		if (!key_obj) {
			fprintf(stderr, "Invalid response, 'key' not found\n");
			fprintf(stderr, "kv '%s'\n", json_object_to_json_string(kv_obj));
			continue;
		}
		value_obj = json_object_object_get(kv_obj, "value");
		if (!value_obj) {
			fprintf(stderr, "Invalid response, 'value' not found\n");
			fprintf(stderr, "kv '%s'\n", json_object_to_json_string(kv_obj));
			continue;
		}
		key_str = base64_decode(json_object_get_string(key_obj));
		value_str = base64_decode(json_object_get_string(value_obj));
		printf("%s: %s\n", key_str, value_str);
		free(key_str);
		free(value_str);
	}
out:
	json_object_put(etcd_resp);
	return size * nmemb;
}

static size_t
etcd_parse_delete_response (void *ptr, size_t size, size_t nmemb, void *arg)
{
	struct etcd_cdc_ctx *ctx = arg;
	struct json_object *etcd_resp, *deleted_obj;
	int deleted = 0;

	etcd_resp = json_tokener_parse(ptr);
	if (!etcd_resp) {
		fprintf(stderr, "Invalid response '%s'\n", (char *)ptr);
		return 0;
	}
	if (ctx->debug)
		printf("%s\n", json_object_to_json_string_ext(etcd_resp,
				JSON_C_TO_STRING_PRETTY));

	deleted_obj = json_object_object_get(etcd_resp, "deleted");
	if (!deleted_obj) {
		fprintf(stderr, "delete key failed, invalid response\n");
		goto out;
	}
	deleted = json_object_get_int(deleted_obj);
	if (!deleted)
		fprintf(stderr, "delete key failed, key not deleted\n");
out:
	json_object_put(etcd_resp);
	return size * nmemb;
}

static CURL *etcd_curl_init(struct etcd_cdc_ctx *ctx)
{
	CURL *curl;
	CURLoption opt;
	CURLcode err;

        curl = curl_easy_init();
        if (!curl) {
		fprintf(stderr, "curl easy init failed\n");
		return NULL;
        }

	opt = CURLOPT_FOLLOWLOCATION;
        err = curl_easy_setopt(curl, opt, 1L);
	if (err != CURLE_OK)
		goto out_err_opt;
	opt = CURLOPT_FORBID_REUSE;
	err = curl_easy_setopt(curl, opt, 1L);
	if (err != CURLE_OK)
		goto out_err_opt;
	opt = CURLOPT_POST;
	err = curl_easy_setopt(curl, opt, 1L);
	if (err != CURLE_OK)
		goto out_err_opt;
	if (ctx->debug)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	return curl;

out_err_opt:
	fprintf(stderr, "curl setopt %d, error %d: %s\n",
		opt, err, curl_easy_strerror(err));
	curl_easy_cleanup(curl);
	return NULL;
}

int etcd_kv_put(struct etcd_cdc_ctx *ctx, char *key, char *value)
{
	char url[1024];
	CURL *curl;
	CURLcode err;
	struct json_object *post_obj = NULL;
	char *encoded_key = NULL;
	char *encoded_value = NULL;
	const char *post_data;

	curl = etcd_curl_init(ctx);
	if (!curl)
		return -1;
	sprintf(url, "%s://%s:%u/v3/kv/put",
		ctx->proto, ctx->host, ctx->port);

        err = curl_easy_setopt(curl, CURLOPT_URL, url);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt url failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}
        err = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			       etcd_parse_set_response);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt writefunction failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}
	post_obj = json_object_new_object();
	encoded_key = base64_encode(key, strlen(key));
	json_object_object_add(post_obj, "key",
			       json_object_new_string(encoded_key));
	encoded_value = base64_encode(value, strlen(value));
	json_object_object_add(post_obj, "value",
			       json_object_new_string(encoded_value));
	post_data = json_object_to_json_string(post_obj);

	err = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setop postfields failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}

	err = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(post_data));
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setop postfieldsize failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}

        err = curl_easy_perform(curl);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl perform failed, %s",
			curl_easy_strerror(err));
		errno = EIO;
	}

err_out:
	if (post_obj)
		json_object_put(post_obj);
	if (encoded_key)
		free(encoded_key);
	if (encoded_value)
		free(encoded_value);
	curl_easy_cleanup(curl);
        return err ? -1 : 0;
}

int etcd_kv_get(struct etcd_cdc_ctx *ctx, char *key)
{
	char url[1024];
	CURL *curl;
	CURLcode err;
	struct json_object *post_obj = NULL;
	char *encoded_key = NULL;
	const char *post_data;

	curl = etcd_curl_init(ctx);
	if (!curl)
		return -1;

	sprintf(url, "%s://%s:%u/v3/kv/range",
		ctx->proto, ctx->host, ctx->port);

        err = curl_easy_setopt(curl, CURLOPT_URL, url);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt url failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}
        err = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			       etcd_parse_range_response);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt writefunction failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}

	post_obj = json_object_new_object();
	encoded_key = base64_encode(key, strlen(key));
	json_object_object_add(post_obj, "key",
			       json_object_new_string(encoded_key));
	post_data = json_object_to_json_string(post_obj);
	if (ctx->debug)
		printf("POST %s\n", post_data);
	err = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setop postfields failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}

	err = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(post_data));
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setop postfieldsize failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}

	err = curl_easy_setopt(curl, CURLOPT_WRITEDATA, ctx);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt writedata failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}

        err = curl_easy_perform(curl);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl perform failed, %s",
			curl_easy_strerror(err));
		errno = EIO;
	}

err_out:
	if (post_obj)
		json_object_put(post_obj);
	if (encoded_key)
		free(encoded_key);
	curl_easy_cleanup(curl);
        return err ? -1 : 0;
}

int etcd_kv_range(struct etcd_cdc_ctx *ctx, char *key)
{
	char url[1024];
	CURL *curl;
	CURLcode err;
	struct json_object *post_obj = NULL;
	char *encoded_key = NULL;
	char *encoded_range = NULL;
	const char *post_data;

	curl = etcd_curl_init(ctx);
	if (!curl)
		return -1;

	sprintf(url, "%s://%s:%u/v3/kv/range",
		ctx->proto, ctx->host, ctx->port);

        err = curl_easy_setopt(curl, CURLOPT_URL, url);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt url failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}
        err = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			       etcd_parse_range_response);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt writefunction failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}

	post_obj = json_object_new_object();
	encoded_key = base64_encode(key, strlen(key));
	json_object_object_add(post_obj, "key",
			       json_object_new_string(encoded_key));
	encoded_range = base64_encode("\0", 1);
	json_object_object_add(post_obj, "range_end",
			       json_object_new_string(encoded_range));
	post_data = json_object_to_json_string(post_obj);
	if (ctx->debug)
		printf("POST %s\n", post_data);
	err = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setop postfields failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}

	err = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(post_data));
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setop postfieldsize failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}

        err = curl_easy_perform(curl);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl perform failed");
		errno = EIO;
	}
err_out:
	if (post_obj)
		json_object_put(post_obj);
	if (encoded_key)
		free(encoded_key);
	if (encoded_range)
		free(encoded_range);
	curl_easy_cleanup(curl);
        return err ? -1 : 0;
}

int etcd_kv_delete(struct etcd_cdc_ctx *ctx, char *key)
{
	char url[1024];
	CURL *curl;
	CURLcode err;
	struct json_object *post_obj = NULL;
	char *encoded_key = NULL;
	const char *post_data;

	sprintf(url, "%s://%s:%u/v3/kv/deleterange",
		ctx->proto, ctx->host, ctx->port);

	curl = etcd_curl_init(ctx);
	if (!curl)
		return -1;
        err = curl_easy_setopt(curl, CURLOPT_URL, url);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt url failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}
        err = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
			       etcd_parse_delete_response);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setopt writefunction failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}

	post_obj = json_object_new_object();
	encoded_key = base64_encode(key, strlen(key));
	json_object_object_add(post_obj, "key",
			       json_object_new_string(encoded_key));
	post_data = json_object_to_json_string(post_obj);
	if (ctx->debug)
		printf("POST %s\n", post_data);
	err = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setop postfields failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}

	err = curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(post_data));
	if (err != CURLE_OK) {
		fprintf(stderr, "curl setop postfieldsize failed, %s",
			curl_easy_strerror(err));
		errno = EINVAL;
		goto err_out;
	}

        err = curl_easy_perform(curl);
	if (err != CURLE_OK) {
		fprintf(stderr, "curl perform failed");
		errno = EIO;
	}
err_out:
	if (post_obj)
		json_object_put(post_obj);
	if (encoded_key)
		free(encoded_key);
	curl_easy_cleanup(curl);
        return err ? -1 : 0;
}
