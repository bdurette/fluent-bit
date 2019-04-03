/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>

#include <msgpack.h>

#include "bigquery.h"
#include "bigquery_conf.h"

static int cb_bigquery_init(struct flb_output_instance *ins,
                            struct flb_config *config, void *data)
{
    char *token;
    struct flb_bigquery *ctx;

    /* Create config context */
    ctx = flb_bigquery_conf_create(ins, config);
    if (!ctx) {
        flb_error("[out_bigquery] configuration failed");
        return -1;
    }

    flb_output_set_context(ins, ctx);

    /* Create upstream context for BigQuery Streaming Inserts (no oauth2 service) */
    ctx->u = flb_upstream_create_url(config, FLB_BIGQUERY_URL_BASE, FLB_IO_TLS, &ins->tls);
    if (!ctx->u) {
        flb_error("[out_bigquery] upstream creation failed");
        return -1;
    }

    /* Retrieve oauth2 token */
    token = flb_gcp_get_access_token(ctx->oauth_credentials, FLB_BIGQUERY_SCOPE);
    if (!token) {
        flb_warn("[out_bigquery] token retrieval failed");
    }

    return 0;
}

static int bigquery_format(void *data, size_t bytes,
                           char *tag, size_t tag_len,
                           char **out_data, size_t *out_size,
                           struct flb_bigquery *ctx)
{
    int ret;
    int array_size = 0;
    size_t off = 0;
    struct flb_time tms;
    msgpack_object *obj;
    msgpack_unpacked result;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    char *json_buf;
    size_t json_size;

    /* Count number of records */
    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        array_size++;
    }
    msgpack_unpacked_destroy(&result);
    msgpack_unpacked_init(&result);

    /* Create temporal msgpack buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * Pack root map (kind & rows):
     *
     * {"kind": "bigquery#tableDataInsertAllRequest"
     *  "rows": []
     */
    msgpack_pack_map(&mp_pck, 2);

    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "kind", 4);

    msgpack_pack_str(&mp_pck, 34);
    msgpack_pack_str_body(&mp_pck, "bigquery#tableDataInsertAllRequest", 34);

    msgpack_pack_str(&mp_pck, 4);
    msgpack_pack_str_body(&mp_pck, "rows", 4);

    /* Append entries */
    msgpack_pack_array(&mp_pck, array_size);

    off = 0;
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /* Get timestamp */
        flb_time_pop_from_msgpack(&tms, &result, &obj);

        /*
         * Pack entry
         *
         * {
         *  "json": {...}
         * }
         *
         * For now, we don't support the insertId that's required for duplicate detection.
         */
        msgpack_pack_map(&mp_pck, 1);

        /* json */
        msgpack_pack_str(&mp_pck, 4);
        msgpack_pack_str_body(&mp_pck, "json", 4);
        msgpack_pack_object(&mp_pck, *obj);
    }

    /* Convert from msgpack to JSON */
    ret = flb_msgpack_raw_to_json_str(mp_sbuf.data, mp_sbuf.size,
                                      &json_buf, &json_size);
    msgpack_sbuffer_destroy(&mp_sbuf);

    if (ret != 0) {
        flb_error("[out_bigquery] error formatting JSON payload");
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    *out_data = json_buf;
    *out_size = json_size;

    return 0;
}

static void set_authorization_header(struct flb_http_client *c,
                                     char *token)
{
    int len;
    char header[512];

    len = snprintf(header, sizeof(header) - 1,
                   "Bearer %s", token);
    flb_http_add_header(c, "Authorization", 13, header, len);
}

static void cb_bigquery_flush(void *data, size_t bytes,
                              char *tag, int tag_len,
                              struct flb_input_instance *i_ins,
                              void *out_context,
                              struct flb_config *config)
{
    (void) i_ins;
    (void) config;
    int ret;
    int ret_code = FLB_RETRY;
    size_t b_sent;
    char *token;
    char *payload_buf;
    size_t payload_size;
    struct flb_bigquery *ctx = out_context;
    struct flb_upstream_conn *u_conn;
    struct flb_http_client *c;

    flb_trace("[bigquery] flushing bytes %d", bytes);
    /* Get upstream connection */
    u_conn = flb_upstream_conn_get(ctx->u);
    if (!u_conn) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Reformat msgpack to bigquery JSON payload */
    ret = bigquery_format(data, bytes, tag, tag_len,
                          &payload_buf, &payload_size, ctx);
    if (ret != 0) {
        flb_upstream_conn_release(u_conn);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Get or renew Token */
    token = flb_gcp_get_access_token(ctx->oauth_credentials, FLB_BIGQUERY_SCOPE);
    if (!token) {
        flb_error("[out_bigquery] cannot retrieve oauth2 token");
        flb_upstream_conn_release(u_conn);
        flb_free(payload_buf);
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    /* Compose HTTP Client request */
    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->uri,
                        payload_buf, payload_size, NULL, 0, NULL, 0);

    flb_http_buffer_size(c, 4192);

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/json", 20);

    /* Compose and append Authorization header */
    set_authorization_header(c, token);

    /* Send HTTP request */
    ret = flb_http_do(c, &b_sent);

    /* validate response */
    if (ret != 0) {
        flb_warn("[out_bigquery] http_do=%i", ret);
        ret_code = FLB_RETRY;
    }
    else {
        /* The request was issued successfully, validate the 'error' field */
        flb_debug("[out_bigquery] HTTP Status=%i", c->resp.status);
        if (c->resp.status == 200) {
            ret_code = FLB_OK;
        }
        else {
            if (c->resp.payload_size > 0) {
                /* we got an error */
                flb_warn("[out_bigquery] error\n%s",
                         c->resp.payload);
            }
            else {
                flb_debug("[out_bigquery] response\n%s",
                          c->resp.payload);
            }
            ret_code = FLB_RETRY;
        }
    }

    /* Cleanup */
    flb_free(payload_buf);
    flb_http_client_destroy(c);
    flb_upstream_conn_release(u_conn);

    /* Done */
    FLB_OUTPUT_RETURN(ret_code);
}

static int cb_bigquery_exit(void *data, struct flb_config *config)
{
    struct flb_bigquery *ctx = data;

    if (!ctx) {
        return -1;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    flb_bigquery_conf_destroy(ctx);
    return 0;
}

struct flb_output_plugin out_bigquery_plugin = {
    .name         = "bigquery",
    .description  = "Send events to BigQuery via streaming insert",
    .cb_init      = cb_bigquery_init,
    .cb_flush     = cb_bigquery_flush,
    .cb_exit      = cb_bigquery_exit,

    /* Plugin flags */
    .flags        = FLB_OUTPUT_NET | FLB_IO_TLS,
};
