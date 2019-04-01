/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
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
#include <fluent-bit/flb_unescape.h>

#include <jsmn/jsmn.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bigquery.h"
#include "bigquery_conf.h"


struct flb_bigquery *flb_bigquery_conf_create(struct flb_output_instance *ins,
                                              struct flb_config *config)
{
    int ret;
    char *tmp;
    struct flb_bigquery *ctx;
    struct flb_gcp_oauth_credentials *creds;

    /* Allocate config context */
    ctx = flb_calloc(1, sizeof(struct flb_bigquery));
    if (!ctx) {
        flb_errno();
        return NULL;
    }
    ctx->config = config;

    creds = flb_gcp_load_credentials(ins, config);
    if (!creds) {
        flb_bigquery_conf_destroy(ctx);
        return NULL;
    }
    ctx->oauth_credentials = creds;

    /* config: 'project_id' */
    tmp = flb_output_get_property("project_id", ins);
    if (tmp) {
        ctx->project_id = flb_sds_create(tmp);
    }
    else {
        flb_error("[out_bigquery] property 'project_id' is not defined");
        flb_bigquery_conf_destroy(ctx);
        return NULL;
    }

    /* config: 'dataset_id' */
    tmp = flb_output_get_property("dataset_id", ins);
    if (tmp) {
        ctx->dataset_id = flb_sds_create(tmp);
    }
    else {
        flb_error("[out_bigquery] property 'dataset_id' is not defined");
        flb_bigquery_conf_destroy(ctx);
        return NULL;
    }
    
    /* config: 'table_id' */
    tmp = flb_output_get_property("table_id", ins);
    if (tmp) {
        ctx->table_id = flb_sds_create(tmp);
    }
    else {
        flb_error("[out_bigquery] property 'table_id' is not defined");
        flb_bigquery_conf_destroy(ctx);
        return NULL;
    }

    /* Create the target URI */
    ctx->uri = flb_sds_create_size(sizeof(FLB_BIGQUERY_RESOURCE_TEMPLATE)-7 +
                                   flb_sds_len(ctx->project_id) +
                                   flb_sds_len(ctx->dataset_id) +
                                   flb_sds_len(ctx->table_id));
    if (!ctx->uri) {
        flb_errno();
        flb_bigquery_conf_destroy(ctx);
        return NULL;
    }
    ctx->uri = flb_sds_printf(&ctx->uri, FLB_BIGQUERY_RESOURCE_TEMPLATE, ctx->project_id, ctx->dataset_id, ctx->table_id);
    flb_info("[out_bigquery] project='%s' dataset='%s' table='%s'",
             ctx->project_id, ctx->dataset_id, ctx->table_id);

    return ctx;
}

int flb_bigquery_conf_destroy(struct flb_bigquery *ctx)
{
    if (!ctx) {
        return -1;
    }

    flb_gcp_oauth_credentials_destroy(ctx->oauth_credentials);

    flb_sds_destroy(ctx->project_id);
    flb_sds_destroy(ctx->dataset_id);
    flb_sds_destroy(ctx->table_id);
    flb_sds_destroy(ctx->uri);

    flb_free(ctx);
    return 0;
}
