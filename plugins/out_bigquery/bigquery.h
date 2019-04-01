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

#ifndef FLB_OUT_BIGQUERY
#define FLB_OUT_BIGQUERY

#include <fluent-bit/flb_gcp.h>
#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>

/* BigQuery streaming inserts oauth scope */
#define FLB_BIGQUERY_SCOPE     "https://www.googleapis.com/auth/bigquery.insertdata"

#define FLB_BIGQUERY_RESOURCE_TEMPLATE  "/bigquery/v2/projects/%s/datasets/%s/tables/%s/insertAll"
#define FLB_BIGQUERY_URL_BASE           "https://www.googleapis.com"


struct flb_bigquery {
    /* oauth credentials to gcp */
    struct flb_gcp_oauth_credentials *oauth_credentials;

    /* bigquery configuration */
    flb_sds_t project_id;
    flb_sds_t dataset_id;
    flb_sds_t table_id;

    flb_sds_t uri;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;

    /* Fluent Bit context */
    struct flb_config *config;
};

#endif
