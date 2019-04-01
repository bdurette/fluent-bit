/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2019 Treasure Data Inc.
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

#ifndef FLB_GCP_H
#define FLB_GCP_H

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_sds.h>

/* refresh token every 50 minutes */
#define FLB_GCP_TOKEN_REFRESH 3000
#define FLB_GCP_AUTH_URL      "https://www.googleapis.com/oauth2/v4/token"

#define GCP_CRED_PATH_SIZE    1024
#define GCP_CRED_PATH_FORMAT  "%s/.config/gcloud/application_default_credentials.json"

struct flb_gcp_oauth_credentials {
    /* parsed GCP credentials file */
    flb_sds_t type;
    flb_sds_t project_id;
    flb_sds_t private_key_id;
    flb_sds_t private_key;
    flb_sds_t client_email;
    flb_sds_t client_id;
    flb_sds_t auth_uri;
    flb_sds_t token_uri;

    /* scope required by the owning output handler */
    flb_sds_t oauth_scope;

    /* oauth2 context */
    struct flb_oauth2 *o;

    /* Fluent Bit context */
    struct flb_config *config;
};

struct flb_gcp_oauth_credentials *flb_gcp_load_credentials(struct flb_output_instance *ins,
                                                           struct flb_config *config);
int flb_gcp_oauth_credentials_destroy(struct flb_gcp_oauth_credentials *creds);
char *flb_gcp_get_access_token(struct flb_gcp_oauth_credentials *ctx);


#endif