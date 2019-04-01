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

#include <jsmn/jsmn.h>
#include <sys/stat.h>

#include <fluent-bit/flb_gcp.h>
#include <fluent-bit/flb_oauth2.h>

#include <mbedtls/base64.h>
#include <mbedtls/sha256.h>


static inline int key_cmp(char *str, int len, char *cmp) {
    if (strlen(cmp) != len) {
        return -1;
    }

    return strncasecmp(str, cmp, len);
}

static int flb_gcp_read_credentials_file(char *fname, struct flb_gcp_oauth_credentials *creds)
{
    int i;
    int ret;
    int key_len;
    int val_len;
    int tok_size = 32;
    char *buf;
    char *key;
    char *val;
    flb_sds_t tmp;
    struct stat st;
    jsmn_parser parser;
    jsmntok_t *t;
    jsmntok_t *tokens;

    /* Validate credentials path */
    ret = stat(fname, &st);
    if (ret == -1) {
        flb_errno();
        flb_error("[flb_gcp] cannot open credentials file: %s",
                  fname);
        return -1;
    }

    if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode)) {
        flb_error("[flb_gcp] credentials file "
                  "is not a valid file: %s", fname);
        return -1;
    }

    /* Read file content */
    buf = mk_file_to_buffer(fname);
    if (!buf) {
        flb_error("[flb_gcp] error reading credentials file: %s",
                  fname);
        return -1;
    }

    /* Parse content */
    jsmn_init(&parser);
    tokens = flb_calloc(1, sizeof(jsmntok_t) * tok_size);
    if (!tokens) {
        flb_errno();
        flb_free(buf);
        return -1;
    }

    ret = jsmn_parse(&parser, buf, st.st_size, tokens, tok_size);
    if (ret <= 0) {
        flb_error("[flb_gcp] invalid JSON credentials file: %s",
                  fname);
        flb_free(buf);
        flb_free(tokens);
        return -1;
    }

    t = &tokens[0];
    if (t->type != JSMN_OBJECT) {
        flb_error("[flb_gcp] invalid JSON map on file: %s",
                  fname);
        flb_free(buf);
        flb_free(tokens);
        return -1;
    }

    /* Parse JSON tokens */
    for (i = 1; i < ret; i++) {
        t = &tokens[i];
        if (t->type != JSMN_STRING) {
            continue;
        }

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)){
            break;
        }

        /* Key */
        key = buf + t->start;
        key_len = (t->end - t->start);

        /* Value */
        i++;
        t = &tokens[i];
        val = buf + t->start;
        val_len = (t->end - t->start);

        if (key_cmp(key, key_len, "type") == 0) {
            creds->type = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "project_id") == 0) {
            creds->project_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "private_key_id") == 0) {
            creds->private_key_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "private_key") == 0) {
            tmp = flb_sds_create_len(val, val_len);
            if (tmp) {
                /* Unescape private key */
                creds->private_key = flb_sds_create_size(flb_sds_alloc(tmp));
                flb_unescape_string(tmp, flb_sds_len(tmp),
                                    &creds->private_key);
                flb_sds_destroy(tmp);
            }
        }
        else if (key_cmp(key, key_len, "client_email") == 0) {
            creds->client_email = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "client_id") == 0) {
            creds->client_id = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "auth_uri") == 0) {
            creds->auth_uri = flb_sds_create_len(val, val_len);
        }
        else if (key_cmp(key, key_len, "token_uri") == 0) {
            creds->token_uri = flb_sds_create_len(val, val_len);
        }
    }

    flb_free(buf);
    flb_free(tokens);

    return 0;
}

struct flb_gcp_oauth_credentials *flb_gcp_load_credentials(struct flb_output_instance *ins,
                                                           struct flb_config *config)
{
    int ret;
    flb_sds_t tmp;
    char cred_path[GCP_CRED_PATH_SIZE];

    struct flb_gcp_oauth_credentials *creds = flb_calloc(1, sizeof(struct flb_gcp_oauth_credentials));
    if (!creds) {
        flb_errno();
        return NULL;
    }

    creds->config = config;

    /* Look for direct configuration. */
    tmp = flb_output_get_property("google_service_credentials", ins);
    if (tmp) {
        ret = flb_gcp_read_credentials_file(tmp, creds);
        if (ret != 0) {
            flb_gcp_oauth_credentials_destroy(creds);
            return NULL;
        }
        return creds;
    }

    /* Check environment variables. */
    /* ... as specified in fluent-bit configuration. */
    tmp = getenv("GOOGLE_SERVICE_CREDENTIALS");
    if (tmp) {
        ret = flb_gcp_read_credentials_file(tmp, creds);
        if (ret != 0) {
            flb_gcp_oauth_credentials_destroy(creds);
            return NULL;
        }
        return creds;
    }
    /* ... as specified in Google Cloud default authentication. */
    tmp = getenv("GOOGLE_APPLICATION_CREDENTIALS");
    if (tmp) {
        ret = flb_gcp_read_credentials_file(tmp, creds);
        if (ret != 0) {
            flb_gcp_oauth_credentials_destroy(creds);
            return NULL;
        }
        return creds;
    }

    /*
     * Check platform-default location: 
     *   ~/.config/gcloud/gcloud/application_default_credentials.json
     */
    tmp = getenv("HOME");
    if (tmp) {
        ret = snprintf(cred_path, GCP_CRED_PATH_SIZE, GCP_CRED_PATH_FORMAT, tmp);
        if (ret < 0) {
            flb_gcp_oauth_credentials_destroy(creds);
            return NULL;
        }
        ret = flb_gcp_read_credentials_file(cred_path, creds);
        if (ret != 0) {
            flb_gcp_oauth_credentials_destroy(creds);
            return NULL;
        }
    }


    /*
     * No credentials file has been defined, do manual lookup of the
     * client email and the private key.
     */

    /* Service Account Email */
    tmp = flb_output_get_property("service_account_email", ins);
    if (tmp) {
        creds->client_email = flb_sds_create(tmp);
    }
    else {
        tmp = getenv("SERVICE_ACCOUNT_EMAIL");
        if (tmp) {
            creds->client_email = flb_sds_create(tmp);
        }
    }

    /* Service Account Secret */
    tmp = flb_output_get_property("service_account_secret", ins);
    if (tmp) {
        creds->private_key = flb_sds_create(tmp);
    }
    else {
        tmp = getenv("SERVICE_ACCOUNT_SECRET");
        if (tmp) {
            creds->private_key = flb_sds_create(tmp);
        }
    }

    if (!creds->client_email) {
        flb_error("[auth_gcp] client_email is not defined");
        flb_gcp_oauth_credentials_destroy(creds);
        return NULL;
    }

    if (!creds->private_key) {
        flb_error("[auth_gcp] private_key is not defined");
        flb_gcp_oauth_credentials_destroy(creds);
        return NULL;
    }
}

/*
 * Base64 Encoding in JWT must:
 *
 * - remove any trailing padding '=' character
 * - replace '+' with '-'
 * - replace '/' with '_'
 *
 * ref: https://www.rfc-editor.org/rfc/rfc7515.txt Appendix C
 */
int gcp_jwt_base64_url_encode(unsigned char *out_buf, size_t out_size,
                          unsigned char *in_buf, size_t in_size,
                          size_t *olen)

{
    int i;
    size_t len;

    /* do normal base64 encoding */
    mbedtls_base64_encode(out_buf, out_size - 1,
                          &len, in_buf, in_size);

    /* Replace '+' and '/' characters */
    for (i = 0; i < len && out_buf[i] != '='; i++) {
        if (out_buf[i] == '+') {
            out_buf[i] = '-';
        }
        else if (out_buf[i] == '/') {
            out_buf[i] = '_';
        }
    }

    /* Now 'i' becomes the new length */
    *olen = i;
    return 0;
}

static int flb_gcp_oath_jwt_encode(char *payload, char *secret,
                                   char **out_signature, size_t *out_size)
{
    int ret;
    int len;
    int buf_size;
    size_t olen;
    char *buf;
    char *sigd;
    char *headers = "{\"alg\": \"RS256\", \"typ\": \"JWT\"}";
    unsigned char sha256_buf[32] = {0};
    mbedtls_sha256_context sha256_ctx;
    mbedtls_rsa_context *rsa;
    flb_sds_t out;
    mbedtls_pk_context pk_ctx;
    unsigned char sig[256] = {0};

    buf_size = (strlen(payload) + strlen(secret)) * 2;
    buf = flb_malloc(buf_size);
    if (!buf) {
        flb_errno();
        return -1;
    }

    /* Encode header */
    len = strlen(headers);
    mbedtls_base64_encode((unsigned char *) buf, buf_size - 1,
                          &olen, (unsigned char *) headers, len);

    /* Create buffer to store JWT */
    out = flb_sds_create_size(2048);
    if (!out) {
        flb_errno();
        flb_free(buf);
        return -1;
    }

    /* Append header */
    out = flb_sds_cat(out, buf, olen);
    out = flb_sds_cat(out, ".", 1);

    /* Encode Payload */
    len = strlen(payload);
    gcp_jwt_base64_url_encode((unsigned char *) buf, buf_size,
                              (unsigned char *) payload, len, &olen);

    /* Append Payload */
    out = flb_sds_cat(out, buf, olen);

    /* do sha256() of base64(header).base64(payload) */
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    mbedtls_sha256_update(&sha256_ctx, (const unsigned char *) out,
                          flb_sds_len(out));
    mbedtls_sha256_finish(&sha256_ctx, sha256_buf);

    /* In mbedTLS cert length must include the null byte */
    len = strlen(secret) + 1;

    /* Load Private Key */
    mbedtls_pk_init(&pk_ctx);
    ret = mbedtls_pk_parse_key(&pk_ctx,
                               (unsigned char *) secret, len, NULL, 0);
    if (ret != 0) {
        flb_error("[flb_gcp] error loading private key");
        flb_free(buf);
        flb_sds_destroy(out);
        return -1;
    }

    /* Create RSA context */
    rsa = mbedtls_pk_rsa(pk_ctx);
    if (!rsa) {
        flb_error("[flb_gcp] error creating RSA context");
        flb_free(buf);
        flb_sds_destroy(out);
        mbedtls_pk_free(&pk_ctx);
        return -1;
    }

    ret = mbedtls_rsa_pkcs1_sign(rsa, NULL, NULL,
                                 MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256,
                                 0, (unsigned char *) sha256_buf, sig);
    if (ret != 0) {
        flb_error("[flb_gcp] error signing SHA256");
        flb_free(buf);
        flb_sds_destroy(out);
        mbedtls_pk_free(&pk_ctx);
        return -1;
    }

    sigd = flb_malloc(2048);
    if (!sigd) {
        flb_errno();
        flb_free(buf);
        flb_sds_destroy(out);
        mbedtls_pk_free(&pk_ctx);
        return -1;
    }

    gcp_jwt_base64_url_encode((unsigned char *) sigd, 2048, sig, 256, &olen);

    out = flb_sds_cat(out, ".", 1);
    out = flb_sds_cat(out, sigd, olen);

    *out_signature = out;
    *out_size = flb_sds_len(out);

    flb_free(buf);
    flb_free(sigd);
    mbedtls_pk_free(&pk_ctx);

    return 0;
}

/* Create a new oauth2 context and get a oauth2 token */
static int flb_gcp_get_oauth2_token(struct flb_gcp_oauth_credentials *ctx)
{
    int ret;
    char *token;
    char *sig_data;
    size_t sig_size;
    time_t issued;
    time_t expires;
    char payload[1024];

    /* JWT encode for oauth2 */
    issued = time(NULL);
    expires = issued + FLB_GCP_TOKEN_REFRESH;

    snprintf(payload, sizeof(payload) - 1,
             "{\"iss\": \"%s\", \"scope\": \"%s\", "
             "\"aud\": \"%s\", \"exp\": %lu, \"iat\": %lu}",
             ctx->client_email, ctx->oauth_scope,
             FLB_GCP_AUTH_URL,
             expires, issued);

    /* Compose JWT signature */
    ret = flb_gcp_oath_jwt_encode(payload, ctx->private_key, &sig_data, &sig_size);
    if (ret != 0) {
        flb_error("[auth_gcp] JWT signature generation failed");
        return -1;
    }

    flb_debug("[auth_gcp] JWT signature:\n%s", sig_data);

    /* Create oauth2 context */
    ctx->o = flb_oauth2_create(ctx->config, FLB_GCP_AUTH_URL, 3000);
    if (!ctx->o) {
        flb_sds_destroy(sig_data);
        flb_error("[auth_gcp] cannot create oauth2 context");
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o,
                                    "grant_type", -1,
                                    "urn:ietf:params:oauth:"
                                    "grant-type:jwt-bearer", -1);
    if (ret == -1) {
        flb_error("[auth_gcp] error appending oauth2 params");
        flb_sds_destroy(sig_data);
        return -1;
    }

    ret = flb_oauth2_payload_append(ctx->o,
                                    "assertion", -1,
                                    sig_data, sig_size);
    if (ret == -1) {
        flb_error("[auth_gcp] error appending oauth2 params");
        flb_sds_destroy(sig_data);
        return -1;
    }
    flb_sds_destroy(sig_data);

    /* Retrieve access token */
    token = flb_oauth2_token_get(ctx->o);
    if (!token) {
        flb_error("[auth_gcp] error retrieving oauth2 access token");
        return -1;
    }

    return 0;
}

static char *flb_gcp_get_access_token(struct flb_gcp_oauth_credentials *ctx)
{
    flb_trace("[auth_gcp] getting google token");
    int ret = 0;

    if (!ctx->o) {
        flb_trace("[auth_gcp] acquiring new token");
        ret = flb_gcp_get_oauth2_token(ctx);
    }
    else if (flb_oauth2_token_expired(ctx->o) == FLB_TRUE) {
        flb_trace("[auth_gcp] replacing expired token");
        flb_oauth2_destroy(ctx->o);
        ret = flb_gcp_get_oauth2_token(ctx);
    }

    if (ret != 0) {
        return NULL;
    }

    return ctx->o->access_token;
}

int flb_gcp_oauth_credentials_destroy(struct flb_gcp_oauth_credentials *creds)
{
    if (!creds) {
        return -1;
    }
    flb_sds_destroy(creds->type);
    flb_sds_destroy(creds->project_id);
    flb_sds_destroy(creds->private_key_id);
    flb_sds_destroy(creds->private_key);
    flb_sds_destroy(creds->client_email);
    flb_sds_destroy(creds->client_id);
    flb_sds_destroy(creds->auth_uri);
    flb_sds_destroy(creds->token_uri);

    if (creds->o) {
        flb_oauth2_destroy(creds->o);
    }

    flb_free(creds);

    return 0;
}

