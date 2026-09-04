/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_oauth2.h>

#include "azure_logs_ingestion.h"
#include "azure_logs_ingestion_batch.h"
#include "azure_logs_ingestion_conf.h"

static int cb_azure_logs_ingestion_init(struct flb_output_instance *ins,
                          struct flb_config *config, void *data)
{
    struct flb_az_li *ctx;
    (void) config;
    (void) ins;
    (void) data;

    /* Allocate and initialize a context from configuration */
    ctx = flb_az_li_ctx_create(ins, config);
    if (!ctx) {
        flb_plg_error(ins, "configuration failed");
        return -1;
    }

    return 0;
}

/* Gets OAuth token; (allocates sds string everytime, must deallocate) */
flb_sds_t get_az_li_token(struct flb_az_li *ctx)
{
    int ret = 0;
    char* token;
    size_t token_len;
    flb_sds_t token_return = NULL;

    if (pthread_mutex_lock(&ctx->token_mutex)) {
        flb_plg_error(ctx->ins, "error locking mutex");
        return NULL;
    }
    /* Retrieve access token only if expired */
    if (flb_oauth2_token_expired(ctx->u_auth) == FLB_TRUE) {
        flb_plg_debug(ctx->ins, "token expired. getting new token");
        /* Clear any previous oauth2 payload content */
        flb_oauth2_payload_clear(ctx->u_auth);

        ret = flb_oauth2_payload_append(ctx->u_auth, "grant_type", 10,
                                        "client_credentials", 18);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 params");
            goto token_cleanup;
        }

        ret = flb_oauth2_payload_append(ctx->u_auth, "scope", 5, FLB_AZ_LI_AUTH_SCOPE,
                                        sizeof(FLB_AZ_LI_AUTH_SCOPE) - 1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 params");
            goto token_cleanup;
        }

        ret = flb_oauth2_payload_append(ctx->u_auth, "client_id", 9,
                                        ctx->client_id, -1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 params");
            goto token_cleanup;
        }

        ret = flb_oauth2_payload_append(ctx->u_auth, "client_secret", 13,
                                        ctx->client_secret, -1);
        if (ret == -1) {
            flb_plg_error(ctx->ins, "error appending oauth2 params");
            goto token_cleanup;
        }

        token = flb_oauth2_token_get(ctx->u_auth);

        /* Copy string to prevent race conditions */
        if (!token) {
            flb_plg_error(ctx->ins, "error retrieving oauth2 access token");
            goto token_cleanup;
        }
        flb_plg_debug(ctx->ins, "got azure token");
    }

    /* Reached this code-block means, got new token or token not expired */
    /* Either way we copy the token to a new string */
    token_len = flb_sds_len(ctx->u_auth->token_type) + 2 +
                    flb_sds_len(ctx->u_auth->access_token);
    flb_plg_debug(ctx->ins, "create token header string");
    /* Now create */
    token_return = flb_sds_create_size(token_len);
    if (!token_return) {
        flb_plg_error(ctx->ins, "error creating token buffer");
        goto token_cleanup;
    }
    flb_sds_snprintf(&token_return, flb_sds_alloc(token_return), "%s %s",
                        ctx->u_auth->token_type, ctx->u_auth->access_token);

token_cleanup:
    if (pthread_mutex_unlock(&ctx->token_mutex)) {
        flb_plg_error(ctx->ins, "error unlocking mutex");
        return NULL;
    }

    return token_return;
}

static int send_payload(struct flb_az_li *ctx,
                        void *payload, size_t payload_size,
                        int compressed)
{
    int ret;
    int flush_status;
    size_t b_sent;
    flb_sds_t token = NULL;
    struct flb_connection *u_conn;
    struct flb_http_client *c = NULL;

    u_conn = flb_upstream_conn_get(ctx->u_dce);
    if (!u_conn) {
        return FLB_RETRY;
    }

    token = get_az_li_token(ctx);
    if (!token) {
        flush_status = FLB_RETRY;
        goto cleanup;
    }

    c = flb_http_client(u_conn, FLB_HTTP_POST, ctx->dce_u_url,
                        payload, payload_size, NULL, 0, NULL, 0);

    if (!c) {
        flb_plg_warn(ctx->ins, "retrying payload bytes=%lu", payload_size);
        flush_status = FLB_RETRY;
        goto cleanup;
    }

    flb_http_add_header(c, "User-Agent", 10, "Fluent-Bit", 10);
    flb_http_add_header(c, "Content-Type", 12, "application/json", 16);
    if (compressed == FLB_TRUE) {
        flb_http_add_header(c, "Content-Encoding", 16, "gzip", 4);
    }
    flb_http_add_header(c, "Authorization", 13, token, flb_sds_len(token));
    flb_http_buffer_size(c, FLB_HTTP_DATA_SIZE_MAX);

    ret = flb_http_do(c, &b_sent);
    if (ret != 0) {
        flb_plg_warn(ctx->ins, "http_do=%i", ret);
        flush_status = FLB_RETRY;
        goto cleanup;
    }
    else {
        if (c->resp.status >= 200 && c->resp.status <= 299) {
            flb_plg_info(ctx->ins, "http_status=%i, dcr_id=%s, table=%s",
                         c->resp.status, ctx->dcr_id, ctx->table_name);
            flush_status = FLB_OK;
            goto cleanup;
        }
        else {
            if (c->resp.payload_size > 0) {
                flb_plg_warn(ctx->ins, "http_status=%i:\n%s",
                             c->resp.status, c->resp.payload);
            }
            else {
                flb_plg_warn(ctx->ins, "http_status=%i", c->resp.status);
            }
            flb_plg_debug(ctx->ins, "retrying payload bytes=%lu", payload_size);
            flush_status = FLB_RETRY;
            goto cleanup;
        }
    }

cleanup:
    if (c) {
        flb_http_client_destroy(c);
    }
    if (u_conn) {
        flb_upstream_conn_release(u_conn);
    }

    /* destory token at last after HTTP call has finished */
    if (token) {
        flb_sds_destroy(token);
    }

    return flush_status;
}

static int send_batch(struct flb_az_li *ctx, struct flb_az_li_batch *batch)
{
    if (ctx->compress_enabled == FLB_TRUE) {
        return send_payload(ctx, batch->compressed_payload,
                            batch->compressed_size, FLB_TRUE);
    }

    return send_payload(ctx, batch->payload,
                        flb_sds_len(batch->payload), FLB_FALSE);
}

static int process_batches(struct flb_az_li *ctx)
{
    int ret;
    int result;
    struct flb_az_li_batch batch;

    pthread_mutex_lock(&ctx->batch_mutex);
    if (ctx->batch_processing == FLB_TRUE) {
        pthread_mutex_unlock(&ctx->batch_mutex);
        return 0;
    }
    ctx->batch_processing = FLB_TRUE;
    pthread_mutex_unlock(&ctx->batch_mutex);

    result = 0;

    while (1) {
        pthread_mutex_lock(&ctx->batch_mutex);
        ret = flb_az_li_batch_prepare(ctx, &batch);
        pthread_mutex_unlock(&ctx->batch_mutex);

        if (ret == FLB_AZ_LI_BATCH_CORRUPT_FILE) {
            continue;
        }

        if (ret <= 0) {
            if (ret == -1) {
                result = -1;
            }
            break;
        }

        ret = send_batch(ctx, &batch);
        if (ret != FLB_OK) {
            pthread_mutex_lock(&ctx->batch_mutex);
            ctx->batch_retry_pending = FLB_TRUE;
            pthread_mutex_unlock(&ctx->batch_mutex);
            flb_az_li_batch_destroy(&batch);
            result = -1;
            break;
        }

        pthread_mutex_lock(&ctx->batch_mutex);
        ret = flb_az_li_batch_commit(ctx, &batch);
        if (ret == 0) {
            ctx->batch_retry_pending = FLB_FALSE;
        }
        pthread_mutex_unlock(&ctx->batch_mutex);
        flb_az_li_batch_destroy(&batch);

        if (ret == -1) {
            flb_plg_error(ctx->ins, "could not commit the buffered batch");
            result = -1;
            break;
        }
    }

    pthread_mutex_lock(&ctx->batch_mutex);
    ctx->batch_processing = FLB_FALSE;
    pthread_mutex_unlock(&ctx->batch_mutex);

    return result;
}

static void batch_timer_callback(struct flb_config *config, void *data)
{
    struct flb_az_li *ctx = data;

    (void) config;

    process_batches(ctx);
    flb_sched_timer_cb_coro_return();
}

static int batch_timer_create(struct flb_az_li *ctx)
{
    int ret;
    struct flb_sched *scheduler;

    pthread_mutex_lock(&ctx->batch_mutex);
    if (ctx->timer_created == FLB_TRUE) {
        pthread_mutex_unlock(&ctx->batch_mutex);
        return 0;
    }

    scheduler = flb_sched_ctx_get();
    if (scheduler == NULL) {
        pthread_mutex_unlock(&ctx->batch_mutex);
        return -1;
    }

    ret = flb_sched_timer_coro_cb_create(scheduler, FLB_SCHED_TIMER_CB_PERM,
                                         1000, batch_timer_callback, ctx, NULL);
    if (ret == 0) {
        ctx->timer_created = FLB_TRUE;
    }
    pthread_mutex_unlock(&ctx->batch_mutex);

    return ret;
}

static int cb_azure_logs_ingestion_pre_run(void *data, struct flb_config *config)
{
    struct flb_az_li *ctx = data;

    (void) config;

    if (ctx->buffering_enabled == FLB_FALSE) {
        return 0;
    }

    if (batch_timer_create(ctx) == -1) {
        flb_plg_error(ctx->ins, "could not create the batch flush timer");
        return -1;
    }

    return 0;
}

static void cb_azure_logs_ingestion_flush(struct flb_event_chunk *event_chunk,
                                          struct flb_output_flush *out_flush,
                                          struct flb_input_instance *i_ins,
                                          void *out_context,
                                          struct flb_config *config)
{
    int ret;
    int compressed;
    size_t payload_size;
    void *compressed_payload;
    flb_sds_t payload;
    struct flb_az_li *ctx = out_context;

    (void) out_flush;
    (void) i_ins;
    (void) config;

    if (ctx->buffering_enabled == FLB_FALSE) {
        payload = NULL;
        compressed_payload = NULL;
        compressed = FLB_FALSE;

        ret = flb_az_li_batch_format_chunk(ctx, event_chunk->data,
                                           event_chunk->size, &payload);
        if (ret == -1) {
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
        payload_size = flb_sds_len(payload);

        if (ctx->compress_enabled == FLB_TRUE) {
            ret = flb_az_li_gzip_compress(ctx, payload, payload_size,
                                          &compressed_payload, &payload_size);
            if (ret == -1) {
                flb_plg_error(ctx->ins,
                              "cannot gzip payload, disabling compression");
            }
            else {
                compressed = FLB_TRUE;
            }
        }

        if (compressed == FLB_TRUE) {
            ret = send_payload(ctx, compressed_payload, payload_size, FLB_TRUE);
            flb_free(compressed_payload);
        }
        else {
            ret = send_payload(ctx, payload, payload_size, FLB_FALSE);
        }
        flb_sds_destroy(payload);

        FLB_OUTPUT_RETURN(ret);
    }

    if (batch_timer_create(ctx) == -1) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    pthread_mutex_lock(&ctx->batch_mutex);
    ret = flb_az_li_batch_append(ctx, event_chunk->data, event_chunk->size);
    pthread_mutex_unlock(&ctx->batch_mutex);
    if (ret == -1) {
        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    if (process_batches(ctx) == -1) {
        flb_plg_warn(ctx->ins, "buffered batches remain pending");
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_azure_logs_ingestion_exit(void *data, struct flb_config *config)
{
    struct flb_az_li *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_plg_debug(ctx->ins, "exiting logs ingestion plugin");
    flb_az_li_ctx_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "tenant_id", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, tenant_id),
     "Set the tenant ID of the AAD application"
    },
    {
     FLB_CONFIG_MAP_STR, "client_id", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, client_id),
     "Set the client/app ID of the AAD application"
    },
    {
     FLB_CONFIG_MAP_STR, "client_secret", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, client_secret),
     "Set the client secret of the AAD application"
    },
    {
     FLB_CONFIG_MAP_STR, "auth_url", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, auth_url_override),
     "[Optional] Override the OAuth2 token endpoint."
    },
    {
     FLB_CONFIG_MAP_STR, "dce_url", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, dce_url),
     "Data Collection Endpoint(DCE) URI (e.g. "
     "https://la-endpoint-q12a.eastus-1.ingest.monitor.azure.com)"
    },
    {
     FLB_CONFIG_MAP_STR, "dcr_id", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, dcr_id),
     "Data Collection Rule (DCR) immutable ID"
    },
    {
     FLB_CONFIG_MAP_STR, "table_name", (char *)NULL,
     0, FLB_TRUE, offsetof(struct flb_az_li, table_name),
     "The name of the custom log table, including '_CL' suffix"
    },
    /* optional params */
    {
     FLB_CONFIG_MAP_STR, "time_key", FLB_AZ_LI_TIME_KEY,
     0, FLB_TRUE, offsetof(struct flb_az_li, time_key),
     "[Optional] Specify the key name where the timestamp will be stored."
    },
    {
     FLB_CONFIG_MAP_BOOL, "time_generated", "false",
     0, FLB_TRUE, offsetof(struct flb_az_li, time_generated),
     "If enabled, will generate a timestamp and append it to JSON. "
     "The key name is set by the 'time_key' parameter"
    },
    {
     FLB_CONFIG_MAP_BOOL, "compress", "false",
     0, FLB_TRUE,  offsetof(struct flb_az_li, compress_enabled),
     "Enable HTTP payload compression (gzip)."
    },
    {
     FLB_CONFIG_MAP_BOOL, "buffering_enabled", "false",
     0, FLB_TRUE, offsetof(struct flb_az_li, buffering_enabled),
     "Enable request buffering and batching by size and timeout."
    },
    {
     FLB_CONFIG_MAP_SIZE, "max_batch_size", FLB_AZ_LI_MAX_BATCH_SIZE,
     0, FLB_TRUE, offsetof(struct flb_az_li, max_batch_size),
     "Set the maximum request size after optional compression."
    },
    {
     FLB_CONFIG_MAP_SIZE, "min_batch_size", FLB_AZ_LI_MIN_BATCH_SIZE,
     0, FLB_TRUE, offsetof(struct flb_az_li, min_batch_size),
     "Set the minimum request size before an unexpired batch is sent. "
     "Batch selection targets 90% of the range between the minimum and "
     "maximum sizes."
    },
    {
     FLB_CONFIG_MAP_TIME, "batch_timeout", FLB_AZ_LI_BATCH_TIMEOUT,
     0, FLB_TRUE, offsetof(struct flb_az_li, batch_timeout),
     "Set the maximum time to postpone an underfilled batch."
    },
    {
     FLB_CONFIG_MAP_STR, "store_dir", FLB_AZ_LI_STORE_DIR,
     0, FLB_TRUE, offsetof(struct flb_az_li, store_dir),
     "Set the directory used to stage pending batches."
    },
    {
     FLB_CONFIG_MAP_SIZE, "store_dir_limit_size", "0",
     0, FLB_TRUE, offsetof(struct flb_az_li, store_dir_limit_size),
     "Limit the staged batch data size (0 means unlimited)."
    },
    /* EOF */
    {0}
};

struct flb_output_plugin out_azure_logs_ingestion_plugin = {
    .name         = "azure_logs_ingestion",
    .description  = "Send logs to Log Analytics with Log Ingestion API",
    .cb_init      = cb_azure_logs_ingestion_init,
    .cb_pre_run   = cb_azure_logs_ingestion_pre_run,
    .cb_flush     = cb_azure_logs_ingestion_flush,
    .cb_exit      = cb_azure_logs_ingestion_exit,

    /* Configuration */
    .config_map     = config_map,

    /* Plugin flags */
    .event_type     = FLB_OUTPUT_LOGS,
    .flags          = FLB_OUTPUT_NET | FLB_IO_TLS | FLB_OUTPUT_SYNCHRONOUS,
};
