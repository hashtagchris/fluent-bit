/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <fluent-bit.h>
#include <fluent-bit/flb_http_client.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_regex.h>

#include "flb_tests_runtime.h"

struct http_client_ctx {
    struct flb_upstream *u;
    struct flb_connection *u_conn;
    struct flb_config *config;
    struct mk_event_loop *evl;
};

static struct http_client_ctx *http_client_ctx_create(int port)
{
    struct http_client_ctx *ret_ctx = NULL;
    struct mk_event_loop *evl       = NULL;

    ret_ctx = flb_calloc(1, sizeof(struct http_client_ctx));
    if (!TEST_CHECK(ret_ctx != NULL)) {
        flb_errno();
        TEST_MSG("flb_calloc(http_client_ctx) failed");
        return NULL;
    }

    evl = mk_event_loop_create(16);
    if (!TEST_CHECK(evl != NULL)) {
        TEST_MSG("mk_event_loop failed");
        flb_free(ret_ctx);
        return NULL;
    }
    ret_ctx->evl = evl;
    flb_engine_evl_init();
    flb_engine_evl_set(evl);

    ret_ctx->config = flb_config_init();
    if (!TEST_CHECK(ret_ctx->config != NULL)) {
        TEST_MSG("flb_config_init failed");
        mk_event_loop_destroy(evl);
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->u = flb_upstream_create(ret_ctx->config, "127.0.0.1", port, 0, NULL);
    if (!TEST_CHECK(ret_ctx->u != NULL)) {
        TEST_MSG("flb_upstream_create failed");
        flb_config_exit(ret_ctx->config);
        mk_event_loop_destroy(evl);
        flb_free(ret_ctx);
        return NULL;
    }

    ret_ctx->u_conn = flb_upstream_conn_get(ret_ctx->u);
    TEST_CHECK(ret_ctx->u_conn != NULL);
    ret_ctx->u_conn->upstream = ret_ctx->u;

    return ret_ctx;
}

static void http_client_ctx_destroy(struct http_client_ctx *http_ctx)
{
    if (!http_ctx) {
        return;
    }
    TEST_CHECK(flb_upstream_conn_release(http_ctx->u_conn) == 0);
    flb_upstream_destroy(http_ctx->u);
    mk_event_loop_destroy(http_ctx->evl);
    flb_config_exit(http_ctx->config);
    flb_free(http_ctx);
}

static int fetch_metrics(struct http_client_ctx *http_ctx, int port,
                         char **out_payload, size_t *out_size)
{
    struct flb_http_client *http_client;
    size_t b_sent;
    int ret;

    http_client = flb_http_client(http_ctx->u_conn,
                                  FLB_HTTP_GET,
                                  "/api/v2/metrics/prometheus",
                                  "",
                                  0,
                                  "127.0.0.1",
                                  port,
                                  NULL,
                                  0);
    TEST_ASSERT(http_client != NULL);

    ret = flb_http_do(http_client, &b_sent);
    TEST_ASSERT(ret == 0);

    if (http_client->resp.status != 200) {
        flb_http_client_destroy(http_client);
        return -1;
    }

    *out_payload = http_client->resp.payload;
    *out_size = http_client->resp.payload_size;
    /* The caller will destroy http_client after using the payload */
    flb_http_client_destroy(http_client);
    return 0;
}

static int pick_free_port()
{
    int sockfd;
    int yes = 1;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);

    /* First, try binding to port 0 to let the OS choose */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd >= 0) {
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

        if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) == 0 &&
            getsockname(sockfd, (struct sockaddr *) &addr, &addrlen) == 0) {
            int port = (int) ntohs(addr.sin_port);
            close(sockfd);
            return port;
        }
        close(sockfd);
    }

    /* Fallback: scan a small range of fixed ports */
    for (int base = 2021; base < 2100; base++) {
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            continue;
        }
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((uint16_t) base);
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(s, (struct sockaddr *) &addr, sizeof(addr)) == 0) {
            close(s);
            return base;
        }
        close(s);
    }

    return -1;
}

static void test_tail_metrics_labels()
{
    int http_port = 0;
    const char *file = "app1_env2_inst3.log";
    const char *msg  = "hello metrics\n";
    FILE *fp;
    int in_ffd;
    int ret;
    flb_ctx_t *ctx;
    struct http_client_ctx *http_ctx = NULL;
    int attempts, max_attempts = 50;

    /* Create test file with content so Tail can process it */
    fp = fopen(file, "w");
    TEST_ASSERT(fp != NULL);
    fwrite(msg, 1, strlen(msg), fp);
    fflush(fp);
    fclose(fp);

    {
        int attempt;
        char port_buf[16];
        const int max_attempts = 10;
        int started = FLB_FALSE;

        for (attempt = 0; attempt < max_attempts; attempt++) {
            http_port = pick_free_port();
            TEST_ASSERT(http_port > 0);

            ctx = flb_create();
            TEST_ASSERT(ctx != NULL);

            snprintf(port_buf, sizeof(port_buf), "%d", http_port);
            TEST_ASSERT(flb_service_set(ctx,
                                        "HTTP_Server", "On",
                                        "HTTP_Listen", "127.0.0.1",
                                        "HTTP_Port", port_buf,
                                        NULL) == 0);

            /* Tail input */
            in_ffd = flb_input(ctx, "tail", NULL);
            TEST_ASSERT(in_ffd >= 0);

            /* Set small refresh interval so removal is detected quickly */
            ret = flb_input_set(ctx, in_ffd,
                                "path", file,
                                "tag", "<app>.<env>.<instance>",
                                "tag_regex", "(?<app>[a-z0-9]+)_(?<env>[a-z0-9]+)_(?<instance>[a-z0-9]+)\\.log",
                                "tag_regex_labels", "app,env,instance",
                                "refresh_interval", "1",
                                NULL);
            TEST_ASSERT(ret == 0);

            /* Start engine */
            ret = flb_start(ctx);
            if (ret == 0) {
                started = FLB_TRUE;
                break;
            }

            flb_destroy(ctx);
        }

        TEST_ASSERT(started == FLB_TRUE);
    }

    /* Give Tail time to read and then remove the file to trigger metrics update */
    flb_time_msleep(500);
    unlink(file);

    /* Wait for a scan cycle */
    flb_time_msleep(1500);

    http_ctx = http_client_ctx_create(http_port);
    TEST_ASSERT(http_ctx != NULL);

    /* Retry loop until the metrics are available */
    for (attempts = 0; attempts < max_attempts; attempts++) {
        char *payload = NULL;
        size_t payload_size = 0;
        struct flb_regex *re_processed;
        struct flb_regex *re_abandoned;
        int ok_processed = FLB_FALSE;
        int ok_abandoned = FLB_FALSE;

        if (fetch_metrics(http_ctx, http_port, &payload, &payload_size) != 0) {
            flb_time_msleep(100);
            continue;
        }

        /* processed bytes metric with labels present */
        re_processed = flb_regex_create(
            "fluentbit_input_file_bytes_total\\{name=\"tail\\.0\",status=\"processed\",app=\"app1\",env=\"env2\",instance=\"inst3\"\\} [0-9]+"
        );
        TEST_ASSERT(re_processed != NULL);
        ok_processed = flb_regex_match(re_processed, payload, payload_size);
        flb_regex_destroy(re_processed);

        /* abandoned bytes metric (may be zero) with labels present */
        re_abandoned = flb_regex_create(
            "fluentbit_input_file_bytes_total\\{name=\"tail\\.0\",status=\"abandoned\",app=\"app1\",env=\"env2\",instance=\"inst3\"\\} [0-9]+"
        );
        TEST_ASSERT(re_abandoned != NULL);
        ok_abandoned = flb_regex_match(re_abandoned, payload, payload_size);
        flb_regex_destroy(re_abandoned);

        if (ok_processed && ok_abandoned) {
            break;
        }

        flb_time_msleep(100);
    }

    http_client_ctx_destroy(http_ctx);

    /* Stop engine and cleanup */
    flb_stop(ctx);
    flb_destroy(ctx);
}

/* Test list */
TEST_LIST = {
    {"tail_metrics_labels", test_tail_metrics_labels},
    {NULL, NULL},
};
