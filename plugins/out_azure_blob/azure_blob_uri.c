/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>

#include "azure_blob.h"

static inline int to_encode(char c)
{
    if ((c >= 48 && c <= 57)  ||  /* 0-9 */
        (c >= 65 && c <= 90)  ||  /* A-Z */
        (c >= 97 && c <= 122) ||  /* a-z */
        (c == '?' || c == '&' || c == '-' || c == '_' || c == '.' ||
         c == '~' || c == '/')) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

flb_sds_t azb_uri_encode(const char *uri, size_t len)
{
    int i;
    flb_sds_t buf = NULL;
    flb_sds_t tmp = NULL;

    buf = flb_sds_create_size(len * 2);
    if (!buf) {
        flb_error("[uri] cannot allocate buffer for URI encoding");
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (to_encode(uri[i]) == FLB_TRUE) {
            tmp = flb_sds_printf(&buf, "%%%02X", (unsigned char) *(uri + i));
            if (!tmp) {
                flb_sds_destroy(buf);
                return NULL;
            }
            continue;
        }

        /* Direct assignment, just copy the character */
        if (buf) {
            tmp = flb_sds_cat(buf, uri + i, 1);
            if (!tmp) {
                flb_sds_destroy(buf);
                return NULL;
            }
            buf = tmp;
        }
    }

    return buf;
}

flb_sds_t azb_uri_decode(const char *uri, size_t len)
{
    int i;
    int hex_result;
    int c = 0;
    char hex[3];
    flb_sds_t out;

    out = flb_sds_create_size(len);
    if (!out) {
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (uri[i] == '%') {
            hex[0] = uri[i + 1];
            hex[1] = uri[i + 2];
            hex[2] = '\0';

            hex_result = flb_utils_hex2int(hex, 2);
            out[c++] = hex_result;
            i += 2;
        }
        else {
            out[c++] = uri[i];
        }
    }
    out[c++] = '\0';

    return out;
}

/* Azure Blob Storage container name constants */
#define AZB_CONTAINER_DEFAULT_PREFIX  'c'
#define AZB_CONTAINER_DEFAULT_NAME    "container"

/*
 * Format container name with tag substitution support
 * Supports $TAG and $TAG[n] placeholders
 */
flb_sds_t azb_format_container_name(struct flb_azure_blob *ctx, const char *tag)
{
    int i = 0;
    char *tag_token = NULL;
    char *strtok_saveptr;
    char tag_delimiters[] = ".-_";
    flb_sds_t tmp = NULL;
    flb_sds_t buf = NULL;
    flb_sds_t container_name = NULL;
    flb_sds_t tmp_container = NULL;
    flb_sds_t tmp_tag = NULL;
    flb_sds_t result = NULL;
    int j;
    char c;

    /* If container_name doesn't contain placeholders, return it as-is */
    if (!strstr(ctx->container_name, "$TAG")) {
        return flb_sds_create(ctx->container_name);
    }

    tmp_tag = flb_sds_create_len(tag, strlen(tag));
    if (!tmp_tag) {
        return NULL;
    }

    container_name = flb_sds_create_len(ctx->container_name, strlen(ctx->container_name));
    if (!container_name) {
        flb_sds_destroy(tmp_tag);
        return NULL;
    }

    /* 
     * Split the tag on delimiters 
     * Note: strtok_r modifies tmp_tag, which is why we created a copy above
     */
    tag_token = strtok_r(tmp_tag, tag_delimiters, &strtok_saveptr);

    /* Replace $TAG[n] with the appropriate tag part */
    i = 0;
    while (tag_token != NULL && i < 10) {
        buf = flb_sds_create_size(10);
        if (!buf) {
            goto error;
        }
        tmp = flb_sds_printf(&buf, "$TAG[%d]", i);
        if (!tmp) {
            goto error;
        }

        /* Replace this tag part in the container name */
        if (strstr(container_name, tmp)) {
            tmp_container = flb_sds_create_size(256);
            if (!tmp_container) {
                if (buf != tmp) {
                    flb_sds_destroy(buf);
                }
                flb_sds_destroy(tmp);
                goto error;
            }

            /* Manual string replacement */
            const char *pos = container_name;
            const char *found;
            while ((found = strstr(pos, tmp)) != NULL) {
                /* Copy everything before the match */
                tmp_container = flb_sds_cat(tmp_container, pos, found - pos);
                if (!tmp_container) {
                    if (buf != tmp) {
                        flb_sds_destroy(buf);
                    }
                    flb_sds_destroy(tmp);
                    goto error;
                }
                /* Copy the replacement */
                tmp_container = flb_sds_cat(tmp_container, tag_token, strlen(tag_token));
                if (!tmp_container) {
                    if (buf != tmp) {
                        flb_sds_destroy(buf);
                    }
                    flb_sds_destroy(tmp);
                    goto error;
                }
                /* Move past the match */
                pos = found + strlen(tmp);
            }
            /* Copy the rest */
            tmp_container = flb_sds_cat(tmp_container, pos, strlen(pos));
            if (!tmp_container) {
                if (buf != tmp) {
                    flb_sds_destroy(buf);
                }
                flb_sds_destroy(tmp);
                goto error;
            }

            flb_sds_destroy(container_name);
            container_name = tmp_container;
            tmp_container = NULL;
        }

        if (buf != tmp) {
            flb_sds_destroy(buf);
        }
        flb_sds_destroy(tmp);
        tmp = NULL;
        buf = NULL;

        tag_token = strtok_r(NULL, tag_delimiters, &strtok_saveptr);
        i++;
    }

    /* Replace $TAG with the entire tag (but not $TAG[n] patterns) */
    if (strstr(container_name, "$TAG")) {
        tmp_container = flb_sds_create_size(256);
        if (!tmp_container) {
            goto error;
        }

        const char *pos = container_name;
        const char *found;
        while ((found = strstr(pos, "$TAG")) != NULL) {
            /* Check if this is $TAG[n] pattern - if so, skip it */
            if (found[4] == '[') {
                /* This is $TAG[n], skip over it */
                tmp_container = flb_sds_cat(tmp_container, pos, (found + 4) - pos);
                if (!tmp_container) {
                    goto error;
                }
                pos = found + 4;
                continue;
            }
            
            /* Copy everything before the match */
            tmp_container = flb_sds_cat(tmp_container, pos, found - pos);
            if (!tmp_container) {
                goto error;
            }
            /* Copy the replacement */
            tmp_container = flb_sds_cat(tmp_container, tag, strlen(tag));
            if (!tmp_container) {
                goto error;
            }
            /* Move past the match */
            pos = found + 4;  /* strlen("$TAG") */
        }
        /* Copy the rest */
        tmp_container = flb_sds_cat(tmp_container, pos, strlen(pos));
        if (!tmp_container) {
            goto error;
        }

        flb_sds_destroy(container_name);
        container_name = tmp_container;
        tmp_container = NULL;
    }

    /* Sanitize container name to meet Azure requirements:
     * - Convert to lowercase
     * - Replace invalid characters with hyphens
     * - Remove consecutive hyphens
     */
    result = flb_sds_create_size(flb_sds_len(container_name) + 1);
    if (!result) {
        goto error;
    }

    j = 0;
    for (i = 0; i < flb_sds_len(container_name); i++) {
        c = container_name[i];
        
        /* Convert to lowercase */
        if (c >= 'A' && c <= 'Z') {
            c = c + ('a' - 'A');
        }
        
        /* Keep alphanumeric and hyphens, replace others with hyphen */
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
            result[j++] = c;
        }
        else if (c == '-' || c == '_' || c == '.' || c == '/') {
            /* Avoid consecutive hyphens */
            if (j == 0 || result[j-1] != '-') {
                result[j++] = '-';
            }
        }
    }
    
    /* Remove trailing hyphens */
    while (j > 0 && result[j-1] == '-') {
        j--;
    }
    
    result[j] = '\0';
    flb_sds_len_set(result, j);

    /* Ensure container name starts with alphanumeric */
    if (j > 0 && result[0] == '-') {
        result[0] = AZB_CONTAINER_DEFAULT_PREFIX;
    }

    /* Ensure minimum length of 3 */
    if (j < 3) {
        flb_sds_destroy(result);
        result = flb_sds_create(AZB_CONTAINER_DEFAULT_NAME);
    }

    /* Ensure maximum length of 63 */
    if (j > 63) {
        result[63] = '\0';
        flb_sds_len_set(result, 63);
        j = 63;
    }

    flb_sds_destroy(tmp_tag);
    flb_sds_destroy(container_name);
    return result;

error:
    if (tmp_tag) {
        flb_sds_destroy(tmp_tag);
    }
    if (container_name) {
        flb_sds_destroy(container_name);
    }
    if (buf && buf != tmp) {
        flb_sds_destroy(buf);
    }
    if (tmp) {
        flb_sds_destroy(tmp);
    }
    if (tmp_container) {
        flb_sds_destroy(tmp_container);
    }
    if (result) {
        flb_sds_destroy(result);
    }
    return NULL;
}

flb_sds_t azb_uri_container(struct flb_azure_blob *ctx)
{
    flb_sds_t uri;

    uri = flb_sds_create_size(256);
    if (!uri) {
        return NULL;
    }

    flb_sds_printf(&uri, "%s%s", ctx->base_uri, ctx->container_name);
    return uri;
}

flb_sds_t azb_uri_container_with_tag(struct flb_azure_blob *ctx, const char *tag)
{
    flb_sds_t uri;
    flb_sds_t container_name;

    container_name = azb_format_container_name(ctx, tag);
    if (!container_name) {
        return NULL;
    }

    uri = flb_sds_create_size(256);
    if (!uri) {
        flb_sds_destroy(container_name);
        return NULL;
    }

    flb_sds_printf(&uri, "%s%s", ctx->base_uri, container_name);
    flb_sds_destroy(container_name);
    return uri;
}

flb_sds_t azb_uri_ensure_or_create_container(struct flb_azure_blob *ctx)
{
    flb_sds_t uri;

    uri = azb_uri_container(ctx);
    if (!uri) {
        return NULL;
    }

    flb_sds_printf(&uri, "?restype=container");
    if (ctx->atype == AZURE_BLOB_AUTH_SAS && ctx->sas_token) {
        flb_sds_printf(&uri, "&%s", ctx->sas_token);
    }

    return uri;
}

flb_sds_t azb_uri_ensure_or_create_container_with_tag(struct flb_azure_blob *ctx, const char *tag)
{
    flb_sds_t uri;

    uri = azb_uri_container_with_tag(ctx, tag);
    if (!uri) {
        return NULL;
    }

    flb_sds_printf(&uri, "?restype=container");
    if (ctx->atype == AZURE_BLOB_AUTH_SAS && ctx->sas_token) {
        flb_sds_printf(&uri, "&%s", ctx->sas_token);
    }

    return uri;
}

flb_sds_t azb_uri_create_blob(struct flb_azure_blob *ctx, char *tag)
{
    flb_sds_t uri;

    /* Check if container name has dynamic placeholders */
    if (strstr(ctx->container_name, "$TAG")) {
        uri = azb_uri_container_with_tag(ctx, tag);
    }
    else {
        uri = azb_uri_container(ctx);
    }
    
    if (!uri) {
        return NULL;
    }

    if (ctx->path) {
        flb_sds_printf(&uri, "/%s/%s", ctx->path, tag);
    }
    else {
        flb_sds_printf(&uri, "/%s", tag);
    }

    if (ctx->atype == AZURE_BLOB_AUTH_SAS && ctx->sas_token) {
        flb_sds_printf(&uri, "?%s", ctx->sas_token);
    }

    return uri;
}

flb_sds_t azb_uri_create_blob_with_tag(struct flb_azure_blob *ctx, const char *tag, const char *blob_name)
{
    flb_sds_t uri;

    uri = azb_uri_container_with_tag(ctx, tag);
    if (!uri) {
        return NULL;
    }

    if (ctx->path) {
        flb_sds_printf(&uri, "/%s/%s", ctx->path, blob_name);
    }
    else {
        flb_sds_printf(&uri, "/%s", blob_name);
    }

    if (ctx->atype == AZURE_BLOB_AUTH_SAS && ctx->sas_token) {
        flb_sds_printf(&uri, "?%s", ctx->sas_token);
    }

    return uri;
}
