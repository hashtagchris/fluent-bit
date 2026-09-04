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

#include <fluent-bit/flb_gzip.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>
#include <stdlib.h>

#include "azure_logs_ingestion_batch.h"

#define FLB_AZ_LI_BATCH_TARGET_PERCENT 90
#define FLB_AZ_LI_BATCH_PERCENT_SCALE 100
#define FLB_AZ_LI_COMPRESSION_RATIO_OLD_WEIGHT 0.75
#define FLB_AZ_LI_COMPRESSION_RATIO_NEW_WEIGHT 0.25
#define FLB_AZ_LI_STORE_META_VERSION 1

struct flb_az_li_store_meta {
    uint32_t version;
    uint32_t reserved;
    uint64_t created;
    uint64_t offset;
};

static void normalize_stream_suffix(char *out, size_t out_size, const char *in)
{
    size_t index;
    char character;

    for (index = 0; index < out_size - 1 && in[index] != '\0'; index++) {
        character = in[index];

        if ((character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z') ||
            (character >= '0' && character <= '9') ||
            character == '_' || character == '-' || character == '.') {
            out[index] = character;
        }
        else {
            out[index] = '_';
        }
    }

    out[index] = '\0';
}

static struct flb_az_li_store_meta *store_meta_get(struct flb_fstore_file *file)
{
    struct flb_az_li_store_meta *meta;

    if (file->meta_size != sizeof(struct flb_az_li_store_meta)) {
        return NULL;
    }

    meta = file->meta_buf;
    if (meta == NULL || meta->version != FLB_AZ_LI_STORE_META_VERSION) {
        return NULL;
    }

    return meta;
}

static int store_file_compare(const void *left, const void *right)
{
    const struct flb_fstore_file *left_file;
    const struct flb_fstore_file *right_file;

    left_file = *(const struct flb_fstore_file * const *) left;
    right_file = *(const struct flb_fstore_file * const *) right;

    return strcmp(left_file->name, right_file->name);
}

static int store_sort_files(struct flb_az_li *ctx)
{
    size_t index;
    size_t file_count;
    struct mk_list *head;
    struct flb_fstore_file **files;

    file_count = mk_list_size(&ctx->fs_stream->files);
    if (file_count < 2) {
        return 0;
    }

    files = flb_malloc(file_count * sizeof(struct flb_fstore_file *));
    if (files == NULL) {
        flb_errno();
        return -1;
    }

    index = 0;
    mk_list_foreach(head, &ctx->fs_stream->files) {
        files[index] = mk_list_entry(head, struct flb_fstore_file, _head);
        index++;
    }

    qsort(files, file_count, sizeof(struct flb_fstore_file *), store_file_compare);

    for (index = 0; index < file_count; index++) {
        mk_list_del(&files[index]->_head);
        mk_list_add(&files[index]->_head, &ctx->fs_stream->files);
    }

    flb_free(files);

    return 0;
}

static int store_recover(struct flb_az_li *ctx)
{
    ssize_t file_size;
    struct mk_list *head;
    struct flb_fstore_file *file;
    struct flb_az_li_store_meta *meta;

    mk_list_foreach(head, &ctx->fs_stream->files) {
        file = mk_list_entry(head, struct flb_fstore_file, _head);
        meta = store_meta_get(file);
        file_size = cio_chunk_get_content_size(file->chunk);

        if (meta == NULL || file_size < 0 || meta->offset > (size_t) file_size) {
            flb_plg_error(ctx->ins, "invalid buffered batch file '%s'", file->name);
            return -1;
        }

        ctx->buffered_size += (size_t) file_size - meta->offset;
    }

    return store_sort_files(ctx);
}

int flb_az_li_batch_init(struct flb_az_li *ctx)
{
    const char *instance_name;
    char stream_suffix[96];

    ctx->fs = flb_fstore_create(ctx->store_dir, FLB_FSTORE_FS);
    if (ctx->fs == NULL) {
        return -1;
    }

    instance_name = ctx->ins->alias ? ctx->ins->alias : ctx->ins->name;
    normalize_stream_suffix(stream_suffix, sizeof(stream_suffix), instance_name);

    ctx->fs_stream_name = flb_sds_create_size(128);
    if (ctx->fs_stream_name == NULL) {
        flb_errno();
        flb_fstore_destroy(ctx->fs);
        ctx->fs = NULL;
        return -1;
    }

    if (flb_sds_printf(&ctx->fs_stream_name, "azure_logs_ingestion_%s",
                       stream_suffix) == NULL) {
        flb_sds_destroy(ctx->fs_stream_name);
        ctx->fs_stream_name = NULL;
        flb_fstore_destroy(ctx->fs);
        ctx->fs = NULL;
        return -1;
    }

    ctx->fs_stream = flb_fstore_stream_create(ctx->fs, ctx->fs_stream_name);
    if (ctx->fs_stream == NULL) {
        flb_sds_destroy(ctx->fs_stream_name);
        ctx->fs_stream_name = NULL;
        flb_fstore_destroy(ctx->fs);
        ctx->fs = NULL;
        return -1;
    }

    if (store_recover(ctx) == -1) {
        flb_az_li_batch_destroy_context(ctx);
        return -1;
    }

    if (ctx->buffered_size > 0) {
        flb_plg_info(ctx->ins, "recovered %zu buffered bytes", ctx->buffered_size);
    }

    return 0;
}

void flb_az_li_batch_destroy_context(struct flb_az_li *ctx)
{
    if (ctx->fs_stream_name != NULL) {
        flb_sds_destroy(ctx->fs_stream_name);
        ctx->fs_stream_name = NULL;
    }

    if (ctx->fs != NULL) {
        flb_fstore_destroy(ctx->fs);
        ctx->fs = NULL;
    }

    ctx->fs_stream = NULL;
}

static flb_sds_t store_file_name(struct flb_az_li *ctx)
{
    flb_sds_t name;
    struct flb_time now;

    flb_time_get(&now);

    name = flb_sds_create_size(96);
    if (name == NULL) {
        flb_errno();
        return NULL;
    }

    if (flb_sds_printf(&name, "%" PRIu64 "-%09" PRIu64 "-%" PRIu64 ".flb",
                       (uint64_t) now.tm.tv_sec,
                       (uint64_t) now.tm.tv_nsec,
                       ctx->store_sequence++) == NULL) {
        flb_sds_destroy(name);
        return NULL;
    }

    return name;
}

int flb_az_li_batch_append(struct flb_az_li *ctx, const void *data, size_t size)
{
    int ret;
    flb_sds_t name;
    struct flb_fstore_file *file;
    struct flb_az_li_store_meta meta;

    if (ctx->store_dir_limit_size > 0 &&
        (ctx->buffered_size > ctx->store_dir_limit_size ||
         size > ctx->store_dir_limit_size - ctx->buffered_size)) {
        flb_plg_error(ctx->ins,
                      "batch buffer is full: buffered=%zu new=%zu limit=%zu",
                      ctx->buffered_size, size, ctx->store_dir_limit_size);
        return -1;
    }

    name = store_file_name(ctx);
    if (name == NULL) {
        return -1;
    }

    file = flb_fstore_file_create(ctx->fs, ctx->fs_stream, name, size);
    flb_sds_destroy(name);
    if (file == NULL) {
        return -1;
    }

    memset(&meta, 0, sizeof(meta));
    meta.version = FLB_AZ_LI_STORE_META_VERSION;
    meta.created = (uint64_t) time(NULL);

    ret = flb_fstore_file_meta_set(ctx->fs, file, &meta, sizeof(meta));
    if (ret == -1) {
        flb_fstore_file_delete(ctx->fs, file);
        return -1;
    }

    ret = flb_fstore_file_append(file, (void *) data, size);
    if (ret == -1) {
        flb_fstore_file_delete(ctx->fs, file);
        return -1;
    }

    ctx->buffered_size += size;
    ctx->buffer_generation++;
    return 0;
}

static flb_sds_t format_record(struct flb_az_li *ctx,
                               struct flb_log_event *log_event)
{
    int index;
    int length;
    size_t size;
    double timestamp;
    struct tm time_value;
    struct flb_time event_time;
    msgpack_object map;
    msgpack_sbuffer buffer;
    msgpack_packer packer;
    flb_sds_t record;
    char formatted_time[32];

    if (log_event->body == NULL || log_event->body->type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "log event body is not a map");
        return NULL;
    }

    map = *log_event->body;
    flb_time_copy(&event_time, &log_event->timestamp);
    msgpack_sbuffer_init(&buffer);
    msgpack_packer_init(&packer, &buffer, msgpack_sbuffer_write);
    msgpack_pack_map(&packer, map.via.map.size + 1);

    msgpack_pack_str(&packer, flb_sds_len(ctx->time_key));
    msgpack_pack_str_body(&packer, ctx->time_key, flb_sds_len(ctx->time_key));

    if (ctx->time_generated == FLB_TRUE) {
        gmtime_r(&event_time.tm.tv_sec, &time_value);
        size = strftime(formatted_time, sizeof(formatted_time) - 1,
                        FLB_PACK_JSON_DATE_ISO8601_FMT, &time_value);
        length = snprintf(formatted_time + size,
                          sizeof(formatted_time) - size,
                          ".%03" PRIu64 "Z",
                          (uint64_t) event_time.tm.tv_nsec / 1000000);
        if (length < 0 || (size_t) length >= sizeof(formatted_time) - size) {
            msgpack_sbuffer_destroy(&buffer);
            return NULL;
        }
        size += length;
        msgpack_pack_str(&packer, size);
        msgpack_pack_str_body(&packer, formatted_time, size);
    }
    else {
        timestamp = flb_time_to_double(&event_time);
        msgpack_pack_double(&packer, timestamp);
    }

    for (index = 0; index < map.via.map.size; index++) {
        msgpack_pack_object(&packer, map.via.map.ptr[index].key);
        msgpack_pack_object(&packer, map.via.map.ptr[index].val);
    }

    record = flb_msgpack_raw_to_json_sds(buffer.data, buffer.size,
                                         ctx->config->json_escape_unicode);
    msgpack_sbuffer_destroy(&buffer);

    return record;
}

int flb_az_li_batch_format_chunk(struct flb_az_li *ctx,
                                 const void *data, size_t size,
                                 flb_sds_t *payload)
{
    int ret;
    int decoder_result;
    int first_record;
    flb_sds_t record;
    flb_sds_t formatted_payload;
    struct flb_log_event_decoder decoder;
    struct flb_log_event log_event;

    formatted_payload = flb_sds_create_size(size);
    if (formatted_payload == NULL) {
        flb_errno();
        return -1;
    }

    ret = flb_sds_cat_safe(&formatted_payload, "[", 1);
    if (ret == -1) {
        flb_sds_destroy(formatted_payload);
        return -1;
    }

    ret = flb_log_event_decoder_init(&decoder, (char *) data, size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_sds_destroy(formatted_payload);
        return -1;
    }

    first_record = FLB_TRUE;
    while ((decoder_result = flb_log_event_decoder_next(&decoder, &log_event)) ==
           FLB_EVENT_DECODER_SUCCESS) {
        record = format_record(ctx, &log_event);
        if (record == NULL) {
            flb_log_event_decoder_destroy(&decoder);
            flb_sds_destroy(formatted_payload);
            return -1;
        }

        if (first_record == FLB_FALSE) {
            ret = flb_sds_cat_safe(&formatted_payload, ",", 1);
        }
        else {
            ret = 0;
            first_record = FLB_FALSE;
        }

        if (ret == 0) {
            ret = flb_sds_cat_safe(&formatted_payload, record, flb_sds_len(record));
        }
        flb_sds_destroy(record);

        if (ret == -1) {
            flb_log_event_decoder_destroy(&decoder);
            flb_sds_destroy(formatted_payload);
            return -1;
        }
    }

    flb_log_event_decoder_destroy(&decoder);
    if (decoder_result != FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA ||
        flb_sds_cat_safe(&formatted_payload, "]", 1) == -1) {
        flb_sds_destroy(formatted_payload);
        return -1;
    }

    *payload = formatted_payload;

    return 0;
}

static int batch_record_add(struct flb_az_li_batch *batch,
                            struct flb_fstore_file *file,
                            size_t end_offset)
{
    size_t capacity;
    struct flb_az_li_batch_record *records;

    if (batch->record_count == batch->record_capacity) {
        capacity = batch->record_capacity == 0 ? 128 : batch->record_capacity * 2;
        records = flb_realloc(batch->records,
                              capacity * sizeof(struct flb_az_li_batch_record));
        if (records == NULL) {
            flb_errno();
            return -1;
        }

        batch->records = records;
        batch->record_capacity = capacity;
    }

    batch->records[batch->record_count].file = file;
    batch->records[batch->record_count].end_offset = end_offset;
    batch->records[batch->record_count].json_end = flb_sds_len(batch->payload);
    batch->record_count++;

    return 0;
}

int flb_az_li_gzip_compress(struct flb_az_li *ctx,
                            void *in_data, size_t in_len,
                            void **out_data, size_t *out_len)
{
#ifdef FLB_HAVE_METRICS
    cmt_counter_inc(ctx->cmt_gzip_operations, cfl_time_now(), 1,
                    (char *[]) {(char *) flb_output_name(ctx->ins)});
#endif

    return flb_gzip_compress(in_data, in_len, out_data, out_len);
}

static int compress_prefix(struct flb_az_li *ctx,
                           struct flb_az_li_batch *batch, size_t record_count,
                           void **compressed_payload, size_t *compressed_size)
{
    int ret;
    size_t json_end;
    char saved_character;

    json_end = batch->records[record_count - 1].json_end;
    saved_character = batch->payload[json_end];
    batch->payload[json_end] = ']';

    ret = flb_az_li_gzip_compress(ctx, batch->payload, json_end + 1,
                                  compressed_payload, compressed_size);
    batch->payload[json_end] = saved_character;

    return ret;
}

static size_t scale_size(size_t size, size_t numerator, size_t denominator)
{
    size_t quotient;
    size_t remainder;

    quotient = size / denominator;
    remainder = size % denominator;

    return quotient * numerator + remainder * numerator / denominator;
}

static size_t batch_target_size(struct flb_az_li *ctx)
{
    size_t size_range;

    size_range = ctx->max_batch_size - ctx->min_batch_size;

    return ctx->min_batch_size +
           scale_size(size_range,
                      FLB_AZ_LI_BATCH_TARGET_PERCENT,
                      FLB_AZ_LI_BATCH_PERCENT_SCALE);
}

static void update_compression_ratio_estimate(struct flb_az_li *ctx,
                                              size_t uncompressed_size,
                                              size_t compressed_size)
{
    if (compressed_size == 0) {
        return;
    }

    ctx->compression_ratio =
        (double) uncompressed_size / (double) compressed_size;
}

static void update_average_compression_ratio(struct flb_az_li *ctx,
                                             size_t uncompressed_size,
                                             size_t compressed_size)
{
    double observed_ratio;

    if (compressed_size == 0) {
        return;
    }

    observed_ratio = (double) uncompressed_size / (double) compressed_size;
    if (ctx->average_compression_ratio == 0) {
        ctx->average_compression_ratio = observed_ratio;
    }
    else {
        ctx->average_compression_ratio =
            ctx->average_compression_ratio *
                FLB_AZ_LI_COMPRESSION_RATIO_OLD_WEIGHT +
            observed_ratio * FLB_AZ_LI_COMPRESSION_RATIO_NEW_WEIGHT;
    }

#ifdef FLB_HAVE_METRICS
    cmt_gauge_set(ctx->cmt_compression_ratio, cfl_time_now(),
                  ctx->average_compression_ratio, 1,
                  (char *[]) {(char *) flb_output_name(ctx->ins)});
#endif
}

static int measure_prefix(struct flb_az_li *ctx,
                          struct flb_az_li_batch *batch,
                          size_t record_count,
                          size_t *request_size)
{
    int ret;
    size_t json_end;
    void *compressed_payload;

    json_end = batch->records[record_count - 1].json_end;
    if (ctx->compress_enabled == FLB_FALSE) {
        *request_size = json_end + 1;
        batch->measured_record_count = record_count;
        batch->measured_size = *request_size;
        return 0;
    }

    compressed_payload = NULL;
    ret = compress_prefix(ctx, batch, record_count,
                          &compressed_payload, request_size);
    if (ret == -1) {
        return -1;
    }

    if (batch->compressed_payload != NULL) {
        flb_free(batch->compressed_payload);
    }
    batch->compressed_payload = compressed_payload;
    batch->compressed_size = *request_size;
    batch->measured_record_count = record_count;
    batch->measured_size = *request_size;
    batch->gzip_operations++;
    ctx->last_probe_generation = ctx->buffer_generation;
    ctx->last_probe_uncompressed_size = json_end + 1;

    update_compression_ratio_estimate(ctx, json_end + 1, *request_size);

    return 0;
}

static size_t project_uncompressed_size(size_t uncompressed_size,
                                       size_t compressed_size,
                                       size_t target_size)
{
    long double projected_size;

    if (compressed_size == 0) {
        return uncompressed_size;
    }

    projected_size = (long double) uncompressed_size * (long double) target_size /
                     (long double) compressed_size;
    if (projected_size >= (long double) SIZE_MAX) {
        return SIZE_MAX;
    }
    if (projected_size < 1) {
        return 1;
    }

    return (size_t) projected_size;
}

static size_t predicted_uncompressed_size(struct flb_az_li *ctx)
{
    long double predicted_size;
    size_t target_size;

    target_size = batch_target_size(ctx);
    if (ctx->compress_enabled == FLB_FALSE || ctx->compression_ratio <= 0) {
        return target_size;
    }

    predicted_size = (long double) target_size *
                     (long double) ctx->compression_ratio;
    if (predicted_size >= (long double) SIZE_MAX) {
        return SIZE_MAX;
    }
    if (predicted_size < 1) {
        return 1;
    }

    return (size_t) predicted_size;
}

static size_t record_json_size(struct flb_az_li_batch *batch,
                               size_t record_count)
{
    return batch->records[record_count - 1].json_end + 1;
}

static size_t nearest_record_count(struct flb_az_li_batch *batch,
                                  size_t target_size,
                                  size_t maximum_count)
{
    size_t low;
    size_t high;
    size_t middle;
    size_t previous_size;
    size_t current_size;

    if (maximum_count == 1 ||
        target_size <= record_json_size(batch, 1)) {
        return 1;
    }
    if (target_size >= record_json_size(batch, maximum_count)) {
        return maximum_count;
    }

    low = 1;
    high = maximum_count;
    while (low < high) {
        middle = low + (high - low) / 2;
        if (record_json_size(batch, middle) < target_size) {
            low = middle + 1;
        }
        else {
            high = middle;
        }
    }

    current_size = record_json_size(batch, low);
    previous_size = record_json_size(batch, low - 1);
    if (target_size - previous_size <= current_size - target_size) {
        return low - 1;
    }

    return low;
}

static int finalize_batch(struct flb_az_li *ctx,
                          struct flb_az_li_batch *batch,
                          size_t selected_count)
{
    int ret;
    size_t json_end;
    size_t request_size;

    if (ctx->compress_enabled == FLB_TRUE &&
        batch->measured_record_count != selected_count) {
        ret = measure_prefix(ctx, batch, selected_count, &request_size);
        if (ret == -1) {
            return -1;
        }
    }

    json_end = batch->records[selected_count - 1].json_end;
    flb_sds_len_set(batch->payload, json_end);
    batch->payload[json_end] = '\0';

    ret = flb_sds_cat_safe(&batch->payload, "]", 1);
    if (ret == -1) {
        return -1;
    }

    batch->record_count = selected_count;
    request_size = flb_sds_len(batch->payload);
    batch->measured_record_count = selected_count;
    batch->measured_size = request_size;

    if (ctx->compress_enabled == FLB_TRUE) {
        request_size = batch->compressed_size;
        batch->measured_size = request_size;
    }

    if (selected_count == 1 && request_size > ctx->max_batch_size) {
        flb_plg_warn(ctx->ins,
                     "single log record exceeds the batch target: "
                     "bytes=%zu target=%zu",
                     request_size, ctx->max_batch_size);
    }

    flb_plg_debug(ctx->ins,
                  "prepared buffered batch records=%zu bytes=%zu "
                  "gzip_operations=%zu",
                  selected_count, request_size, batch->gzip_operations);

    return 0;
}

static int finalize_oversized_batch(struct flb_az_li *ctx,
                                   struct flb_az_li_batch *batch,
                                   size_t record_count,
                                   size_t request_size)
{
    int ret;
    void *safe_payload;
    size_t high_count;
    size_t low_count;
    size_t minimum_size;
    size_t safe_count;
    size_t safe_size;
    size_t target_size;
    size_t projected_size;
    size_t selected_count;

    safe_payload = NULL;
    safe_count = 0;
    safe_size = 0;
    low_count = 0;
    high_count = record_count;
    minimum_size = ctx->min_batch_size;
    target_size = batch_target_size(ctx);

    while (1) {
        if (request_size <= ctx->max_batch_size) {
            if (request_size >= minimum_size) {
                flb_free(safe_payload);
                return finalize_batch(ctx, batch, record_count);
            }

            if (ctx->compress_enabled == FLB_TRUE) {
                flb_free(safe_payload);
                safe_payload = batch->compressed_payload;
                batch->compressed_payload = NULL;
            }
            safe_count = record_count;
            safe_size = request_size;
            low_count = record_count;
        }
        else {
            high_count = record_count;
        }

        if (high_count <= 1) {
            flb_free(safe_payload);
            return finalize_batch(ctx, batch, 1);
        }

        if (low_count + 1 >= high_count) {
            if (safe_count == 0) {
                flb_free(safe_payload);
                return finalize_batch(ctx, batch, 1);
            }

            if (ctx->compress_enabled == FLB_TRUE) {
                flb_free(batch->compressed_payload);
                batch->compressed_payload = safe_payload;
                batch->compressed_size = safe_size;
                safe_payload = NULL;
            }
            batch->measured_record_count = safe_count;
            batch->measured_size = safe_size;

            return finalize_batch(ctx, batch, safe_count);
        }

        projected_size = project_uncompressed_size(
            record_json_size(batch, record_count), request_size, target_size);
        selected_count = nearest_record_count(batch, projected_size,
                                             high_count - 1);
        if (selected_count <= low_count) {
            selected_count = low_count + 1;
        }
        if (selected_count >= high_count) {
            selected_count = high_count - 1;
        }

        ret = measure_prefix(ctx, batch, selected_count, &request_size);
        if (ret == -1) {
            flb_free(safe_payload);
            return -1;
        }
        record_count = selected_count;
    }
}

static int batch_is_expired(struct flb_az_li *ctx,
                            struct flb_az_li_batch *batch)
{
    struct flb_az_li_store_meta *meta;

    meta = store_meta_get(batch->records[0].file);
    if (meta == NULL) {
        return FLB_FALSE;
    }

    if ((uint64_t) time(NULL) >= meta->created + (uint64_t) ctx->batch_timeout) {
        return FLB_TRUE;
    }

    return FLB_FALSE;
}

static void discard_corrupt_file(struct flb_az_li *ctx,
                                struct flb_fstore_file *file,
                                size_t file_size,
                                size_t offset)
{
    size_t pending_size;

    pending_size = file_size - offset;
    if (pending_size <= ctx->buffered_size) {
        ctx->buffered_size -= pending_size;
    }
    else {
        ctx->buffered_size = 0;
    }

    flb_plg_error(ctx->ins, "discarding corrupt buffered batch file '%s'",
                  file->name);
    flb_fstore_file_delete(ctx->fs, file);
}

int flb_az_li_batch_prepare(struct flb_az_li *ctx,
                            struct flb_az_li_batch *batch)
{
    int ret;
    int decoder_result;
    int expired;
    size_t minimum_size;
    size_t target_size;
    size_t next_check;
    size_t file_size;
    size_t request_size;
    void *file_data;
    flb_sds_t record;
    struct mk_list *head;
    struct mk_list *temporary;
    struct flb_fstore_file *file;
    struct flb_az_li_store_meta *meta;
    struct flb_log_event_decoder decoder;
    struct flb_log_event log_event;

    memset(batch, 0, sizeof(struct flb_az_li_batch));
    batch->payload = flb_sds_create_size(ctx->max_batch_size + 1);
    if (batch->payload == NULL) {
        flb_errno();
        return -1;
    }

    ret = flb_sds_cat_safe(&batch->payload, "[", 1);
    if (ret == -1) {
        flb_az_li_batch_destroy(batch);
        return -1;
    }

    minimum_size = ctx->min_batch_size;
    target_size = batch_target_size(ctx);
    next_check = predicted_uncompressed_size(ctx);

    mk_list_foreach_safe(head, temporary, &ctx->fs_stream->files) {
        file = mk_list_entry(head, struct flb_fstore_file, _head);
        meta = store_meta_get(file);
        if (meta == NULL) {
            flb_plg_error(ctx->ins, "invalid buffered batch metadata in '%s'",
                          file->name);
            flb_az_li_batch_destroy(batch);
            return -1;
        }

        file_data = NULL;
        file_size = 0;
        ret = flb_fstore_file_content_copy(ctx->fs, file, &file_data, &file_size);
        if (ret == -1 || meta->offset > file_size) {
            flb_plg_error(ctx->ins, "cannot read buffered batch file '%s'",
                          file->name);
            flb_free(file_data);
            flb_az_li_batch_destroy(batch);
            return -1;
        }

        if (meta->offset == file_size) {
            flb_free(file_data);
            flb_fstore_file_delete(ctx->fs, file);
            continue;
        }

        ret = flb_log_event_decoder_init(&decoder,
                                         (char *) file_data + meta->offset,
                                         file_size - meta->offset);
        if (ret != FLB_EVENT_DECODER_SUCCESS) {
            flb_free(file_data);
            discard_corrupt_file(ctx, file, file_size, meta->offset);
            flb_az_li_batch_destroy(batch);
            return FLB_AZ_LI_BATCH_CORRUPT_FILE;
        }

        while ((decoder_result = flb_log_event_decoder_next(&decoder, &log_event)) ==
               FLB_EVENT_DECODER_SUCCESS) {
            record = format_record(ctx, &log_event);
            if (record == NULL) {
                flb_log_event_decoder_destroy(&decoder);
                flb_free(file_data);
                discard_corrupt_file(ctx, file, file_size, meta->offset);
                flb_az_li_batch_destroy(batch);
                return FLB_AZ_LI_BATCH_CORRUPT_FILE;
            }

            if (batch->record_count > 0) {
                ret = flb_sds_cat_safe(&batch->payload, ",", 1);
                if (ret == -1) {
                    flb_sds_destroy(record);
                    flb_log_event_decoder_destroy(&decoder);
                    flb_free(file_data);
                    flb_az_li_batch_destroy(batch);
                    return -1;
                }
            }

            ret = flb_sds_cat_safe(&batch->payload, record, flb_sds_len(record));
            flb_sds_destroy(record);
            if (ret == -1 ||
                batch_record_add(batch, file,
                                 meta->offset + decoder.offset) == -1) {
                flb_log_event_decoder_destroy(&decoder);
                flb_free(file_data);
                flb_az_li_batch_destroy(batch);
                return -1;
            }

            if (flb_sds_len(batch->payload) >= next_check) {
                ret = measure_prefix(ctx, batch, batch->record_count, &request_size);
                if (ret == -1) {
                    flb_log_event_decoder_destroy(&decoder);
                    flb_free(file_data);
                    flb_az_li_batch_destroy(batch);
                    return -1;
                }

                if (request_size > ctx->max_batch_size) {
                    flb_log_event_decoder_destroy(&decoder);
                    flb_free(file_data);
                    ret = finalize_oversized_batch(ctx, batch,
                                                   batch->record_count,
                                                   request_size);
                    if (ret == -1) {
                        flb_az_li_batch_destroy(batch);
                        return -1;
                    }
                    return 1;
                }

                if (request_size >= minimum_size) {
                    flb_log_event_decoder_destroy(&decoder);
                    flb_free(file_data);
                    if (finalize_batch(ctx, batch, batch->record_count) == -1) {
                        flb_az_li_batch_destroy(batch);
                        return -1;
                    }
                    return 1;
                }

                next_check = project_uncompressed_size(
                    record_json_size(batch, batch->record_count),
                    request_size, target_size);
                if (next_check <= flb_sds_len(batch->payload)) {
                    next_check = flb_sds_len(batch->payload) + 1;
                }
            }
        }

        flb_log_event_decoder_destroy(&decoder);
        flb_free(file_data);

        if (decoder_result != FLB_EVENT_DECODER_ERROR_INSUFFICIENT_DATA) {
            flb_plg_error(ctx->ins, "invalid log data in buffered batch file '%s'",
                          file->name);
            discard_corrupt_file(ctx, file, file_size, meta->offset);
            flb_az_li_batch_destroy(batch);
            return FLB_AZ_LI_BATCH_CORRUPT_FILE;
        }

        if (batch->record_count == 0) {
            ctx->buffered_size -= file_size - meta->offset;
            flb_fstore_file_delete(ctx->fs, file);
        }
    }

    if (batch->record_count == 0) {
        flb_az_li_batch_destroy(batch);
        return 0;
    }

    expired = batch_is_expired(ctx, batch);
    if (batch->measured_record_count != batch->record_count &&
        (expired == FLB_TRUE ||
         ctx->batch_retry_pending == FLB_TRUE ||
         (ctx->compress_enabled == FLB_TRUE &&
          flb_sds_len(batch->payload) >= minimum_size &&
          (ctx->last_probe_generation != ctx->buffer_generation ||
           flb_sds_len(batch->payload) >
               ctx->last_probe_uncompressed_size)))) {
        ret = measure_prefix(ctx, batch, batch->record_count, &request_size);
        if (ret == -1) {
            flb_az_li_batch_destroy(batch);
            return -1;
        }
    }
    else if (batch->measured_record_count == batch->record_count) {
        request_size = batch->measured_size;
    }
    else {
        flb_az_li_batch_destroy(batch);
        return 0;
    }

    if (request_size > ctx->max_batch_size) {
        ret = finalize_oversized_batch(ctx, batch, batch->record_count,
                                       request_size);
    }
    else if (request_size >= minimum_size || expired == FLB_TRUE) {
        ret = finalize_batch(ctx, batch, batch->record_count);
    }
    else {
        flb_az_li_batch_destroy(batch);
        return 0;
    }
    if (ret == -1) {
        flb_az_li_batch_destroy(batch);
        return -1;
    }

    return 1;
}

int flb_az_li_batch_commit(struct flb_az_li *ctx,
                           struct flb_az_li_batch *batch)
{
    int ret;
    size_t index;
    size_t last_index;
    size_t file_size;
    size_t previous_offset;
    struct flb_fstore_file *file;
    struct flb_az_li_store_meta meta;
    struct flb_az_li_store_meta *stored_meta;

    index = 0;

    while (index < batch->record_count) {
        file = batch->records[index].file;
        last_index = index;

        while (last_index + 1 < batch->record_count &&
               batch->records[last_index + 1].file == file) {
            last_index++;
        }

        stored_meta = store_meta_get(file);
        if (stored_meta == NULL) {
            return -1;
        }

        meta = *stored_meta;
        previous_offset = meta.offset;
        meta.offset = batch->records[last_index].end_offset;

        ret = flb_fstore_file_meta_set(ctx->fs, file, &meta, sizeof(meta));
        if (ret == -1) {
            return -1;
        }

        if (meta.offset >= previous_offset &&
            meta.offset - previous_offset <= ctx->buffered_size) {
            ctx->buffered_size -= meta.offset - previous_offset;
        }
        else {
            ctx->buffered_size = 0;
        }

        file_size = cio_chunk_get_content_size(file->chunk);
        if (meta.offset >= file_size) {
            flb_fstore_file_delete(ctx->fs, file);
        }

        index = last_index + 1;
    }

    if (ctx->compress_enabled == FLB_TRUE) {
        update_average_compression_ratio(ctx, flb_sds_len(batch->payload),
                                         batch->compressed_size);
    }
    ctx->buffer_generation++;

    return 0;
}

void flb_az_li_batch_destroy(struct flb_az_li_batch *batch)
{
    if (batch->payload != NULL) {
        flb_sds_destroy(batch->payload);
    }

    if (batch->compressed_payload != NULL) {
        flb_free(batch->compressed_payload);
    }

    if (batch->records != NULL) {
        flb_free(batch->records);
    }

    memset(batch, 0, sizeof(struct flb_az_li_batch));
}
