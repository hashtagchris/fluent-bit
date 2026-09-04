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

#ifndef FLB_OUT_AZURE_LOGS_INGESTION_BATCH_H
#define FLB_OUT_AZURE_LOGS_INGESTION_BATCH_H

#include "azure_logs_ingestion.h"

#define FLB_AZ_LI_BATCH_CORRUPT_FILE -2

struct flb_az_li_batch_record {
    struct flb_fstore_file *file;
    size_t end_offset;
    size_t json_end;
};

struct flb_az_li_batch {
    flb_sds_t payload;
    void *compressed_payload;
    size_t compressed_size;
    size_t measured_record_count;
    size_t measured_size;
    size_t gzip_operations;
    struct flb_az_li_batch_record *records;
    size_t record_count;
    size_t record_capacity;
};

int flb_az_li_batch_init(struct flb_az_li *ctx);
void flb_az_li_batch_destroy_context(struct flb_az_li *ctx);
int flb_az_li_gzip_compress(struct flb_az_li *ctx,
                            void *in_data, size_t in_len,
                            void **out_data, size_t *out_len);
int flb_az_li_batch_format_chunk(struct flb_az_li *ctx,
                                 const void *data, size_t size,
                                 flb_sds_t *payload);
int flb_az_li_batch_append(struct flb_az_li *ctx, const void *data, size_t size);
int flb_az_li_batch_prepare(struct flb_az_li *ctx,
                            struct flb_az_li_batch *batch);
int flb_az_li_batch_commit(struct flb_az_li *ctx,
                           struct flb_az_li_batch *batch);
void flb_az_li_batch_destroy(struct flb_az_li_batch *batch);

#endif
