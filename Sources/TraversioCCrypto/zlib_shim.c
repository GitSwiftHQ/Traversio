/*
 * Copyright (c) 2026 GitSwift LLC
 *
 * Licensed under the GNU Affero General Public License v3.0 or later.
 * See LICENSE for details.
 */

#include "TraversioCCrypto.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

struct traversio_zlib_compressor_ctx {
    z_stream stream;
};

struct traversio_zlib_decompressor_ctx {
    z_stream stream;
};

static int
traversio_zlib_is_invalid_buffer_args(
    const uint8_t *input,
    size_t input_length,
    size_t *output_length
) {
    if (output_length == NULL) {
        return 1;
    }

    if (input_length > 0 && input == NULL) {
        return 1;
    }

    return 0;
}

static uint8_t *
traversio_zlib_grow_buffer(
    uint8_t *buffer,
    size_t minimum_capacity,
    size_t *capacity
)
{
    size_t new_capacity = *capacity == 0 ? 256 : *capacity;

    while (new_capacity < minimum_capacity) {
        new_capacity *= 2;
    }

    uint8_t *resized = realloc(buffer, new_capacity);
    if (resized == NULL) {
        free(buffer);
        return NULL;
    }

    *capacity = new_capacity;
    return resized;
}

traversio_zlib_compressor_ctx *
traversio_zlib_compressor_new(void)
{
    traversio_zlib_compressor_ctx *ctx = calloc(1, sizeof(*ctx));

    if (ctx == NULL) {
        return NULL;
    }

    if (deflateInit(&ctx->stream, Z_DEFAULT_COMPRESSION) != Z_OK) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

void
traversio_zlib_compressor_free(traversio_zlib_compressor_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    deflateEnd(&ctx->stream);
    free(ctx);
}

int
traversio_zlib_compress(
    traversio_zlib_compressor_ctx *ctx,
    const uint8_t *input,
    size_t input_length,
    uint8_t **output,
    size_t *output_length
)
{
    int status = Z_OK;
    size_t capacity = 0;
    size_t used = 0;
    uint8_t *buffer;

    if (ctx == NULL || traversio_zlib_is_invalid_buffer_args(
        input,
        input_length,
        output_length
    ) || output == NULL) {
        return TRAVERSIO_ZLIB_ERROR_INVALID_ARGUMENT;
    }

    buffer = traversio_zlib_grow_buffer(
        NULL,
        deflateBound(&ctx->stream, (uLong)input_length) + 16,
        &capacity
    );
    if (buffer == NULL) {
        return TRAVERSIO_ZLIB_ERROR_INTERNAL;
    }

    ctx->stream.next_in = (Bytef *)(uintptr_t)input;
    ctx->stream.avail_in = (uInt)input_length;

    while (1) {
        if (used == capacity) {
            buffer = traversio_zlib_grow_buffer(buffer, capacity + 1, &capacity);
            if (buffer == NULL) {
                return TRAVERSIO_ZLIB_ERROR_INTERNAL;
            }
        }

        ctx->stream.next_out = buffer + used;
        ctx->stream.avail_out = (uInt)(capacity - used);
        status = deflate(&ctx->stream, Z_SYNC_FLUSH);
        used = capacity - ctx->stream.avail_out;

        if (status != Z_OK && status != Z_BUF_ERROR) {
            free(buffer);
            return TRAVERSIO_ZLIB_ERROR_INTERNAL;
        }

        if (ctx->stream.avail_in == 0
            && ctx->stream.avail_out > 0
            && (status == Z_OK || status == Z_BUF_ERROR)) {
            *output = buffer;
            *output_length = used;
            return TRAVERSIO_ZLIB_SUCCESS;
        }

        if (ctx->stream.avail_out > 0) {
            buffer = traversio_zlib_grow_buffer(buffer, capacity + 1, &capacity);
            if (buffer == NULL) {
                return TRAVERSIO_ZLIB_ERROR_INTERNAL;
            }
        }
    }
}

traversio_zlib_decompressor_ctx *
traversio_zlib_decompressor_new(void)
{
    traversio_zlib_decompressor_ctx *ctx = calloc(1, sizeof(*ctx));

    if (ctx == NULL) {
        return NULL;
    }

    if (inflateInit(&ctx->stream) != Z_OK) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

void
traversio_zlib_decompressor_free(traversio_zlib_decompressor_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    inflateEnd(&ctx->stream);
    free(ctx);
}

int
traversio_zlib_decompress(
    traversio_zlib_decompressor_ctx *ctx,
    const uint8_t *input,
    size_t input_length,
    uint8_t **output,
    size_t *output_length
)
{
    int status = Z_OK;
    size_t capacity = 0;
    size_t used = 0;
    uint8_t *buffer;

    if (ctx == NULL || traversio_zlib_is_invalid_buffer_args(
        input,
        input_length,
        output_length
    ) || output == NULL) {
        return TRAVERSIO_ZLIB_ERROR_INVALID_ARGUMENT;
    }

    buffer = traversio_zlib_grow_buffer(
        NULL,
        input_length == 0 ? 256 : input_length * 4,
        &capacity
    );
    if (buffer == NULL) {
        return TRAVERSIO_ZLIB_ERROR_INTERNAL;
    }

    ctx->stream.next_in = (Bytef *)(uintptr_t)input;
    ctx->stream.avail_in = (uInt)input_length;

    while (1) {
        if (used == capacity) {
            buffer = traversio_zlib_grow_buffer(buffer, capacity + 1, &capacity);
            if (buffer == NULL) {
                return TRAVERSIO_ZLIB_ERROR_INTERNAL;
            }
        }

        ctx->stream.next_out = buffer + used;
        ctx->stream.avail_out = (uInt)(capacity - used);
        status = inflate(&ctx->stream, Z_SYNC_FLUSH);
        used = capacity - ctx->stream.avail_out;

        if (status == Z_DATA_ERROR) {
            free(buffer);
            return TRAVERSIO_ZLIB_ERROR_INVALID_DATA;
        }

        if (status != Z_OK && status != Z_STREAM_END && status != Z_BUF_ERROR) {
            free(buffer);
            return TRAVERSIO_ZLIB_ERROR_INTERNAL;
        }

        if (ctx->stream.avail_in == 0
            && ctx->stream.avail_out > 0
            && (status == Z_OK || status == Z_STREAM_END || status == Z_BUF_ERROR)) {
            *output = buffer;
            *output_length = used;
            return TRAVERSIO_ZLIB_SUCCESS;
        }

        if (ctx->stream.avail_out > 0) {
            buffer = traversio_zlib_grow_buffer(buffer, capacity + 1, &capacity);
            if (buffer == NULL) {
                return TRAVERSIO_ZLIB_ERROR_INTERNAL;
            }
        }
    }
}

void
traversio_zlib_buffer_free(void *buffer)
{
    free(buffer);
}
