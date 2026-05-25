/*
 * Copyright (c) 2026 GitSwift LLC
 *
 * Licensed under the GNU Affero General Public License v3.0 or later.
 * See LICENSE for details.
 */

#ifndef TRAVERSIO_CCRYPTO_H
#define TRAVERSIO_CCRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define TRAVERSIO_CHACHAPOLY_SUCCESS 0
#define TRAVERSIO_CHACHAPOLY_ERROR_INVALID_ARGUMENT 1
#define TRAVERSIO_CHACHAPOLY_ERROR_INVALID_MAC 2
#define TRAVERSIO_BCRYPT_PBKDF_SUCCESS 0
#define TRAVERSIO_BCRYPT_PBKDF_ERROR_INVALID_ARGUMENT 1
#define TRAVERSIO_BCRYPT_PBKDF_ERROR_INTERNAL 2
#define TRAVERSIO_UMAC_SUCCESS 0
#define TRAVERSIO_UMAC_ERROR_INVALID_ARGUMENT 1
#define TRAVERSIO_UMAC_ERROR_INTERNAL 2
#define TRAVERSIO_ZLIB_SUCCESS 0
#define TRAVERSIO_ZLIB_ERROR_INVALID_ARGUMENT 1
#define TRAVERSIO_ZLIB_ERROR_BUFFER_TOO_SMALL 2
#define TRAVERSIO_ZLIB_ERROR_INVALID_DATA 3
#define TRAVERSIO_ZLIB_ERROR_INTERNAL 4

typedef struct traversio_chachapoly_ctx traversio_chachapoly_ctx;
typedef struct traversio_umac_ctx traversio_umac_ctx;
typedef struct traversio_zlib_compressor_ctx traversio_zlib_compressor_ctx;
typedef struct traversio_zlib_decompressor_ctx traversio_zlib_decompressor_ctx;

traversio_chachapoly_ctx *traversio_chachapoly_new(const uint8_t *key, size_t keylen);
void traversio_chachapoly_free(traversio_chachapoly_ctx *ctx);

int traversio_chachapoly_encrypt_packet(
    traversio_chachapoly_ctx *ctx,
    uint32_t sequence_number,
    const uint8_t *packet,
    size_t packet_length,
    uint8_t *encrypted_packet,
    uint8_t *tag
);

int traversio_chachapoly_decrypt_packet(
    traversio_chachapoly_ctx *ctx,
    uint32_t sequence_number,
    const uint8_t *encrypted_packet,
    size_t packet_length,
    const uint8_t *tag,
    uint8_t *packet
);

int traversio_chachapoly_get_length(
    traversio_chachapoly_ctx *ctx,
    uint32_t sequence_number,
    const uint8_t *encrypted_prefix,
    size_t prefix_length,
    uint32_t *packet_length
);

int traversio_bcrypt_pbkdf(
    const char *passphrase,
    size_t passphrase_length,
    const uint8_t *salt,
    size_t salt_length,
    uint8_t *derived_key,
    size_t derived_key_length,
    uint32_t rounds
);

traversio_umac_ctx *traversio_umac_new(
    size_t tag_length,
    const uint8_t *key,
    size_t key_length
);
void traversio_umac_free(traversio_umac_ctx *ctx);

int traversio_umac_authenticate(
    traversio_umac_ctx *ctx,
    uint32_t sequence_number,
    const uint8_t *packet_bytes,
    size_t packet_length,
    uint8_t *tag
);

traversio_zlib_compressor_ctx *traversio_zlib_compressor_new(void);
void traversio_zlib_compressor_free(traversio_zlib_compressor_ctx *ctx);

int traversio_zlib_compress(
    traversio_zlib_compressor_ctx *ctx,
    const uint8_t *input,
    size_t input_length,
    uint8_t **output,
    size_t *output_length
);

traversio_zlib_decompressor_ctx *traversio_zlib_decompressor_new(void);
void traversio_zlib_decompressor_free(traversio_zlib_decompressor_ctx *ctx);

int traversio_zlib_decompress(
    traversio_zlib_decompressor_ctx *ctx,
    const uint8_t *input,
    size_t input_length,
    uint8_t **output,
    size_t *output_length
);

void traversio_zlib_buffer_free(void *buffer);

#endif
