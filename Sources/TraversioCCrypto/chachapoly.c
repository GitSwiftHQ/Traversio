/*
 * Portions of this file are adapted from OpenSSH portable:
 * - chacha.c (public domain)
 * - poly1305.c (public domain)
 * - cipher-chachapoly.c (ISC-style permissive terms)
 *
 * This package-only wrapper keeps the OpenSSH chacha20-poly1305 packet
 * construction in one small implementation unit instead of re-deriving it
 * in Swift.
 */

#include "TraversioCCrypto.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct traversio_chacha_ctx {
    uint32_t input[16];
} traversio_chacha_ctx;

struct traversio_chachapoly_ctx {
    traversio_chacha_ctx main_ctx;
    traversio_chacha_ctx header_ctx;
};

#define TRAVERSIO_POLY1305_KEY_LENGTH 32
#define TRAVERSIO_POLY1305_TAG_LENGTH 16

#define TRAVERSIO_U8V(v) ((uint8_t)(v) & 0xFFU)
#define TRAVERSIO_U32V(v) ((uint32_t)(v) & 0xFFFFFFFFU)
#define TRAVERSIO_ROTL32(v, n) (TRAVERSIO_U32V((v) << (n)) | ((v) >> (32 - (n))))
#define TRAVERSIO_PLUS(v, w) TRAVERSIO_U32V((v) + (w))
#define TRAVERSIO_PLUSONE(v) TRAVERSIO_PLUS((v), 1)
#define TRAVERSIO_XOR(v, w) ((v) ^ (w))

#define TRAVERSIO_U8TO32_LITTLE(p) \
    (((uint32_t)((p)[0])) | \
     ((uint32_t)((p)[1]) << 8) | \
     ((uint32_t)((p)[2]) << 16) | \
     ((uint32_t)((p)[3]) << 24))

#define TRAVERSIO_U32TO8_LITTLE(p, v) \
    do { \
        (p)[0] = TRAVERSIO_U8V((v)); \
        (p)[1] = TRAVERSIO_U8V((v) >> 8); \
        (p)[2] = TRAVERSIO_U8V((v) >> 16); \
        (p)[3] = TRAVERSIO_U8V((v) >> 24); \
    } while (0)

#define TRAVERSIO_U8TO32_BIG(p) \
    (((uint32_t)((p)[0]) << 24) | \
     ((uint32_t)((p)[1]) << 16) | \
     ((uint32_t)((p)[2]) << 8) | \
      (uint32_t)((p)[3]))

#define TRAVERSIO_POLY1305_MUL32X32_64(a, b) ((uint64_t)(a) * (b))
#define TRAVERSIO_POLY1305_U8TO32_LE(p) \
    (((uint32_t)((p)[0])) | \
     ((uint32_t)((p)[1]) << 8) | \
     ((uint32_t)((p)[2]) << 16) | \
     ((uint32_t)((p)[3]) << 24))

#define TRAVERSIO_POLY1305_U32TO8_LE(p, v) \
    do { \
        (p)[0] = (uint8_t)((v)); \
        (p)[1] = (uint8_t)((v) >> 8); \
        (p)[2] = (uint8_t)((v) >> 16); \
        (p)[3] = (uint8_t)((v) >> 24); \
    } while (0)

#define TRAVERSIO_QUARTERROUND(a, b, c, d) \
    a = TRAVERSIO_PLUS(a, b); d = TRAVERSIO_ROTL32(TRAVERSIO_XOR(d, a), 16); \
    c = TRAVERSIO_PLUS(c, d); b = TRAVERSIO_ROTL32(TRAVERSIO_XOR(b, c), 12); \
    a = TRAVERSIO_PLUS(a, b); d = TRAVERSIO_ROTL32(TRAVERSIO_XOR(d, a), 8); \
    c = TRAVERSIO_PLUS(c, d); b = TRAVERSIO_ROTL32(TRAVERSIO_XOR(b, c), 7);

static const uint8_t traversio_chacha_sigma[16] = "expand 32-byte k";

static void
traversio_secure_bzero(void *memory, size_t length)
{
    volatile uint8_t *pointer = (volatile uint8_t *)memory;
    while (length-- > 0) {
        *pointer++ = 0;
    }
}

static int
traversio_constant_time_equals(const uint8_t *lhs, const uint8_t *rhs, size_t length)
{
    uint8_t difference = 0;
    size_t index;

    for (index = 0; index < length; index++) {
        difference |= lhs[index] ^ rhs[index];
    }

    return difference == 0;
}

static void
traversio_poke_u64_big(uint8_t *destination, uint64_t value)
{
    destination[0] = (uint8_t)((value >> 56) & 0xff);
    destination[1] = (uint8_t)((value >> 48) & 0xff);
    destination[2] = (uint8_t)((value >> 40) & 0xff);
    destination[3] = (uint8_t)((value >> 32) & 0xff);
    destination[4] = (uint8_t)((value >> 24) & 0xff);
    destination[5] = (uint8_t)((value >> 16) & 0xff);
    destination[6] = (uint8_t)((value >> 8) & 0xff);
    destination[7] = (uint8_t)(value & 0xff);
}

static void
traversio_chacha_keysetup(traversio_chacha_ctx *ctx, const uint8_t *key)
{
    ctx->input[0] = TRAVERSIO_U8TO32_LITTLE(traversio_chacha_sigma + 0);
    ctx->input[1] = TRAVERSIO_U8TO32_LITTLE(traversio_chacha_sigma + 4);
    ctx->input[2] = TRAVERSIO_U8TO32_LITTLE(traversio_chacha_sigma + 8);
    ctx->input[3] = TRAVERSIO_U8TO32_LITTLE(traversio_chacha_sigma + 12);
    ctx->input[4] = TRAVERSIO_U8TO32_LITTLE(key + 0);
    ctx->input[5] = TRAVERSIO_U8TO32_LITTLE(key + 4);
    ctx->input[6] = TRAVERSIO_U8TO32_LITTLE(key + 8);
    ctx->input[7] = TRAVERSIO_U8TO32_LITTLE(key + 12);
    ctx->input[8] = TRAVERSIO_U8TO32_LITTLE(key + 16);
    ctx->input[9] = TRAVERSIO_U8TO32_LITTLE(key + 20);
    ctx->input[10] = TRAVERSIO_U8TO32_LITTLE(key + 24);
    ctx->input[11] = TRAVERSIO_U8TO32_LITTLE(key + 28);
}

static void
traversio_chacha_ivsetup(traversio_chacha_ctx *ctx, const uint8_t *nonce, const uint8_t *counter)
{
    ctx->input[12] = counter == NULL ? 0 : TRAVERSIO_U8TO32_LITTLE(counter + 0);
    ctx->input[13] = counter == NULL ? 0 : TRAVERSIO_U8TO32_LITTLE(counter + 4);
    ctx->input[14] = TRAVERSIO_U8TO32_LITTLE(nonce + 0);
    ctx->input[15] = TRAVERSIO_U8TO32_LITTLE(nonce + 4);
}

static void
traversio_chacha_encrypt_bytes(
    traversio_chacha_ctx *ctx,
    const uint8_t *input,
    uint8_t *output,
    size_t count
)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
    uint32_t j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
    uint8_t *partial_target = NULL;
    uint8_t partial_block[64];
    unsigned int round;
    size_t index;

    if (count == 0) {
        return;
    }

    j0 = ctx->input[0];
    j1 = ctx->input[1];
    j2 = ctx->input[2];
    j3 = ctx->input[3];
    j4 = ctx->input[4];
    j5 = ctx->input[5];
    j6 = ctx->input[6];
    j7 = ctx->input[7];
    j8 = ctx->input[8];
    j9 = ctx->input[9];
    j10 = ctx->input[10];
    j11 = ctx->input[11];
    j12 = ctx->input[12];
    j13 = ctx->input[13];
    j14 = ctx->input[14];
    j15 = ctx->input[15];

    for (;;) {
        if (count < 64) {
            for (index = 0; index < count; index++) {
                partial_block[index] = input[index];
            }
            input = partial_block;
            partial_target = output;
            output = partial_block;
        }

        x0 = j0; x1 = j1; x2 = j2; x3 = j3;
        x4 = j4; x5 = j5; x6 = j6; x7 = j7;
        x8 = j8; x9 = j9; x10 = j10; x11 = j11;
        x12 = j12; x13 = j13; x14 = j14; x15 = j15;

        for (round = 20; round > 0; round -= 2) {
            TRAVERSIO_QUARTERROUND(x0, x4, x8, x12)
            TRAVERSIO_QUARTERROUND(x1, x5, x9, x13)
            TRAVERSIO_QUARTERROUND(x2, x6, x10, x14)
            TRAVERSIO_QUARTERROUND(x3, x7, x11, x15)
            TRAVERSIO_QUARTERROUND(x0, x5, x10, x15)
            TRAVERSIO_QUARTERROUND(x1, x6, x11, x12)
            TRAVERSIO_QUARTERROUND(x2, x7, x8, x13)
            TRAVERSIO_QUARTERROUND(x3, x4, x9, x14)
        }

        x0 = TRAVERSIO_PLUS(x0, j0);
        x1 = TRAVERSIO_PLUS(x1, j1);
        x2 = TRAVERSIO_PLUS(x2, j2);
        x3 = TRAVERSIO_PLUS(x3, j3);
        x4 = TRAVERSIO_PLUS(x4, j4);
        x5 = TRAVERSIO_PLUS(x5, j5);
        x6 = TRAVERSIO_PLUS(x6, j6);
        x7 = TRAVERSIO_PLUS(x7, j7);
        x8 = TRAVERSIO_PLUS(x8, j8);
        x9 = TRAVERSIO_PLUS(x9, j9);
        x10 = TRAVERSIO_PLUS(x10, j10);
        x11 = TRAVERSIO_PLUS(x11, j11);
        x12 = TRAVERSIO_PLUS(x12, j12);
        x13 = TRAVERSIO_PLUS(x13, j13);
        x14 = TRAVERSIO_PLUS(x14, j14);
        x15 = TRAVERSIO_PLUS(x15, j15);

        x0 = TRAVERSIO_XOR(x0, TRAVERSIO_U8TO32_LITTLE(input + 0));
        x1 = TRAVERSIO_XOR(x1, TRAVERSIO_U8TO32_LITTLE(input + 4));
        x2 = TRAVERSIO_XOR(x2, TRAVERSIO_U8TO32_LITTLE(input + 8));
        x3 = TRAVERSIO_XOR(x3, TRAVERSIO_U8TO32_LITTLE(input + 12));
        x4 = TRAVERSIO_XOR(x4, TRAVERSIO_U8TO32_LITTLE(input + 16));
        x5 = TRAVERSIO_XOR(x5, TRAVERSIO_U8TO32_LITTLE(input + 20));
        x6 = TRAVERSIO_XOR(x6, TRAVERSIO_U8TO32_LITTLE(input + 24));
        x7 = TRAVERSIO_XOR(x7, TRAVERSIO_U8TO32_LITTLE(input + 28));
        x8 = TRAVERSIO_XOR(x8, TRAVERSIO_U8TO32_LITTLE(input + 32));
        x9 = TRAVERSIO_XOR(x9, TRAVERSIO_U8TO32_LITTLE(input + 36));
        x10 = TRAVERSIO_XOR(x10, TRAVERSIO_U8TO32_LITTLE(input + 40));
        x11 = TRAVERSIO_XOR(x11, TRAVERSIO_U8TO32_LITTLE(input + 44));
        x12 = TRAVERSIO_XOR(x12, TRAVERSIO_U8TO32_LITTLE(input + 48));
        x13 = TRAVERSIO_XOR(x13, TRAVERSIO_U8TO32_LITTLE(input + 52));
        x14 = TRAVERSIO_XOR(x14, TRAVERSIO_U8TO32_LITTLE(input + 56));
        x15 = TRAVERSIO_XOR(x15, TRAVERSIO_U8TO32_LITTLE(input + 60));

        j12 = TRAVERSIO_PLUSONE(j12);
        if (j12 == 0) {
            j13 = TRAVERSIO_PLUSONE(j13);
        }

        TRAVERSIO_U32TO8_LITTLE(output + 0, x0);
        TRAVERSIO_U32TO8_LITTLE(output + 4, x1);
        TRAVERSIO_U32TO8_LITTLE(output + 8, x2);
        TRAVERSIO_U32TO8_LITTLE(output + 12, x3);
        TRAVERSIO_U32TO8_LITTLE(output + 16, x4);
        TRAVERSIO_U32TO8_LITTLE(output + 20, x5);
        TRAVERSIO_U32TO8_LITTLE(output + 24, x6);
        TRAVERSIO_U32TO8_LITTLE(output + 28, x7);
        TRAVERSIO_U32TO8_LITTLE(output + 32, x8);
        TRAVERSIO_U32TO8_LITTLE(output + 36, x9);
        TRAVERSIO_U32TO8_LITTLE(output + 40, x10);
        TRAVERSIO_U32TO8_LITTLE(output + 44, x11);
        TRAVERSIO_U32TO8_LITTLE(output + 48, x12);
        TRAVERSIO_U32TO8_LITTLE(output + 52, x13);
        TRAVERSIO_U32TO8_LITTLE(output + 56, x14);
        TRAVERSIO_U32TO8_LITTLE(output + 60, x15);

        if (count <= 64) {
            if (count < 64) {
                for (index = 0; index < count; index++) {
                    partial_target[index] = output[index];
                }
            }

            ctx->input[12] = j12;
            ctx->input[13] = j13;
            traversio_secure_bzero(partial_block, sizeof(partial_block));
            return;
        }

        count -= 64;
        output += 64;
        input += 64;
    }
}

static void
traversio_poly1305_auth(
    uint8_t output[TRAVERSIO_POLY1305_TAG_LENGTH],
    const uint8_t *message,
    size_t length,
    const uint8_t key[TRAVERSIO_POLY1305_KEY_LENGTH]
)
{
    uint32_t t0, t1, t2, t3;
    uint32_t h0, h1, h2, h3, h4;
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;
    uint32_t carry, not_borrow;
    size_t index;
    uint64_t t[5];
    uint64_t f0, f1, f2, f3;
    uint32_t g0, g1, g2, g3, g4;
    uint64_t c;
    uint8_t partial[16];

    t0 = TRAVERSIO_POLY1305_U8TO32_LE(key + 0);
    t1 = TRAVERSIO_POLY1305_U8TO32_LE(key + 4);
    t2 = TRAVERSIO_POLY1305_U8TO32_LE(key + 8);
    t3 = TRAVERSIO_POLY1305_U8TO32_LE(key + 12);

    r0 = t0 & 0x3ffffff; t0 >>= 26; t0 |= t1 << 6;
    r1 = t0 & 0x3ffff03; t1 >>= 20; t1 |= t2 << 12;
    r2 = t1 & 0x3ffc0ff; t2 >>= 14; t2 |= t3 << 18;
    r3 = t2 & 0x3f03fff; t3 >>= 8;
    r4 = t3 & 0x00fffff;

    s1 = r1 * 5;
    s2 = r2 * 5;
    s3 = r3 * 5;
    s4 = r4 * 5;

    h0 = h1 = h2 = h3 = h4 = 0;

    if (length < 16) {
        goto traversio_poly1305_partial;
    }

traversio_poly1305_block:
    message += 16;
    length -= 16;

    t0 = TRAVERSIO_POLY1305_U8TO32_LE(message - 16);
    t1 = TRAVERSIO_POLY1305_U8TO32_LE(message - 12);
    t2 = TRAVERSIO_POLY1305_U8TO32_LE(message - 8);
    t3 = TRAVERSIO_POLY1305_U8TO32_LE(message - 4);

    h0 += t0 & 0x3ffffff;
    h1 += ((((uint64_t)t1 << 32) | t0) >> 26) & 0x3ffffff;
    h2 += ((((uint64_t)t2 << 32) | t1) >> 20) & 0x3ffffff;
    h3 += ((((uint64_t)t3 << 32) | t2) >> 14) & 0x3ffffff;
    h4 += (t3 >> 8) | (1 << 24);

traversio_poly1305_multiply:
    t[0] = TRAVERSIO_POLY1305_MUL32X32_64(h0, r0)
        + TRAVERSIO_POLY1305_MUL32X32_64(h1, s4)
        + TRAVERSIO_POLY1305_MUL32X32_64(h2, s3)
        + TRAVERSIO_POLY1305_MUL32X32_64(h3, s2)
        + TRAVERSIO_POLY1305_MUL32X32_64(h4, s1);
    t[1] = TRAVERSIO_POLY1305_MUL32X32_64(h0, r1)
        + TRAVERSIO_POLY1305_MUL32X32_64(h1, r0)
        + TRAVERSIO_POLY1305_MUL32X32_64(h2, s4)
        + TRAVERSIO_POLY1305_MUL32X32_64(h3, s3)
        + TRAVERSIO_POLY1305_MUL32X32_64(h4, s2);
    t[2] = TRAVERSIO_POLY1305_MUL32X32_64(h0, r2)
        + TRAVERSIO_POLY1305_MUL32X32_64(h1, r1)
        + TRAVERSIO_POLY1305_MUL32X32_64(h2, r0)
        + TRAVERSIO_POLY1305_MUL32X32_64(h3, s4)
        + TRAVERSIO_POLY1305_MUL32X32_64(h4, s3);
    t[3] = TRAVERSIO_POLY1305_MUL32X32_64(h0, r3)
        + TRAVERSIO_POLY1305_MUL32X32_64(h1, r2)
        + TRAVERSIO_POLY1305_MUL32X32_64(h2, r1)
        + TRAVERSIO_POLY1305_MUL32X32_64(h3, r0)
        + TRAVERSIO_POLY1305_MUL32X32_64(h4, s4);
    t[4] = TRAVERSIO_POLY1305_MUL32X32_64(h0, r4)
        + TRAVERSIO_POLY1305_MUL32X32_64(h1, r3)
        + TRAVERSIO_POLY1305_MUL32X32_64(h2, r2)
        + TRAVERSIO_POLY1305_MUL32X32_64(h3, r1)
        + TRAVERSIO_POLY1305_MUL32X32_64(h4, r0);

    h0 = (uint32_t)t[0] & 0x3ffffff; c = t[0] >> 26;
    t[1] += c; h1 = (uint32_t)t[1] & 0x3ffffff; carry = (uint32_t)(t[1] >> 26);
    t[2] += carry; h2 = (uint32_t)t[2] & 0x3ffffff; carry = (uint32_t)(t[2] >> 26);
    t[3] += carry; h3 = (uint32_t)t[3] & 0x3ffffff; carry = (uint32_t)(t[3] >> 26);
    t[4] += carry; h4 = (uint32_t)t[4] & 0x3ffffff; carry = (uint32_t)(t[4] >> 26);
    h0 += carry * 5;

    if (length >= 16) {
        goto traversio_poly1305_block;
    }

traversio_poly1305_partial:
    if (length == 0) {
        goto traversio_poly1305_finish;
    }

    for (index = 0; index < length; index++) {
        partial[index] = message[index];
    }
    partial[index++] = 1;
    for (; index < 16; index++) {
        partial[index] = 0;
    }
    length = 0;

    t0 = TRAVERSIO_POLY1305_U8TO32_LE(partial + 0);
    t1 = TRAVERSIO_POLY1305_U8TO32_LE(partial + 4);
    t2 = TRAVERSIO_POLY1305_U8TO32_LE(partial + 8);
    t3 = TRAVERSIO_POLY1305_U8TO32_LE(partial + 12);

    h0 += t0 & 0x3ffffff;
    h1 += ((((uint64_t)t1 << 32) | t0) >> 26) & 0x3ffffff;
    h2 += ((((uint64_t)t2 << 32) | t1) >> 20) & 0x3ffffff;
    h3 += ((((uint64_t)t3 << 32) | t2) >> 14) & 0x3ffffff;
    h4 += (t3 >> 8);

    goto traversio_poly1305_multiply;

traversio_poly1305_finish:
    carry = h0 >> 26; h0 &= 0x3ffffff;
    h1 += carry; carry = h1 >> 26; h1 &= 0x3ffffff;
    h2 += carry; carry = h2 >> 26; h2 &= 0x3ffffff;
    h3 += carry; carry = h3 >> 26; h3 &= 0x3ffffff;
    h4 += carry; carry = h4 >> 26; h4 &= 0x3ffffff;
    h0 += carry * 5; carry = h0 >> 26; h0 &= 0x3ffffff;
    h1 += carry;

    g0 = h0 + 5; carry = g0 >> 26; g0 &= 0x3ffffff;
    g1 = h1 + carry; carry = g1 >> 26; g1 &= 0x3ffffff;
    g2 = h2 + carry; carry = g2 >> 26; g2 &= 0x3ffffff;
    g3 = h3 + carry; carry = g3 >> 26; g3 &= 0x3ffffff;
    g4 = h4 + carry - (1U << 26);

    carry = (g4 >> 31) - 1;
    not_borrow = ~carry;
    h0 = (h0 & not_borrow) | (g0 & carry);
    h1 = (h1 & not_borrow) | (g1 & carry);
    h2 = (h2 & not_borrow) | (g2 & carry);
    h3 = (h3 & not_borrow) | (g3 & carry);
    h4 = (h4 & not_borrow) | (g4 & carry);

    f0 = ((h0) | (h1 << 26)) + (uint64_t)TRAVERSIO_POLY1305_U8TO32_LE(&key[16]);
    f1 = ((h1 >> 6) | (h2 << 20)) + (uint64_t)TRAVERSIO_POLY1305_U8TO32_LE(&key[20]);
    f2 = ((h2 >> 12) | (h3 << 14)) + (uint64_t)TRAVERSIO_POLY1305_U8TO32_LE(&key[24]);
    f3 = ((h3 >> 18) | (h4 << 8)) + (uint64_t)TRAVERSIO_POLY1305_U8TO32_LE(&key[28]);

    TRAVERSIO_POLY1305_U32TO8_LE(&output[0], f0); f1 += (f0 >> 32);
    TRAVERSIO_POLY1305_U32TO8_LE(&output[4], f1); f2 += (f1 >> 32);
    TRAVERSIO_POLY1305_U32TO8_LE(&output[8], f2); f3 += (f2 >> 32);
    TRAVERSIO_POLY1305_U32TO8_LE(&output[12], f3);

    traversio_secure_bzero(partial, sizeof(partial));
}

traversio_chachapoly_ctx *
traversio_chachapoly_new(const uint8_t *key, size_t keylen)
{
    traversio_chachapoly_ctx *ctx;

    if (key == NULL || keylen != 64) {
        return NULL;
    }

    ctx = (traversio_chachapoly_ctx *)calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return NULL;
    }

    traversio_chacha_keysetup(&ctx->main_ctx, key);
    traversio_chacha_keysetup(&ctx->header_ctx, key + 32);
    return ctx;
}

void
traversio_chachapoly_free(traversio_chachapoly_ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    traversio_secure_bzero(ctx, sizeof(*ctx));
    free(ctx);
}

int
traversio_chachapoly_encrypt_packet(
    traversio_chachapoly_ctx *ctx,
    uint32_t sequence_number,
    const uint8_t *packet,
    size_t packet_length,
    uint8_t *encrypted_packet,
    uint8_t *tag
)
{
    static const uint8_t counter_one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t nonce[8];
    uint8_t zero_block[TRAVERSIO_POLY1305_KEY_LENGTH];
    uint8_t poly_key[TRAVERSIO_POLY1305_KEY_LENGTH];

    if (ctx == NULL || packet == NULL || encrypted_packet == NULL || tag == NULL || packet_length < 4) {
        return TRAVERSIO_CHACHAPOLY_ERROR_INVALID_ARGUMENT;
    }

    memset(zero_block, 0, sizeof(zero_block));
    traversio_poke_u64_big(nonce, sequence_number);
    traversio_chacha_ivsetup(&ctx->main_ctx, nonce, NULL);
    traversio_chacha_encrypt_bytes(&ctx->main_ctx, zero_block, poly_key, sizeof(poly_key));

    traversio_chacha_ivsetup(&ctx->header_ctx, nonce, NULL);
    traversio_chacha_encrypt_bytes(&ctx->header_ctx, packet, encrypted_packet, 4);

    traversio_chacha_ivsetup(&ctx->main_ctx, nonce, counter_one);
    traversio_chacha_encrypt_bytes(&ctx->main_ctx, packet + 4, encrypted_packet + 4, packet_length - 4);

    traversio_poly1305_auth(tag, encrypted_packet, packet_length, poly_key);
    traversio_secure_bzero(nonce, sizeof(nonce));
    traversio_secure_bzero(zero_block, sizeof(zero_block));
    traversio_secure_bzero(poly_key, sizeof(poly_key));
    return TRAVERSIO_CHACHAPOLY_SUCCESS;
}

int
traversio_chachapoly_decrypt_packet(
    traversio_chachapoly_ctx *ctx,
    uint32_t sequence_number,
    const uint8_t *encrypted_packet,
    size_t packet_length,
    const uint8_t *tag,
    uint8_t *packet
)
{
    static const uint8_t counter_one[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
    uint8_t nonce[8];
    uint8_t zero_block[TRAVERSIO_POLY1305_KEY_LENGTH];
    uint8_t poly_key[TRAVERSIO_POLY1305_KEY_LENGTH];
    uint8_t expected_tag[TRAVERSIO_POLY1305_TAG_LENGTH];

    if (ctx == NULL || encrypted_packet == NULL || tag == NULL || packet == NULL || packet_length < 4) {
        return TRAVERSIO_CHACHAPOLY_ERROR_INVALID_ARGUMENT;
    }

    memset(zero_block, 0, sizeof(zero_block));
    traversio_poke_u64_big(nonce, sequence_number);
    traversio_chacha_ivsetup(&ctx->main_ctx, nonce, NULL);
    traversio_chacha_encrypt_bytes(&ctx->main_ctx, zero_block, poly_key, sizeof(poly_key));
    traversio_poly1305_auth(expected_tag, encrypted_packet, packet_length, poly_key);

    if (!traversio_constant_time_equals(expected_tag, tag, sizeof(expected_tag))) {
        traversio_secure_bzero(nonce, sizeof(nonce));
        traversio_secure_bzero(zero_block, sizeof(zero_block));
        traversio_secure_bzero(poly_key, sizeof(poly_key));
        traversio_secure_bzero(expected_tag, sizeof(expected_tag));
        return TRAVERSIO_CHACHAPOLY_ERROR_INVALID_MAC;
    }

    traversio_chacha_ivsetup(&ctx->header_ctx, nonce, NULL);
    traversio_chacha_encrypt_bytes(&ctx->header_ctx, encrypted_packet, packet, 4);

    traversio_chacha_ivsetup(&ctx->main_ctx, nonce, counter_one);
    traversio_chacha_encrypt_bytes(&ctx->main_ctx, encrypted_packet + 4, packet + 4, packet_length - 4);

    traversio_secure_bzero(nonce, sizeof(nonce));
    traversio_secure_bzero(zero_block, sizeof(zero_block));
    traversio_secure_bzero(poly_key, sizeof(poly_key));
    traversio_secure_bzero(expected_tag, sizeof(expected_tag));
    return TRAVERSIO_CHACHAPOLY_SUCCESS;
}

int
traversio_chachapoly_get_length(
    traversio_chachapoly_ctx *ctx,
    uint32_t sequence_number,
    const uint8_t *encrypted_prefix,
    size_t prefix_length,
    uint32_t *packet_length
)
{
    uint8_t nonce[8];
    uint8_t decrypted_length[4];

    if (ctx == NULL || encrypted_prefix == NULL || packet_length == NULL || prefix_length < 4) {
        return TRAVERSIO_CHACHAPOLY_ERROR_INVALID_ARGUMENT;
    }

    traversio_poke_u64_big(nonce, sequence_number);
    traversio_chacha_ivsetup(&ctx->header_ctx, nonce, NULL);
    traversio_chacha_encrypt_bytes(&ctx->header_ctx, encrypted_prefix, decrypted_length, 4);
    *packet_length = TRAVERSIO_U8TO32_BIG(decrypted_length);
    traversio_secure_bzero(nonce, sizeof(nonce));
    traversio_secure_bzero(decrypted_length, sizeof(decrypted_length));
    return TRAVERSIO_CHACHAPOLY_SUCCESS;
}
