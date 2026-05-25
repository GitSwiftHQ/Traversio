/*
 * Adapted for Traversio from the OpenBSD/OpenSSH bcrypt_pbkdf implementation.
 *
 * Original notices:
 *   Copyright (c) 2013 Ted Unangst <tedu@openbsd.org>
 *   Copyright 1997 Niels Provos <provos@physnet.uni-hamburg.de>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the original copyright notices
 * and disclaimers are preserved.
 */

#include <CommonCrypto/CommonDigest.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "TraversioCCrypto.h"
#include "blf.h"
#include "traversio_compat.h"

#define TRAVERSIO_BCRYPT_WORDS 8
#define TRAVERSIO_BCRYPT_HASHSIZE (TRAVERSIO_BCRYPT_WORDS * 4)
#define TRAVERSIO_MINIMUM(a, b) (((a) < (b)) ? (a) : (b))

static void
traversio_bcrypt_hash(
    uint8_t *sha2pass,
    uint8_t *sha2salt,
    uint8_t *out
)
{
    blf_ctx state;
    uint8_t ciphertext[TRAVERSIO_BCRYPT_HASHSIZE] =
        "OxychromaticBlowfishSwatDynamite";
    uint32_t cdata[TRAVERSIO_BCRYPT_WORDS];
    uint16_t j = 0;

    Blowfish_initstate(&state);
    Blowfish_expandstate(
        &state,
        sha2salt,
        CC_SHA512_DIGEST_LENGTH,
        sha2pass,
        CC_SHA512_DIGEST_LENGTH
    );
    for (int i = 0; i < 64; i++) {
        Blowfish_expand0state(&state, sha2salt, CC_SHA512_DIGEST_LENGTH);
        Blowfish_expand0state(&state, sha2pass, CC_SHA512_DIGEST_LENGTH);
    }

    for (int i = 0; i < TRAVERSIO_BCRYPT_WORDS; i++) {
        cdata[i] = Blowfish_stream2word(
            ciphertext,
            sizeof(ciphertext),
            &j
        );
    }
    for (int i = 0; i < 64; i++) {
        blf_enc(&state, cdata, TRAVERSIO_BCRYPT_WORDS / 2);
    }

    for (int i = 0; i < TRAVERSIO_BCRYPT_WORDS; i++) {
        out[4 * i + 3] = (uint8_t)((cdata[i] >> 24) & 0xff);
        out[4 * i + 2] = (uint8_t)((cdata[i] >> 16) & 0xff);
        out[4 * i + 1] = (uint8_t)((cdata[i] >> 8) & 0xff);
        out[4 * i + 0] = (uint8_t)(cdata[i] & 0xff);
    }

    explicit_bzero(ciphertext, sizeof(ciphertext));
    explicit_bzero(cdata, sizeof(cdata));
    explicit_bzero(&state, sizeof(state));
}

int
traversio_bcrypt_pbkdf(
    const char *passphrase,
    size_t passphrase_length,
    const uint8_t *salt,
    size_t salt_length,
    uint8_t *derived_key,
    size_t derived_key_length,
    uint32_t rounds
)
{
    uint8_t sha2pass[CC_SHA512_DIGEST_LENGTH];
    uint8_t sha2salt[CC_SHA512_DIGEST_LENGTH];
    uint8_t out[TRAVERSIO_BCRYPT_HASHSIZE];
    uint8_t tmpout[TRAVERSIO_BCRYPT_HASHSIZE];
    uint8_t *countsalt = NULL;
    size_t stride;
    size_t amount;
    size_t remaining;
    size_t original_length = derived_key_length;

    if (passphrase == NULL || salt == NULL || derived_key == NULL ||
        rounds < 1 || passphrase_length == 0 || salt_length == 0 ||
        derived_key_length == 0 ||
        derived_key_length > sizeof(out) * sizeof(out) ||
        salt_length > (1u << 20)) {
        return TRAVERSIO_BCRYPT_PBKDF_ERROR_INVALID_ARGUMENT;
    }

    countsalt = calloc(1, salt_length + 4);
    if (countsalt == NULL) {
        return TRAVERSIO_BCRYPT_PBKDF_ERROR_INTERNAL;
    }

    stride = (derived_key_length + sizeof(out) - 1) / sizeof(out);
    amount = (derived_key_length + stride - 1) / stride;
    remaining = derived_key_length;
    memcpy(countsalt, salt, salt_length);

    CC_SHA512(passphrase, (CC_LONG)passphrase_length, sha2pass);

    for (uint32_t count = 1; remaining > 0; count++) {
        countsalt[salt_length + 0] = (uint8_t)((count >> 24) & 0xff);
        countsalt[salt_length + 1] = (uint8_t)((count >> 16) & 0xff);
        countsalt[salt_length + 2] = (uint8_t)((count >> 8) & 0xff);
        countsalt[salt_length + 3] = (uint8_t)(count & 0xff);

        CC_SHA512(countsalt, (CC_LONG)(salt_length + 4), sha2salt);

        traversio_bcrypt_hash(sha2pass, sha2salt, tmpout);
        memcpy(out, tmpout, sizeof(out));

        for (uint32_t round = 1; round < rounds; round++) {
            CC_SHA512(tmpout, (CC_LONG)sizeof(tmpout), sha2salt);
            traversio_bcrypt_hash(sha2pass, sha2salt, tmpout);
            for (size_t index = 0; index < sizeof(out); index++) {
                out[index] ^= tmpout[index];
            }
        }

        amount = TRAVERSIO_MINIMUM(amount, remaining);
        size_t written = 0;
        for (; written < amount; written++) {
            size_t destination = written * stride + (count - 1);
            if (destination >= original_length) {
                break;
            }
            derived_key[destination] = out[written];
        }
        remaining -= written;
    }

    freezero(countsalt, salt_length + 4);
    explicit_bzero(sha2pass, sizeof(sha2pass));
    explicit_bzero(sha2salt, sizeof(sha2salt));
    explicit_bzero(out, sizeof(out));
    explicit_bzero(tmpout, sizeof(tmpout));
    return TRAVERSIO_BCRYPT_PBKDF_SUCCESS;
}
