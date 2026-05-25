/*
 * Copyright (c) 2026 GitSwift LLC
 *
 * Licensed under the GNU Affero General Public License v3.0 or later.
 * See LICENSE for details.
 */

#include "TraversioCCrypto.h"

#include <limits.h>
#include <stdlib.h>

#include "traversio_compat.h"
#include "umac.h"

struct traversio_umac_ctx {
	struct umac_ctx *context;
	size_t tag_length;
};

traversio_umac_ctx *
traversio_umac_new(size_t tag_length, const uint8_t *key, size_t key_length)
{
	traversio_umac_ctx *ctx;

	if (key == NULL || key_length != 16 ||
	    (tag_length != 8 && tag_length != 16)) {
		return NULL;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		return NULL;
	}

	ctx->context = tag_length == 8 ? umac_new(key) : umac128_new(key);
	if (ctx->context == NULL) {
		free(ctx);
		return NULL;
	}

	ctx->tag_length = tag_length;
	return ctx;
}

void
traversio_umac_free(traversio_umac_ctx *ctx)
{
	if (ctx == NULL) {
		return;
	}

	if (ctx->context != NULL) {
		if (ctx->tag_length == 8) {
			umac_delete(ctx->context);
		} else {
			umac128_delete(ctx->context);
		}
	}
	free(ctx);
}

int
traversio_umac_authenticate(
	traversio_umac_ctx *ctx,
	uint32_t sequence_number,
	const uint8_t *packet_bytes,
	size_t packet_length,
	uint8_t *tag
)
{
	static const uint8_t empty_input = 0;
	const uint8_t *input = packet_bytes;
	uint8_t nonce[8];
	int ok;

	if (ctx == NULL || ctx->context == NULL || tag == NULL ||
	    packet_length > LONG_MAX ||
	    (packet_length != 0 && packet_bytes == NULL)) {
		return TRAVERSIO_UMAC_ERROR_INVALID_ARGUMENT;
	}

	if (input == NULL) {
		input = &empty_input;
	}

	put_u64(nonce, sequence_number);
	if (ctx->tag_length == 8) {
		ok = umac_update(ctx->context, input, (long)packet_length) &&
			umac_final(ctx->context, tag, nonce);
	} else {
		ok = umac128_update(ctx->context, input, (long)packet_length) &&
			umac128_final(ctx->context, tag, nonce);
	}
	explicit_bzero(nonce, sizeof(nonce));

	return ok ? TRAVERSIO_UMAC_SUCCESS : TRAVERSIO_UMAC_ERROR_INTERNAL;
}
