/*
 * Copyright (c) 2026 GitSwift LLC
 *
 * Licensed under the GNU Affero General Public License v3.0 or later.
 * See LICENSE for details.
 */

#ifndef TRAVERSIO_OPENSSH_COMPAT_H
#define TRAVERSIO_OPENSSH_COMPAT_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#endif

#ifndef BIG_ENDIAN
#define BIG_ENDIAN 4321
#endif

#ifndef BYTE_ORDER
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define BYTE_ORDER LITTLE_ENDIAN
#else
#define BYTE_ORDER BIG_ENDIAN
#endif
#endif

static inline void
traversio_explicit_bzero(void *pointer, size_t length)
{
	volatile uint8_t *bytes = (volatile uint8_t *)pointer;

	while (length-- > 0) {
		*bytes++ = 0;
	}
}

#define explicit_bzero traversio_explicit_bzero
#define xcalloc calloc

static inline void
freezero(void *pointer, size_t length)
{
	if (pointer == NULL) {
		return;
	}

	explicit_bzero(pointer, length);
	free(pointer);
}

static inline uint32_t
get_u32(const void *pointer)
{
	const uint8_t *bytes = (const uint8_t *)pointer;

	return ((uint32_t)bytes[0] << 24) |
		((uint32_t)bytes[1] << 16) |
		((uint32_t)bytes[2] << 8) |
		(uint32_t)bytes[3];
}

static inline uint64_t
get_u64(const void *pointer)
{
	const uint8_t *bytes = (const uint8_t *)pointer;

	return ((uint64_t)bytes[0] << 56) |
		((uint64_t)bytes[1] << 48) |
		((uint64_t)bytes[2] << 40) |
		((uint64_t)bytes[3] << 32) |
		((uint64_t)bytes[4] << 24) |
		((uint64_t)bytes[5] << 16) |
		((uint64_t)bytes[6] << 8) |
		(uint64_t)bytes[7];
}

static inline uint32_t
get_u32_le(const void *pointer)
{
	const uint8_t *bytes = (const uint8_t *)pointer;

	return ((uint32_t)bytes[3] << 24) |
		((uint32_t)bytes[2] << 16) |
		((uint32_t)bytes[1] << 8) |
		(uint32_t)bytes[0];
}

static inline void
put_u32(void *pointer, uint32_t value)
{
	uint8_t *bytes = (uint8_t *)pointer;

	bytes[0] = (uint8_t)((value >> 24) & 0xff);
	bytes[1] = (uint8_t)((value >> 16) & 0xff);
	bytes[2] = (uint8_t)((value >> 8) & 0xff);
	bytes[3] = (uint8_t)(value & 0xff);
}

static inline void
put_u64(void *pointer, uint64_t value)
{
	uint8_t *bytes = (uint8_t *)pointer;

	bytes[0] = (uint8_t)((value >> 56) & 0xff);
	bytes[1] = (uint8_t)((value >> 48) & 0xff);
	bytes[2] = (uint8_t)((value >> 40) & 0xff);
	bytes[3] = (uint8_t)((value >> 32) & 0xff);
	bytes[4] = (uint8_t)((value >> 24) & 0xff);
	bytes[5] = (uint8_t)((value >> 16) & 0xff);
	bytes[6] = (uint8_t)((value >> 8) & 0xff);
	bytes[7] = (uint8_t)(value & 0xff);
}

static inline void
put_u32_le(void *pointer, uint32_t value)
{
	uint8_t *bytes = (uint8_t *)pointer;

	bytes[0] = (uint8_t)(value & 0xff);
	bytes[1] = (uint8_t)((value >> 8) & 0xff);
	bytes[2] = (uint8_t)((value >> 16) & 0xff);
	bytes[3] = (uint8_t)((value >> 24) & 0xff);
}

#endif
