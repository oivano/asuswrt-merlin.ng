/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2021 David Woodhouse.
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <config.h>

#include <stdint.h>
#include <stdio.h>
#ifdef _WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif

#define __OPENCONNECT_INTERNAL_H__

/* I always coded as if it worked like this. Now it does. */
#define realloc_inplace(p, size) do {			\
		void *__realloc_old = p;		\
		p = realloc(p, size);			\
		if (size && !p)				\
			free(__realloc_old);		\
	} while (0)

struct oc_packed_uint32_t {
	uint32_t d;
} __attribute__((packed));
struct oc_packed_uint16_t {
	uint16_t d;
} __attribute__((packed));

static inline uint32_t load_be32(const void *_p)
{
	const struct oc_packed_uint32_t *p = _p;
	return ntohl(p->d);
}

static inline uint16_t load_be16(const void *_p)
{
	const struct oc_packed_uint16_t *p = _p;
	return ntohs(p->d);
}

static inline void store_be32(void *_p, uint32_t d)
{
	struct oc_packed_uint32_t *p = _p;
	p->d = htonl(d);
}

static inline void store_be16(void *_p, uint16_t d)
{
	struct oc_packed_uint16_t *p = _p;
	p->d = htons(d);
}

static inline uint32_t load_le32(const void *_p)
{
	const unsigned char *p = _p;
	return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static inline uint16_t load_le16(const void *_p)
{
	const unsigned char *p = _p;
	return p[0] | (p[1] << 8);
}

static inline void store_le16(void *_p, uint16_t d)
{
	unsigned char *p = _p;
	p[0] = d;
	p[1] = d >> 8;
}

static inline void store_le32(void *_p, uint32_t d)
{
	unsigned char *p = _p;
	p[0] = d;
	p[1] = d >> 8;
	p[2] = d >> 16;
	p[3] = d >> 24;
}

struct oc_text_buf {
	char *data;
	int pos;
	int buf_len;
	int error;
};

#define BUFTEST
#include "../textbuf.c"

#define assert(x) do {							\
		if (!(x)) {						\
			fprintf(stderr,					\
			        "assert(%s) failed at line %d\n",	\
			        #x, __LINE__);				\
			exit(1);					\
		}							\
	} while (0)


static char testbytes[OC_BUF_MAX];

int main(void)
{
	struct oc_text_buf *buf = NULL;

	assert(buf_error(buf) == -ENOMEM);

	buf = buf_alloc();
	assert(!buf_error(buf));

	int len = (OC_BUF_MAX - 1) / 4 * 3;
	buf_append_base64(buf, testbytes, len, 0);
	assert(!buf_error(buf));
	assert(buf->pos == OC_BUF_MAX - 4);

	buf_truncate(buf);
	len++;
	buf_append_base64(buf, testbytes, len, 0);
	assert(buf_error(buf) == -E2BIG);

	buf->error = 0;
	buf_append_base64(buf, testbytes, -1, 0);
	assert(buf_error(buf) == -EINVAL);

	buf->error = 0;
	buf_truncate(buf);

	int ll;

	for (ll = 0; ll < 128; ll += 4) {
		for (len = 0; len < 16384; len++) {
			buf_truncate(buf);
			buf_append_base64(buf, testbytes, len, ll);
			assert(!buf_error(buf));
			if (len > 128)
				len += len/2;
		}
	}
	buf_free(buf);
	return 0;
}
