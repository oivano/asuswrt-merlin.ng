/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2016 Intel Corporation.
 * Copyright © 2016-2021 David Woodhouse.
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

#include "openconnect-internal.h"

#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <limits.h>
#include <stdarg.h>

#define BUF_CHUNK_SIZE 4096
#define OC_BUF_MAX ((unsigned)(16*1024*1024))

struct oc_text_buf *buf_alloc(void)
{
	return calloc(1, sizeof(struct oc_text_buf));
}

int buf_error(struct oc_text_buf *buf)
{
	return buf ? buf->error : -ENOMEM;
}


void buf_truncate(struct oc_text_buf *buf)
{
	if (!buf)
		return;

	if (buf->data)
		memset(buf->data, 0, buf->pos);

	buf->pos = 0;
}

int buf_free(struct oc_text_buf *buf)
{
	int error = buf_error(buf);

	if (buf) {
		buf_truncate(buf);
		if (buf->data)
			free(buf->data);
		free(buf);
	}

	return error;
}

int buf_ensure_space(struct oc_text_buf *buf, int len)
{
	unsigned int new_buf_len;

	if (!buf)
		return -ENOMEM;

	new_buf_len = (buf->pos + len + BUF_CHUNK_SIZE - 1) & ~(BUF_CHUNK_SIZE - 1);

	if (new_buf_len <= buf->buf_len)
		return 0;

	if (new_buf_len > OC_BUF_MAX) {
		buf->error = -E2BIG;
		return buf->error;
	} else {
		realloc_inplace(buf->data, new_buf_len);
		if (!buf->data)
			buf->error = -ENOMEM;
		else
			buf->buf_len = new_buf_len;
	}
	return buf->error;
}

void buf_append_bytes(struct oc_text_buf *buf, const void *bytes, int len)
{
	if (!buf || buf->error)
		return;

	if (buf_ensure_space(buf, len + 1))
		return;

	memcpy(buf->data + buf->pos, bytes, len);
	buf->pos += len;
	buf->data[buf->pos] = 0;
}

void  __attribute__ ((format (printf, 2, 3)))
	buf_append(struct oc_text_buf *buf, const char *fmt, ...)
{
	va_list ap;

	if (!buf || buf->error)
		return;

	if (buf_ensure_space(buf, 1))
		return;

	while (1) {
		int max_len = buf->buf_len - buf->pos, ret;

		va_start(ap, fmt);
		ret = vsnprintf(buf->data + buf->pos, max_len, fmt, ap);
		va_end(ap);
		if (ret < 0) {
			buf->error = -EIO;
			break;
		} else if (ret < max_len) {
			buf->pos += ret;
			break;
		} else if (buf_ensure_space(buf, ret))
			break;
	}
}

void buf_append_urlencoded(struct oc_text_buf *buf, const char *str)
{
	while (str && *str) {
		unsigned char c = *str;
		if (c < 0x80 && (isalnum((int)(c)) || c=='-' || c=='_' || c=='.' || c=='~'))
			buf_append_bytes(buf, str, 1);
		else
			buf_append(buf, "%%%02x", c);

		str++;
	}
}

void buf_append_xmlescaped(struct oc_text_buf *buf, const char *str)
{
	while (str && *str) {
		unsigned char c = *str;
		if (c=='<' || c=='>' || c=='&' || c=='"' || c=='\'')
			buf_append(buf, "&#x%02x;", c);
		else
			buf_append_bytes(buf, str, 1);

		str++;
	}
}

void buf_append_be16(struct oc_text_buf *buf, uint16_t val)
{
	unsigned char b[2];

	store_be16(b, val);

	buf_append_bytes(buf, b, 2);
}

void buf_append_be32(struct oc_text_buf *buf, uint32_t val)
{
	unsigned char b[4];

	store_be32(b, val);

	buf_append_bytes(buf, b, 4);
}

void buf_append_le16(struct oc_text_buf *buf, uint16_t val)
{
	unsigned char b[2];

	store_le16(b, val);

	buf_append_bytes(buf, b, 2);
}

void buf_append_hex(struct oc_text_buf *buf, const void *str, unsigned len)
{
	const unsigned char *data = str;
	unsigned i;

	for (i = 0; i < len; i++)
		buf_append(buf, "%02x", (unsigned)data[i]);
}

void buf_append_from_utf16le(struct oc_text_buf *buf, const void *_utf16)
{
	const unsigned char *utf16 = _utf16;
	unsigned char utf8[4];
	int c;

	if (!utf16)
		return;

	while (utf16[0] || utf16[1]) {
		if ((utf16[1] & 0xfc) == 0xd8 && (utf16[3] & 0xfc) == 0xdc) {
			c = ((load_le16(utf16) & 0x3ff) << 10)|
				(load_le16(utf16 + 2) & 0x3ff);
			c += 0x10000;
			utf16 += 4;
		} else {
			c = load_le16(utf16);
			utf16 += 2;
		}

		if (c < 0x80) {
			utf8[0] = c;
			buf_append_bytes(buf, utf8, 1);
		} else if (c < 0x800) {
			utf8[0] = 0xc0 | (c >> 6);
			utf8[1] = 0x80 | (c & 0x3f);
			buf_append_bytes(buf, utf8, 2);
		} else if (c < 0x10000) {
			utf8[0] = 0xe0 | (c >> 12);
			utf8[1] = 0x80 | ((c >> 6) & 0x3f);
			utf8[2] = 0x80 | (c & 0x3f);
			buf_append_bytes(buf, utf8, 3);
		} else {
			utf8[0] = 0xf0 | (c >> 18);
			utf8[1] = 0x80 | ((c >> 12) & 0x3f);
			utf8[2] = 0x80 | ((c >> 6) & 0x3f);
			utf8[3] = 0x80 | (c & 0x3f);
			buf_append_bytes(buf, utf8, 4);
		}
	}
	utf8[0] = 0;
	buf_append_bytes(buf, utf8, 1);
}

int get_utf8char(const char **p)
{
	const char *utf8 = *p;
	unsigned char c;
	int utfchar, nr_extra, min;

	c = *(utf8++);
	if (c < 128) {
		utfchar = c;
		nr_extra = 0;
		min = 0;
	} else if ((c & 0xe0) == 0xc0) {
		utfchar = c & 0x1f;
		nr_extra = 1;
		min = 0x80;
	} else if ((c & 0xf0) == 0xe0) {
		utfchar = c & 0x0f;
		nr_extra = 2;
		min = 0x800;
	} else if ((c & 0xf8) == 0xf0) {
		utfchar = c & 0x07;
		nr_extra = 3;
		min = 0x10000;
	} else {
		return -EILSEQ;
	}

	while (nr_extra--) {
		c = *(utf8++);
		if ((c & 0xc0) != 0x80)
			return -EILSEQ;

		utfchar <<= 6;
		utfchar |= (c & 0x3f);
	}
	if (utfchar > 0x10ffff || utfchar < min)
		return -EILSEQ;

	*p = utf8;
	return utfchar;
}

int buf_append_utf16le(struct oc_text_buf *buf, const char *utf8)
{
	int utfchar, len = 0;

	if (!utf8)
		return 0;

	/* Ick. Now I'm implementing my own UTF8 handling too. Perhaps it's
	   time to bite the bullet and start requiring something like glib? */
	while (*utf8) {
		utfchar = get_utf8char(&utf8);
		if (utfchar < 0) {
			if (buf)
				buf->error = utfchar;
			return utfchar;
		}
		if (!buf)
			continue;

		if (utfchar >= 0x10000) {
			utfchar -= 0x10000;
			if (buf_ensure_space(buf, 4))
				return buf_error(buf);
			store_le16(buf->data + buf->pos, (utfchar >> 10) | 0xd800);
			store_le16(buf->data + buf->pos + 2, (utfchar & 0x3ff) | 0xdc00);
			buf->pos += 4;
			len += 4;
		} else {
			if (buf_ensure_space(buf, 2))
				return buf_error(buf);
			store_le16(buf->data + buf->pos, utfchar);
			buf->pos += 2;
			len += 2;
		}
	}

	/* We were only being used for validation */
	if (!buf)
		return 0;

	/* Ensure UTF16 is NUL-terminated */
	if (buf_ensure_space(buf, 2))
		return buf_error(buf);
	buf->data[buf->pos] = buf->data[buf->pos + 1] = 0;

	return len;
}

/* Ick. Yet another wheel to reinvent. But although we could pull it
   in from OpenSSL, we can't from GnuTLS */

static inline int b64_char(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

void *openconnect_base64_decode(int *ret_len, const char *in)
{
	unsigned char *buf;
	int b[4];
	int len = strlen(in);

	if (len & 3) {
		*ret_len = -EINVAL;
		return NULL;
	}
	len = (len * 3) / 4;
	buf = malloc(len);
	if (!buf) {
		*ret_len = -ENOMEM;
		return NULL;
	}

	len = 0;
	while (*in) {
		if (!in[1] || !in[2] || !in[3])
			goto err;
		b[0] = b64_char(in[0]);
		b[1] = b64_char(in[1]);
		if (b[0] < 0 || b[1] < 0)
			goto err;
		buf[len++] = (b[0] << 2) | (b[1] >> 4);

		if (in[2] == '=') {
			if (in[3] != '=' || in[4] != 0)
				goto err;
			break;
		}
		b[2] = b64_char(in[2]);
		if (b[2] < 0)
			goto err;
		buf[len++] = (b[1] << 4) | (b[2] >> 2);
		if (in[3] == '=') {
			if (in[4] != 0)
				goto err;
			break;
		}
		b[3] = b64_char(in[3]);
		if (b[3] < 0)
			goto err;
		buf[len++] = (b[2] << 6) | b[3];
		in += 4;
	}
	*ret_len = len;
	return buf;

 err:
	free(buf);
	*ret_len = -EINVAL;
	return NULL;
}

static const char b64_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

void buf_append_base64(struct oc_text_buf *buf, const void *bytes, int len,
		       int line_len)
{
	const unsigned char *in = bytes;
	int hibits;

	if (!buf || buf->error)
		return;

	if (len < 0 || line_len < 0 || (line_len & 3)) {
		buf->error = -EINVAL;
		return;
	}

	unsigned int needed = ((len + 2u) / 3) * 4;

	/* Line endings, but not for the last line if it reaches line_len */
	if (line_len && needed)
		needed += (needed - 1) / line_len;
	needed++; /* Allow for the trailing NUL */

	if (needed >= (unsigned)(OC_BUF_MAX - buf->pos)) {
		buf->error = -E2BIG;
		return;
	}

	if (buf_ensure_space(buf, needed))
		return;

#ifdef BUFTEST
	int orig_len = len, orig_pos = buf->pos;
#endif
	int ll = 0;
	while (len > 0) {
		if (line_len) {
			if (ll >= line_len) {
				ll = 0;
				buf->data[buf->pos++] = '\n';
			}
			ll += 4;
		}

		buf->data[buf->pos++] = b64_table[in[0] >> 2];
		hibits = (in[0] << 4) & 0x30;
		if (len == 1) {
			buf->data[buf->pos++] = b64_table[hibits];
			buf->data[buf->pos++] = '=';
			buf->data[buf->pos++] = '=';
			break;
		}
		buf->data[buf->pos++] = b64_table[hibits | (in[1] >> 4)];
		hibits = (in[1] << 2) & 0x3c;
		if (len == 2) {
			buf->data[buf->pos++] = b64_table[hibits];
			buf->data[buf->pos++] = '=';
			break;
		}
		buf->data[buf->pos++] = b64_table[hibits | (in[2] >> 6)];
		buf->data[buf->pos++] = b64_table[in[2] & 0x3f];
		in += 3;
		len -= 3;
	}
#ifdef BUFTEST
	if (buf->pos != orig_pos + needed - 1) {
		printf("Used %d instead of calculated %d for %d bytes at line len %d\n",
		       buf->pos - orig_pos, needed, orig_len, line_len);
		buf->error = -EIO;
	}
#endif
	buf->data[buf->pos] = 0;
}
