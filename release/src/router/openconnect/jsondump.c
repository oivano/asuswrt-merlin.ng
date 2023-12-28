/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020 David Woodhouse
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

#include "json.h"

#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <inttypes.h>

/*
 * Copyright (C) 2015 Mirko Pasqualetti  All rights reserved.
 * https://github.com/udp/json-parser
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


static void print_buf(struct openconnect_info *vpninfo, int lvl, struct oc_text_buf *buf)
{
	if (!buf_error(buf))
		vpn_progress(vpninfo, lvl, "%s", buf->data);

	buf_truncate(buf);
}

static void print_depth_shift(struct oc_text_buf *buf, int depth)
{
	int j;
	for (j=0; j < depth; j++) {
		buf_append(buf, " ");
	}
}

static void dump_json_value(struct openconnect_info *vpninfo, int lvl,
			    struct oc_text_buf *buf, json_value *value, int depth);

static void dump_json_object(struct openconnect_info *vpninfo, int lvl,
			     struct oc_text_buf *buf, json_value* value, int depth)
{
	int length, x;
	if (value == NULL) {
		return;
	}
	length = value->u.object.length;
	for (x = 0; x < length; x++) {
		print_depth_shift(buf, depth);
		buf_append(buf, "object[%d].name = %s\n", x, value->u.object.values[x].name);
		print_buf(vpninfo, lvl, buf);
		dump_json_value(vpninfo, lvl, buf, value->u.object.values[x].value, depth+1);
	}
}

static void dump_json_array(struct openconnect_info *vpninfo, int lvl,
			    struct oc_text_buf *buf, json_value* value, int depth)
{
	int length, x;
	if (value == NULL) {
		return;
	}
	length = value->u.array.length;
	buf_append(buf, "array\n");
	print_buf(vpninfo, lvl, buf);
	for (x = 0; x < length; x++) {
		dump_json_value(vpninfo, lvl, buf, value->u.array.values[x], depth);
	}
}

static void dump_json_value(struct openconnect_info *vpninfo, int lvl,
			    struct oc_text_buf *buf, json_value *value, int depth)
{
	if (!value)
		return;

	if (value->type != json_object) {
		print_depth_shift(buf, depth);
	}
	switch (value->type) {
	case json_none:
	default:
		buf_append(buf, "none\n");
		break;
	case json_object:
		dump_json_object(vpninfo, lvl, buf, value, depth+1);
		return;
	case json_array:
		dump_json_array(vpninfo, lvl, buf, value, depth+1);
		return;
	case json_integer:
		buf_append(buf, "int: %10" PRId64 "\n", value->u.integer);
		break;
	case json_double:
		buf_append(buf, "double: %f\n", value->u.dbl);
		break;
	case json_string:
		buf_append(buf, "string: %s\n", value->u.string.ptr);
		break;
	case json_boolean:
		buf_append(buf, "bool: %d\n", value->u.boolean);
		break;
	}
	print_buf(vpninfo, lvl, buf);

}

void dump_json(struct openconnect_info *vpninfo, int lvl, json_value *value)
{
	struct oc_text_buf *buf = buf_alloc();
	if (!buf)
		return;

	dump_json_value(vpninfo, lvl, buf, value, 0);
	buf_free(buf);
}
