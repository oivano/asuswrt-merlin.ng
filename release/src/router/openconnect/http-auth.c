/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
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
#include <fcntl.h>

#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

static int basic_authorization(struct openconnect_info *vpninfo, int proxy,
			       struct http_auth_state *auth_state,
			       struct oc_text_buf *hdrbuf)
{
	struct oc_text_buf *text;
	const char *user, *pass;

	if (proxy) {
		user = vpninfo->proxy_user;
		pass = vpninfo->proxy_pass;
	} else {
		/* Need to parse this out of the URL */
		return -EINVAL;
	}

	if (!user || !pass)
		return -EINVAL;

	if (auth_state->state == AUTH_IN_PROGRESS) {
		auth_state->state = AUTH_FAILED;
		return -EAGAIN;
	}

	text = buf_alloc();
	buf_append(text, "%s:%s", user, pass);
	if (buf_error(text))
		return buf_free(text);

	buf_append(hdrbuf, "%sAuthorization: Basic ", proxy ? "Proxy-" : "");
	buf_append_base64(hdrbuf, text->data, text->pos, 0);
	buf_append(hdrbuf, "\r\n");

	memset(text->data, 0, text->pos);
	buf_free(text);

	if (proxy)
		vpn_progress(vpninfo, PRG_INFO, _("Attempting HTTP Basic authentication to proxy\n"));
	else
		vpn_progress(vpninfo, PRG_INFO, _("Attempting HTTP Basic authentication to server '%s'\n"),
			     vpninfo->hostname);

	auth_state->state = AUTH_IN_PROGRESS;
	return 0;
}

static int bearer_authorization(struct openconnect_info *vpninfo, int proxy,
			       struct http_auth_state *auth_state,
			       struct oc_text_buf *hdrbuf)
{
	const char *bearer_token = vpninfo->bearer_token;

	if (proxy) {
		return -EINVAL;
	}

	if (!bearer_token)
		return -EINVAL;

	if (auth_state->state == AUTH_IN_PROGRESS) {
		auth_state->state = AUTH_FAILED;
		return -EAGAIN;
	}

	buf_append(hdrbuf, "Authorization: Bearer %s\r\n", bearer_token);

	vpn_progress(vpninfo, PRG_INFO, _("Attempting HTTP Bearer authentication to server '%s'\n"),
				vpninfo->hostname);

	auth_state->state = AUTH_IN_PROGRESS;
	return 0;
}

#if !defined(HAVE_GSSAPI) && !defined(_WIN32)
static int no_gssapi_authorization(struct openconnect_info *vpninfo, int proxy,
				   struct http_auth_state *auth_state,
				   struct oc_text_buf *hdrbuf)
{
	/* This comes last so just complain. We're about to bail. */
	vpn_progress(vpninfo, PRG_ERR,
		     _("This version of OpenConnect was built without GSSAPI support\n"));
	auth_state->state = AUTH_FAILED;
	return -ENOENT;
}
#endif

struct auth_method {
	int state_index;
	const char *name;
	int (*authorization)(struct openconnect_info *, int, struct http_auth_state *, struct oc_text_buf *);
	void (*cleanup)(struct openconnect_info *, struct http_auth_state *);
} auth_methods[] = {
#if defined(HAVE_GSSAPI) || defined(_WIN32)
	{ AUTH_TYPE_GSSAPI, "Negotiate", gssapi_authorization, cleanup_gssapi_auth },
#endif
	{ AUTH_TYPE_NTLM, "NTLM", ntlm_authorization, cleanup_ntlm_auth },
	{ AUTH_TYPE_DIGEST, "Digest", digest_authorization, NULL },
	{ AUTH_TYPE_BASIC, "Basic", basic_authorization, NULL },
	{ AUTH_TYPE_BEARER, "Bearer", bearer_authorization, NULL },
#if !defined(HAVE_GSSAPI) && !defined(_WIN32)
	{ AUTH_TYPE_GSSAPI, "Negotiate", no_gssapi_authorization, NULL }
#endif
};

/* Generate Proxy-Authorization: header for request if appropriate */
int gen_authorization_hdr(struct openconnect_info *vpninfo, int proxy,
			  struct oc_text_buf *buf)
{
	int ret;
	int i;

	for (i = 0; i < ARRAY_SIZE(auth_methods); i++) {
		struct http_auth_state *auth_state;
		if (proxy)
			auth_state = &vpninfo->proxy_auth[auth_methods[i].state_index];
		else
			auth_state = &vpninfo->http_auth[auth_methods[i].state_index];

		if (auth_state->state == AUTH_DEFAULT_DISABLED) {
			if (proxy)
				vpn_progress(vpninfo, PRG_ERR,
					     _("Proxy requested Basic authentication which is disabled by default\n"));
			else
				vpn_progress(vpninfo, PRG_ERR,
					     _("Server '%s' requested Basic authentication which is disabled by default\n"),
					       vpninfo->hostname);
			auth_state->state = AUTH_FAILED;
			return -EINVAL;
		}


		if (auth_state->state > AUTH_UNSEEN) {
			ret = auth_methods[i].authorization(vpninfo, proxy, auth_state, buf);
			if (ret == -EAGAIN || !ret)
				return ret;
		}
	}
	vpn_progress(vpninfo, PRG_INFO, _("No more authentication methods to try\n"));

	if (vpninfo->retry_on_auth_fail) {
		/* Try again without the X-Support-HTTP-Auth: header */
		vpninfo->try_http_auth = 0;
		return 0;
	}
	return -ENOENT;
}

/* Returns non-zero if it matched */
static int handle_auth_proto(struct openconnect_info *vpninfo,
			     struct http_auth_state *auth_states,
			     struct auth_method *method, char *hdr)
{
	struct http_auth_state *auth = &auth_states[method->state_index];
	int l = strlen(method->name);

	if (auth->state <= AUTH_FAILED)
		return 0;

	if (strncmp(method->name, hdr, l))
		return 0;
	if (hdr[l] != ' ' && hdr[l] != 0)
		return 0;

	if (auth->state == AUTH_UNSEEN)
		auth->state = AUTH_AVAILABLE;

	free(auth->challenge);
	if (hdr[l])
		auth->challenge = strdup(hdr + l + 1);
	else
		auth->challenge = NULL;

	return 1;
}

int proxy_auth_hdrs(struct openconnect_info *vpninfo, char *hdr, char *val)
{
	int i;

	if (!strcasecmp(hdr, "Proxy-Connection") ||
	    !strcasecmp(hdr, "Connection")) {
		if (!strcasecmp(val, "close"))
			vpninfo->proxy_close_during_auth = 1;
		return 0;
	}

	if (strcasecmp(hdr, "Proxy-Authenticate"))
		return 0;

	for (i = 0; i < ARRAY_SIZE(auth_methods); i++) {
		/* Return once we've found a match */
		if (handle_auth_proto(vpninfo, vpninfo->proxy_auth, &auth_methods[i], val))
			return 0;
	}

	return 0;
}

int http_auth_hdrs(struct openconnect_info *vpninfo, char *hdr, char *val)
{
	int i;

	if (!strcasecmp(hdr, "X-HTTP-Auth-Support") &&
	    !strcasecmp(val, "fallback")) {
		vpninfo->retry_on_auth_fail = 1;
		return 0;
	}

	if (strcasecmp(hdr, "WWW-Authenticate"))
		return 0;

	for (i = 0; i < ARRAY_SIZE(auth_methods); i++) {
		/* Return once we've found a match */
		if (handle_auth_proto(vpninfo, vpninfo->http_auth, &auth_methods[i], val))
			return 0;
	}

	return 0;
}

void clear_auth_states(struct openconnect_info *vpninfo,
		       struct http_auth_state *auth_states, int reset)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(auth_methods); i++) {
		struct http_auth_state *auth = &auth_states[auth_methods[i].state_index];

		/* The 'reset' argument is set when we're connected successfully,
		   to fully reset the state to allow another connection to start
		   again. Otherwise, we need to remember which auth methods have
		   been tried and should not be attempted again. */
		if (reset && auth_methods[i].cleanup)
			auth_methods[i].cleanup(vpninfo, auth);

		free(auth->challenge);
		auth->challenge = NULL;
		/* If it *failed* don't try it again even next time */
		if (auth->state <= AUTH_FAILED)
			continue;
		if (reset || auth->state == AUTH_AVAILABLE)
			auth->state = AUTH_UNSEEN;
	}
}

static int set_authmethods(struct openconnect_info *vpninfo, struct http_auth_state *auth_states,
			   const char *methods)
{
	int i, len;
	const char *p;

	for (i = 0; i < ARRAY_SIZE(auth_methods); i++)
		auth_states[auth_methods[i].state_index].state = AUTH_DISABLED;

	while (methods) {
		p = strchr(methods, ',');
		if (p) {
			len = p - methods;
			p++;
		} else
			len = strlen(methods);

		for (i = 0; i < ARRAY_SIZE(auth_methods); i++) {
			if (strprefix_match(methods, len, auth_methods[i].name) ||
			    (auth_methods[i].state_index == AUTH_TYPE_GSSAPI &&
			     strprefix_match(methods, len, "gssapi"))) {
				auth_states[auth_methods[i].state_index].state = AUTH_UNSEEN;
				break;
			}
		}
		methods = p;
	}
	return 0;
}

int openconnect_set_http_auth(struct openconnect_info *vpninfo, const char *methods)
{
	return set_authmethods(vpninfo, vpninfo->http_auth, methods);
}

int openconnect_set_proxy_auth(struct openconnect_info *vpninfo, const char *methods)
{
	return set_authmethods(vpninfo, vpninfo->proxy_auth, methods);
}
