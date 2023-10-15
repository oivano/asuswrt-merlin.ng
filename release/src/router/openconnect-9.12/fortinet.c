/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020-2021 David Woodhouse, Daniel Lenski
 *
 * Author: David Woodhouse <dwmw2@infradead.org>, Daniel Lenski <dlenski@gmail.com>
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

#include "ppp.h"

#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>

#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

/* clthello/svrhello strings for Fortinet DTLS initialization.
 * NB: C string literals implicitly add a final \0 (which is correct for these).
 */
static const char clthello[] = "GFtype\0clthello\0SVPNCOOKIE"; /* + cookie value + '\0' */
static const char svrhello[] = "GFtype\0svrhello\0handshake"; /* + "ok"/"fail" + '\0' */

void fortinet_common_headers(struct openconnect_info *vpninfo,
			 struct oc_text_buf *buf)
{
	char *orig_ua = vpninfo->useragent;

	/* XX: This is what openfortivpn uses */
	vpninfo->useragent = (char *)"Mozilla/5.0 SV1";
	http_common_headers(vpninfo, buf);
	vpninfo->useragent = orig_ua;

	/* XXX: Openfortivpn additionally sends the following
	 * headers, even with GET requests, which should not be
	 * necessary:

	   buf_append(buf,
		      "Accept: *" "/" "*\r\n"
		      "Accept-Encoding: gzip, deflate, br\r\n"
		      "Pragma: no-cache\r\n"
		      "Cache-Control: no-store, no-cache, must-revalidate\r\n"
		      "If-Modified-Since: Sat, 1 Jan 2000 00:00:00 GMT\r\n"
		      "Content-Type: application/x-www-form-urlencoded\r\n"
		      "Content-Length: 0\r\n");
	*/
}

/* XX: consolidate with gpst.c version (differs only in '&' vs ',' as separator for input) */
static int filter_opts(struct oc_text_buf *buf, const char *query, const char *incexc, int include)
{
	const char query_sep = ',';
	const char *f, *endf, *eq;
	const char *found, *comma;

	for (f = query; *f; f=(*endf) ? endf+1 : endf) {
		endf = strchrnul(f, query_sep);
		eq = strchr(f, '=');
		if (!eq || eq > endf)
			eq = endf;

		for (found = incexc; *found; found=(*comma) ? comma+1 : comma) {
			comma = strchrnul(found, ',');
			if (!strncmp(found, f, MAX(comma-found, eq-f)))
				break;
		}

		if ((include && *found) || (!include && !*found)) {
			if (buf->pos && buf->data[buf->pos-1] != '?' && buf->data[buf->pos-1] != '&')
				buf_append(buf, "&");
			buf_append_bytes(buf, f, (int)(endf-f));
		}
	}
	return buf_error(buf);
}

int fortinet_obtain_cookie(struct openconnect_info *vpninfo)
{
	int ret, ftmpush;
	struct oc_text_buf *req_buf = NULL;
	struct oc_auth_form *form = NULL;
	struct oc_form_opt *opt, *opt2;
	char *resp_buf = NULL, *realm = NULL, *tokeninfo_fields = NULL, *ti;

	req_buf = buf_alloc();
	if (buf_error(req_buf)) {
		ret = buf_error(req_buf);
		goto out;
	}

	ret = do_https_request(vpninfo, "GET", NULL, NULL, &resp_buf, NULL, HTTP_REDIRECT);
	if (ret < 0)
		goto out;

	/* XX: Fortinet's initial 'GET /' normally redirects to /remote/login.
	 * If a valid, non-default "realm" is specified (~= usergroup or authgroup),
	 * it will appear as a query parameter of the resulting URL, and we need to
	 * capture and save it. That is, for example:
	 *   'GET /MyRealmName' will redirect to '/remote/login?realm=MyRealmName'
	 */
	if (vpninfo->urlpath) {
		for (realm = strchr(vpninfo->urlpath, '?'); realm && *++realm; realm=strchr(realm, '&')) {
			if (!strncmp(realm, "realm=", 6)) {
				const char *end = strchrnul(realm+1, '&');
				realm = strndup(realm+6, end-realm-6);
				vpn_progress(vpninfo, PRG_INFO, _("Got login realm '%s'\n"), realm);
				break;
			}
		}
	}

	/* XX: Fortinet HTML forms *seem* like they should be about as easy to follow
	 * as Juniper HTML forms, but some redirects use Javascript EXCLUSIVELY (no
	 * 'Location' header). Also, a failed login returns the misleading HTTP status
	 * "405 Method Not Allowed", rather than 403/401, and HTTP status 401 is used to
	 * signal an HTML-form-based mode of presenting a 2FA challenge.
	 *
	 * So we just build a static form (username and password) to start.
	 */
	form = calloc(1, sizeof(*form));
	if (!form) {
	nomem:
		ret = -ENOMEM;
		goto out;
	}
	form->auth_id = strdup("_login");
	if (!form->auth_id)
		goto nomem;
	opt = form->opts = calloc(1, sizeof(*opt));
	if (!opt)
		goto nomem;
	opt->label = strdup("Username: ");
	opt->name = strdup("username");
	opt->type = OC_FORM_OPT_TEXT;

	opt2 = opt->next = calloc(1, sizeof(*opt2));
	if (!opt2)
		goto nomem;
	opt2->label = strdup("Password: ");
	opt2->name = strdup("credential");
	opt2->type = OC_FORM_OPT_PASSWORD;

	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup("remote/logincheck");

	/* XX: submit form repeatedly until success? */
	for (;;) {
		ret = process_auth_form(vpninfo, form);
		if (ret == OC_FORM_RESULT_CANCELLED || ret < 0)
			goto out;

		/* generate token code if specified */
		ret = do_gen_tokencode(vpninfo, form);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to generate OTP tokencode; disabling token\n"));
			vpninfo->token_bypassed = 1;
			goto out;
		}

		buf_truncate(req_buf);
		append_form_opts(vpninfo, form, req_buf);
		buf_append(req_buf, "&realm=%s", realm ?: ""); /* XX: already URL-escaped */

		if (!tokeninfo_fields) {
			/* "normal" form (fields 'username', 'credential') */
			buf_append(req_buf, "&ajax=1&just_logged_in=1");
		} else {
			/* 2FA form (fields 'username', 'code', and a bunch of values
			 * from the previous response which we mindlessly parrot back)
			 */
			buf_append(req_buf, "&%s", tokeninfo_fields);

			/* But if the server sent 'tokeninfo=ftm_push' AND 'code' was left
			 * blank, then we exclude 'magic' and add 'ftmpush=1', in order to
			 * trigger the appropriate mobile-push-based response. */
			if (ftmpush && (!opt2->_value || !opt2->_value[0])) {
				char *magic = strstr(req_buf->data, "&magic=");
				if (magic)
					req_buf->pos = magic - req_buf->data;
				buf_append(req_buf, "&ftmpush=1");
			}
		}

		if ((ret = buf_error(req_buf)))
		        goto out;

		/* XX: Disable HTTP auth, because Fortinet uses 401 status to indicate HTML-type 2FA challenge */
		int try_http_auth = vpninfo->try_http_auth;
		vpninfo->try_http_auth = 0;
		ret = do_https_request(vpninfo, "POST", "application/x-www-form-urlencoded",
				       req_buf, &resp_buf, NULL, HTTP_BODY_ON_ERROR);
		vpninfo->try_http_auth = try_http_auth;

		/* If we got SVPNCOOKIE, then we're done. */
		struct oc_vpn_option *cookie;
		for (cookie = vpninfo->cookies; cookie; cookie = cookie->next) {
			if (!strcmp(cookie->option, "SVPNCOOKIE")) {
				free(vpninfo->cookie);
				if (asprintf(&vpninfo->cookie, "SVPNCOOKIE=%s", cookie->value) < 0)
					goto nomem;
				ret = 0;
				goto out;
			}
		}

		/* XX: We got 200 status, but no SVPNCOOKIE. tokeninfo-type 2FA? */
		if (ret > 0 &&
		    !strncmp(resp_buf, "ret=", 4) && (ti = strstr(resp_buf, ",tokeninfo="))) {
			const char *prompt;
			struct oc_text_buf *tokeninfo_buf = buf_alloc();
			ftmpush = !strncmp(ti + 11, "ftm_push", 8);

			/* Hide 'username' field */
			opt->type = OC_FORM_OPT_HIDDEN;

			/* Change 'credential' field to 'code'. */
			free(opt2->label);
			free(opt2->_value);
			opt2->_value = NULL;
			opt2->name = strdup("code");
			opt2->label = strdup("Code: ");
			if (!can_gen_tokencode(vpninfo, form, opt2))
				opt2->type = OC_FORM_OPT_TOKEN;
			else
				opt2->type = OC_FORM_OPT_PASSWORD;

			/* Change 'auth_id' to '_challenge'. */
			free(form->auth_id);
			if (!(form->auth_id = strdup("_challenge")))
				goto nomem;

			/* Save a bunch of values to parrot back. 'magic' must be LAST
			 * in order for the 'ftmpush' trick above to work. */
			filter_opts(tokeninfo_buf, resp_buf, "reqid,polid,grp,portal,peer,magic", 1);
			if ((ret = buf_error(tokeninfo_buf)))
				goto out;
			free(tokeninfo_fields);
			tokeninfo_fields = tokeninfo_buf->data;
			tokeninfo_buf->data = NULL;
			buf_free(tokeninfo_buf);

			if ((prompt = strstr(resp_buf, ",chal_msg="))) {
				const char *end = strchrnul(prompt, ',');
				prompt += 10;
				free(form->message);
				form->message = strndup(prompt, end-prompt);
			}
		}
		/* XX: We got 401 response with HTML body. HTML-type 2FA? */
		else if (ret == -EPERM && resp_buf) {
			xmlDocPtr doc = NULL;
			xmlNode *node;
			char *url = internal_get_url(vpninfo);

			if (!url)
				goto nomem;

			/* XX: HTML body should contain a "normal" HTML form with hidden fields
			 * including 'username', 'magic', 'reqid', 'grpid' (similar to the tokeninfo-type
			 * 2FA bove), and a password field named 'credential'.
			 */
			doc = htmlReadMemory(resp_buf, strlen(resp_buf), url, NULL,
					     HTML_PARSE_RECOVER|HTML_PARSE_NOERROR|HTML_PARSE_NOWARNING|HTML_PARSE_NONET);
			free(url);

			node = find_form_node(doc);
			if (node) {
				free_auth_form(form);
				form = parse_form_node(vpninfo, node, NULL, can_gen_tokencode);
				if (!form)
					goto no_html_form;
			} else {
			no_html_form:
				xmlFreeDoc(doc);
				ret = -EINVAL;
				goto out;
			}
		}
		/* XX: We got "405 Method Not Allowed", which is strangely used to indicate invalid credentials */
		else if (ret == -EOPNOTSUPP) {
			free(form->message);
			form->message = strdup(_("Invalid credentials; try again."));
		}
	}

 out:
	free(realm);
	if (resp_buf)
		free(resp_buf);
	if (form)
		free_auth_form(form);
	free(tokeninfo_fields);
	buf_free(req_buf);
	return ret;
}

static int parse_split_routes(struct openconnect_info *vpninfo, xmlNode *split_tunnel_info,
			      struct oc_vpn_option *new_opts, struct oc_ip_info *new_ip_info)
{
	int negate = 0, ret = 0;
	int ip_version = !strcmp((char *)split_tunnel_info->parent->name, "ipv6") ? 6 : 4;
	char *s = NULL, *s2 = NULL;

	if (!xmlnode_get_prop(split_tunnel_info, "negate", &s))
		negate = atoi(s);
	for (xmlNode *x = split_tunnel_info->children; x; x=x->next) {
		if (xmlnode_is_named(x, "addr")) {
			if (!xmlnode_get_prop(x, ip_version == 6 ? "ipv6" : "ip", &s) &&
			    !xmlnode_get_prop(x, ip_version == 6 ? "prefix-len" : "mask", &s2) &&
			    s && s2 && *s && *s2) {
				struct oc_split_include *inc = malloc(sizeof(*inc));
				char *route = NULL;

				if (!inc || asprintf(&route, "%s/%s", s, s2) == -1) {
					free(route);
					free(inc);
					free_optlist(new_opts);
					free_split_routes(new_ip_info);
					ret = -ENOMEM;
					goto out;
				}

				if (negate) {
					vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d exclude route %s\n"), ip_version, route);
					inc->route = add_option_steal(&new_opts, "split-exclude", &route);
					inc->next = new_ip_info->split_excludes;
					new_ip_info->split_excludes = inc;
				} else {
					vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d route %s\n"), ip_version, route);
					inc->route = add_option_steal(&new_opts, "split-include", &route);
					inc->next = new_ip_info->split_includes;
					new_ip_info->split_includes = inc;
				}
				/* XX: static analyzer doesn't realize that add_option_steal will steal route's reference, so... */
				free(route);
			}
		}
	}
 out:
	free(s);
	free(s2);
	return ret;
}

/* Parse this:
<?xml version="1.0" encoding="utf-8"?>
<sslvpn-tunnel ver="2" dtls="1" patch="1">
  <dtls-config heartbeat-interval="10" heartbeat-fail-count="10" heartbeat-idle-timeout="10" client-hello-timeout="10"/>
  <tunnel-method value="ppp"/>
  <tunnel-method value="tun"/>
  <fos platform="FG100E" major="5" minor="06" patch="6" build="1630" branch="1630"/>
  <auth-ses check-src-ip='1' tun-connect-without-reauth='1' tun-user-ses-timeout='240' />
  <client-config save-password="off" keep-alive="on" auto-connect="off"/>
  <ipv4>
    <dns ip="1.1.1.1"/>
    <dns ip="8.8.8.8" domain="foo.com"/>
    <split-dns domains='mydomain1.local,mydomain2.local' dnsserver1='10.10.10.10' dnsserver2='10.10.10.11' />
    <assigned-addr ipv4="172.16.1.1"/>
    <split-tunnel-info>
      <addr ip="10.11.10.10" mask="255.255.255.255"/>
      <addr ip="10.11.1.0" mask="255.255.255.0"/>
    </split-tunnel-info>
    <split-tunnel-info negate="1">
      <addr ip="1.2.3.4" mask="255.255.255.255"/>
    </split-tunnel-info>
  </ipv4>
  <ipv6>
    <assigned-addr ipv6='fdff:ffff::1' prefix-len='120'/>
    <split-tunnel-info>
      <addr ipv6='fdff:ffff::' prefix-len='120'/>
    </split-tunnel-info>
    <split-tunnel-info negate="1">
      <addr ipv6='2011:abcd::' prefix-len='32'/>
    </split-tunnel-info>
  </ipv6>
  <idle-timeout val="3600"/>
  <auth-timeout val="18000"/>
</sslvpn-tunnel>
*/
static int parse_fortinet_xml_config(struct openconnect_info *vpninfo, char *buf, int len)
{
	xmlNode *xml_node, *x;
	xmlDocPtr xml_doc;
	int ret = 0, n_dns = 0;
	char *s = NULL, *s2 = NULL;
	int reconnect_after_drop = -1;
	struct oc_text_buf *domains = NULL;

	if (!buf || !len)
		return -EINVAL;

	xml_doc = xmlReadMemory(buf, len, NULL, NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	if (!xml_doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse Fortinet config XML\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), buf);
		return -EINVAL;
	}

	xml_node = xmlDocGetRootElement(xml_doc);
	if (!xml_node || !xmlnode_is_named(xml_node, "sslvpn-tunnel"))
		return -EINVAL;

	struct oc_vpn_option *new_opts = NULL;
	struct oc_ip_info new_ip_info = {};

	domains = buf_alloc();

	if (vpninfo->dtls_state == DTLS_NOSECRET &&
	    !xmlnode_get_prop(xml_node, "dtls", &s) && atoi(s)) {
		udp_sockaddr(vpninfo, vpninfo->port); /* XX: DTLS always uses same port as TLS? */
		vpn_progress(vpninfo, PRG_INFO, _("DTLS is enabled on port %d\n"), vpninfo->port);
		vpninfo->dtls_state = DTLS_SECRET;
		/* This doesn't mean it actually will; it means that we can at least *try* */
		vpninfo->dtls12 = 1;
	}

	for (xml_node = xml_node->children; xml_node; xml_node=xml_node->next) {
		if (xmlnode_is_named(xml_node, "auth-timeout") && !xmlnode_get_prop(xml_node, "val", &s))
			vpninfo->auth_expiration = time(NULL) + atol(s);
		else if (xmlnode_is_named(xml_node, "idle-timeout") && !xmlnode_get_prop(xml_node, "val", &s)) {
			int sec = vpninfo->idle_timeout = atoi(s);
			vpn_progress(vpninfo, PRG_INFO, _("Idle timeout is %d minutes.\n"), sec/60);
		} else if (xmlnode_is_named(xml_node, "dtls-config") && !xmlnode_get_prop(xml_node, "heartbeat-interval", &s)) {
			int sec = atoi(s);
			if (sec && !vpninfo->dtls_times.dpd)
				vpninfo->dtls_times.dpd = vpninfo->ssl_times.dpd = sec;
		} else if (xmlnode_is_named(xml_node, "auth-ses")) {
			/* These settings were apparently added in v6.2.1 of the Fortigate server,
			 * (see https://docs.fortinet.com/document/fortigate/6.2.1/cli-reference/281620/vpn-ssl-settings)
			 * and seem to control the possibility of reconnecting after a dropped connection.
			 * See discussion at https://gitlab.com/openconnect/openconnect/-/issues/297#note_664686767
			 */
			int check_ip_src = -1, dropped_session_cleanup = -1;
			if (!xmlnode_get_prop(xml_node, "tun-connect-without-reauth", &s)) {
				reconnect_after_drop = atoi(s);
				if (reconnect_after_drop) {
					if (!xmlnode_get_prop(xml_node, "check-src-ip", &s))
						check_ip_src = atoi(s);
					if (!xmlnode_get_prop(xml_node, "tun-user-ses-timeout", &s))
						dropped_session_cleanup = atoi(s);
					vpn_progress(vpninfo, PRG_INFO,
						     _("Server reports that reconnect-after-drop is allowed within %d seconds, %s\n"),
						     dropped_session_cleanup,
						     check_ip_src ? _("but only from the same source IP address") : _("even if source IP address changes"));
				} else
					vpn_progress(vpninfo, PRG_INFO,
						     _("Server reports that reconnect-after-drop is not allowed. OpenConnect will not\n"
						       "be able to reconnect if dead peer is detected. If reconnection DOES work,\n"
						       "please report to <%s>\n"),
						     "openconnect-devel@lists.infradead.org");
			}
		} else if (xmlnode_is_named(xml_node, "fos")) {
			char platform[80], *p = platform, *e = platform + 80;
			if (!xmlnode_get_prop(xml_node, "platform", &s)) {
				p+=snprintf(p, e-p, "%s", s);
				if (!xmlnode_get_prop(xml_node, "major", &s))  p+=snprintf(p, e-p, " v%s", s);
				if (!xmlnode_get_prop(xml_node, "minor", &s))  p+=snprintf(p, e-p, ".%s", s);
				if (!xmlnode_get_prop(xml_node, "patch", &s))  p+=snprintf(p, e-p, ".%s", s);
				if (!xmlnode_get_prop(xml_node, "build", &s))  p+=snprintf(p, e-p, " build %s", s);
				if (!xmlnode_get_prop(xml_node, "branch", &s)) p+=snprintf(p, e-p, " branch %s", s);
				if (!xmlnode_get_prop(xml_node, "mr_num", &s))    snprintf(p, e-p, " mr_num %s", s);
				vpn_progress(vpninfo, PRG_INFO,
					     _("Reported platform is %s\n"), platform);
			}
		} else if (xmlnode_is_named(xml_node, "ipv4")) {
			for (x = xml_node->children; x; x=x->next) {
				if (xmlnode_is_named(x, "assigned-addr") && !xmlnode_get_prop(x, "ipv4", &s)) {
					vpn_progress(vpninfo, PRG_INFO, _("Got Legacy IP address %s\n"), s);
					new_ip_info.addr = add_option_steal(&new_opts, "ipaddr", &s);
				} else if (xmlnode_is_named(x, "dns")) {
					if (!xmlnode_get_prop(x, "domain", &s) && s && *s) {
						vpn_progress(vpninfo, PRG_INFO, _("Got search domain %s\n"), s);
						buf_append(domains, "%s ", s);
					}
					if (!xmlnode_get_prop(x, "ip", &s) && s && *s) {
						vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d DNS server %s\n"), 4, s);
						if (n_dns < 3) new_ip_info.dns[n_dns++] = add_option_steal(&new_opts, "DNS", &s);
					}
				} else if (xmlnode_is_named(x, "split-dns")) {
					int ii;
					if (!xmlnode_get_prop(x, "domains", &s) && s && *s)
						vpn_progress(vpninfo, PRG_ERR, _("WARNING: Got split-DNS domains %s (not yet implemented)\n"), s);
					for (ii=1; ii<10; ii++) {
						char propname[] = "dnsserver0";
						propname[9] = '0' + ii;
						if (!xmlnode_get_prop(x, propname, &s) && s && *s)
							vpn_progress(vpninfo, PRG_ERR, _("WARNING: Got split-DNS server %s (not yet implemented)\n"), s);
						else
							break;
					}
				} else if (xmlnode_is_named(x, "split-tunnel-info")) {
					ret = parse_split_routes(vpninfo, x, new_opts, &new_ip_info);
					if (ret < 0)
						goto out;
				}
			}
		} else if (xmlnode_is_named(xml_node, "ipv6")) {
			for (x = xml_node->children; x; x=x->next) {
				if (xmlnode_is_named(x, "assigned-addr") && !xmlnode_get_prop(x, "ipv6", &s)) {
					if (!xmlnode_get_prop(x, "prefix-len", &s2)) {
						char *a;
						if (asprintf(&a, "%s/%s", s, s2) < 0) {
							ret = -ENOMEM;
							goto out;
						}
						vpn_progress(vpninfo, PRG_INFO, _("Got IPv6 address %s\n"), a);
						if (!vpninfo->disable_ipv6)
							new_ip_info.netmask6 = add_option_steal(&new_opts, "ipaddr6", &a);
						free(a);
					} else {
						vpn_progress(vpninfo, PRG_INFO, _("Got IPv6 address %s\n"), s);
						if (!vpninfo->disable_ipv6)
							new_ip_info.addr6 = add_option_steal(&new_opts, "ipaddr6", &s);
					}
				} else if (xmlnode_is_named(x, "dns")) {
					if (!xmlnode_get_prop(x, "domain", &s) && s && *s) {
						vpn_progress(vpninfo, PRG_INFO, _("Got search domain %s\n"), s);
						buf_append(domains, "%s ", s);
					}
					if (!xmlnode_get_prop(x, "ipv6", &s) && s && *s) {
						vpn_progress(vpninfo, PRG_INFO, _("Got IPv%d DNS server %s\n"), 6, s);
						if (n_dns < 3) new_ip_info.dns[n_dns++] = add_option_steal(&new_opts, "DNS", &s);
					}
				} else if (xmlnode_is_named(x, "split-dns")) {
					int ii;
					if (!xmlnode_get_prop(x, "domains", &s) && s && *s)
						vpn_progress(vpninfo, PRG_ERR, _("WARNING: Got split-DNS domains %s (not yet implemented)\n"), s);
					for (ii=1; ii<10; ii++) {
						char propname[] = "dnsserver0";
						propname[9] = '0' + ii;
						if (!xmlnode_get_prop(x, propname, &s) && s && *s)
							vpn_progress(vpninfo, PRG_ERR, _("WARNING: Got split-DNS server %s (not yet implemented)\n"), s);
						else
							break;
					}
				} else if (xmlnode_is_named(x, "split-tunnel-info")) {
					ret = parse_split_routes(vpninfo, x, new_opts, &new_ip_info);
					if (ret != 0)
						goto out;
				}
			}
		}
	}

	if (reconnect_after_drop < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("WARNING: Fortinet server does not specifically enable or disable reconnection\n"
			       "    without reauthentication. If automatic reconnection does work, please\n"
			       "    report results to <%s>\n"),
			     "openconnect-devel@lists.infradead.org");
	}

	if (reconnect_after_drop == -1)
		vpn_progress(vpninfo, PRG_ERR,
			     _("Server did not send <auth-ses tun-connect-without-reauth=\"0/1\"/>. OpenConnect will\n"
			       "probably not be able to reconnect if dead peer is detected. If reconnection DOES,\n"
			       "work please report to <%s>\n"),
			     "openconnect-devel@lists.infradead.org");

	if (new_ip_info.addr) {
		if (new_ip_info.split_includes)
			vpn_progress(vpninfo, PRG_INFO, _("Received split routes; not setting default Legacy IP route\n"));
		else {
			vpn_progress(vpninfo, PRG_INFO, _("No split routes received; setting default Legacy IP route\n"));
			new_ip_info.netmask = add_option_dup(&new_opts, "full-netmask", "0.0.0.0", -1);
		}
	}
	if (buf_error(domains) == 0 && domains->pos > 0) {
		domains->data[domains->pos-1] = '\0';
		new_ip_info.domain = add_option_steal(&new_opts, "search", &domains->data);
	}

	ret = install_vpn_opts(vpninfo, new_opts, &new_ip_info);
	if (ret) {
		free_optlist(new_opts);
                free_split_routes(&new_ip_info);

		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to find VPN options\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), buf);
	}
 out:
	xmlFreeDoc(xml_doc);
	buf_free(domains);
	free(s);
	free(s2);

	return ret;
}

static int fortinet_configure(struct openconnect_info *vpninfo)
{
	char *res_buf = NULL;
	struct oc_text_buf *reqbuf = NULL;
	struct oc_vpn_option *svpncookie = NULL;
	int ret;

	/* XXX: We should use check_address_sanity to verify that addresses haven't
	   changed on a reconnect, except that:

	   1) We haven't yet been able to test fully on a Fortinet
	      server that actually allows reconnects
	   2) The evidence we do have suggests that Fortinet servers which *do* allow
	      reconnects nevertheless *do not* allow us to redo the configuration requests
	      without invalidating the cookie. So reconnects *must* use only ppp_reset(),
	      rather than calling fortinet_configure(), to redo the PPP tunnel setup. See
	      https://gitlab.com/openconnect/openconnect/-/issues/235#note_552995833
	*/

	if (!vpninfo->cookies) {
		/* XX: This will happen if authentication was separate/external */
		ret = internal_split_cookies(vpninfo, 1, "SVPNCOOKIE");
		if (ret)
			return ret;
	}

	/* Fetch the connection options in XML format */
	free(vpninfo->urlpath);
	if (asprintf(&vpninfo->urlpath, "remote/fortisslvpn_xml%s", vpninfo->disable_ipv6 ? "" : "?dual_stack=1") < 0) {
		ret = -ENOMEM;
		goto out;
	}
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, NULL, HTTP_NO_FLAGS);
	if (ret < 0) {
		if (ret == -EPERM) {
			/* XXX: Forticlient and Openfortivpn fetch the legacy HTTP configuration.
			 * FortiOS 4 was the last version to send the legacy HTTP configuration.
			 * FortiOS 5 and later send the current XML configuration.
			 * We clearly do not need to support FortiOS 4 anymore.
			 *
			 * Yet we keep this code around in order to get a sanity check about
			 * whether the SVPNCOOKIE is still valid/alive, until we are sure we've
			 * worked out the weirdness with reconnects.
			 */
			free(vpninfo->urlpath);
			vpninfo->urlpath = strdup("remote/fortisslvpn");
			int ret2 = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, NULL, HTTP_NO_FLAGS);
			if (ret2 > 0)
				vpn_progress(vpninfo, PRG_ERR,
					     _("Ancient Fortinet server (<v5?) only supports ancient HTML config, which is not implemented by OpenConnect.\n"));
			else
				vpn_progress(vpninfo, PRG_ERR,
					     _("Fortinet server is rejecting request for connection options. This\n"
					       "has been observed after reconnection in some cases. Please report to\n"
					       "<%s>, or see the discussions on\n"
					       "%s and\n"
					       "%s.\n"),
					     "openconnect-devel@lists.infradead.org",
					     "https://gitlab.com/openconnect/openconnect/-/issues/297",
					     "https://gitlab.com/openconnect/openconnect/-/issues/298");
		}
		goto out;
	} else if (ret == 0) {
		/* A redirect to /remote/login also indicates that the auth session/cookie
		 * is no longer valid, and appears to occur only on older FortiGate
		 * versions.
		 *
		 * XX: See do_https_request() for why ret==0 can only happen
		 * if there was a successful-but-unfetched redirect.
		 */
		if (vpninfo->urlpath && !strncmp(vpninfo->urlpath, "remote/login", 12))
			ret = -EPERM;
		else
			ret = -EINVAL;
		goto out;
	}

	ret = parse_fortinet_xml_config(vpninfo, res_buf, ret);
	if (ret)
		goto out;

	/* Build TLS connection request (looks like HTTP GET, but acts as HTTP CONNECT) */
	reqbuf = vpninfo->ppp_tls_connect_req;
	if (!reqbuf)
		reqbuf = buf_alloc();
	buf_truncate(reqbuf);
	buf_append(reqbuf, "GET /remote/sslvpn-tunnel HTTP/1.1\r\n");
	fortinet_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "\r\n");
	if ((ret = buf_error(reqbuf))) {
	buf_err:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error establishing Fortinet connection\n"));
		goto out;
	}
	vpninfo->ppp_tls_connect_req = reqbuf;
	reqbuf = NULL;

	/* Build DTLS connection request (bespoke Fortinet format) */
	reqbuf = vpninfo->ppp_dtls_connect_req;
	if (!reqbuf)
		reqbuf = buf_alloc();
	buf_truncate(reqbuf);
	for (svpncookie = vpninfo->cookies; svpncookie; svpncookie = svpncookie->next)
		if (!strcmp(svpncookie->option, "SVPNCOOKIE") && svpncookie->value)
			break;
	if (!svpncookie) {
		vpn_progress(vpninfo, PRG_ERR, _("No cookie named SVPNCOOKIE.\n"));
		ret = -EINVAL;
		goto out;
	}
	buf_append_be16(reqbuf, 2 + sizeof(clthello) + strlen(svpncookie->value) + 1); /* length */
	buf_append_bytes(reqbuf, clthello, sizeof(clthello));
	buf_append(reqbuf, "%s%c", svpncookie->value, 0);
	if ((ret = buf_error(reqbuf)))
		goto buf_err;
	vpninfo->ppp_dtls_connect_req = reqbuf;
	reqbuf = NULL;

	int ipv4 = !!vpninfo->ip_info.addr;
	int ipv6 = !!(vpninfo->ip_info.addr6 || vpninfo->ip_info.netmask6);
	ret = openconnect_ppp_new(vpninfo, PPP_ENCAP_FORTINET, ipv4, ipv6);

 out:
	buf_free(reqbuf);
	free(res_buf);

	return ret;
}

int fortinet_connect(struct openconnect_info *vpninfo)
{
	int ret = 0;

	ret = fortinet_configure(vpninfo);
	if (ret) {
	err:
		openconnect_close_https(vpninfo, 0);
		return ret;
	}

	ret = ppp_tcp_should_connect(vpninfo);
	if (ret <= 0)
		goto err;

	/* XX: Openfortivpn closes and reopens the HTTPS connection here, and
	 * also sends 'Host: sslvpn' (rather than the true hostname). Neither
	 * appears to be necessary, and either might prevent connecting to
	 * a vhost-based Fortinet server.
	 */
	ret = openconnect_open_https(vpninfo);
	if (ret)
		goto err;

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', vpninfo->ppp_tls_connect_req->data);
	ret = vpninfo->ssl_write(vpninfo, vpninfo->ppp_tls_connect_req->data,
				 vpninfo->ppp_tls_connect_req->pos);
	if (ret < 0) {
		openconnect_close_https(vpninfo, 0);
		goto err;
	}

	/* XX: If this connection request succeeds, no HTTP response appears.
	 * We just start sending our encapsulated PPP configuration packets.
	 * However, if the request FAILS, it WILL send an HTTP response.
	 * We handle that in the PPP mainloop.
	 *
	 * Don't blame me. I didn't design this.
	 */
	vpninfo->ppp->check_http_response = 1;

	/* Trigger the first PPP negotiations and ensure the PPP state
	 * is PPPS_ESTABLISH so that ppp_tcp_mainloop() knows we've started. */
	ppp_start_tcp_mainloop(vpninfo);

	/* XX: Some Fortinet servers can't cope with reconnect, which means
	 * there's absolutely no point in trying to opportunistically do
	 * DTLS after this point. Can we detect that, and disable DTLS?
	 * I think it's relatively harmless because the auth packet over
	 * DTLS will fail anyway, so we'll never make it past DTLS_CONNECTED
	 * to DTLS_ESTABLISHED and never give up on the existing TCP link
	 * but it's still a waste of time and resources trying to do it
	 * at all. */

	monitor_fd_new(vpninfo, ssl);
	monitor_read_fd(vpninfo, ssl);
	monitor_except_fd(vpninfo, ssl);

	return 0;
}

int fortinet_dtls_catch_svrhello(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	char *const buf = (void *)pkt->data;
	const int len = pkt->len;

	buf[len] = 0;

	if (load_be16(buf) != len || len < sizeof(svrhello) + 2 ||
	    memcmp(buf + 2, svrhello, sizeof(svrhello))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Did not receive expected svrhello response.\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)buf, len);
	disable:
		dtls_close(vpninfo);
		vpninfo->dtls_state = DTLS_DISABLED;
		return -EINVAL;
	}

	if (strncmp("ok", buf + 2 + sizeof(svrhello),
		    len - 2 - sizeof(svrhello))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("svrhello status was \"%.*s\" rather than \"ok\"\n"),
			     (int)(len - 2 - sizeof(svrhello)),
			     buf + 2 + sizeof(svrhello));
		goto disable;
	}

	/* XX: The 'ok' packet might get dropped, and the server won't resend
	 * it when we resend the GET request. What will happen in that case
	 * is it'll just keep sending PPP frames. If we detect a PPP frame
	 * we should take that as 'success' too. Bonus points for actually
	 * feeding it to the PPP code to process too, but dropping it *ought*
	 * to be OK. */

	return 1;
}

int fortinet_bye(struct openconnect_info *vpninfo, const char *reason)
{
	char *orig_path;
	char *res_buf=NULL;
	int ret;

	/* XX: handle clean PPP termination?
	   ppp_bye(vpninfo); */

	/* We need to close and reopen the HTTPS connection (to kill
	 * the fortinet tunnel) and submit a new HTTPS request to logout.
	 */
	openconnect_close_https(vpninfo, 0);

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup("remote/logout");
	ret = do_https_request(vpninfo, "GET", NULL, NULL, &res_buf, NULL, HTTP_NO_FLAGS);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;

	if (ret < 0)
		vpn_progress(vpninfo, PRG_ERR, _("Logout failed.\n"));
	else
		vpn_progress(vpninfo, PRG_INFO, _("Logout successful.\n"));

	free(res_buf);
	return ret;
}
