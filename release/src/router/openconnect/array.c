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

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#ifdef _WIN32
#include "win32-ipicmp.h"
#else
/* The BSDs require the first two headers before netinet/ip.h
 * (Linux and macOS already #include them within netinet/ip.h)
 */
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#endif

#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

static struct oc_auth_form *plain_auth_form(void)
{
	struct oc_auth_form *form;
	struct oc_form_opt *opt, *opt2, *opt3;

	form = calloc(1, sizeof(*form));
	if (!form) {
	nomem:
		free_auth_form(form);
		return NULL;
	}
	form->auth_id = strdup("form");
	opt = form->opts = calloc(1, sizeof(*opt));
	if (!opt)
		goto nomem;
	opt->label = strdup("authgroup:");
	opt->name = strdup("method");
	opt->type = OC_FORM_OPT_TEXT;

	opt2 = opt->next = calloc(1, sizeof(*opt2));
	if (!opt2)
		goto nomem;
	opt2->label = strdup("username:");
	opt2->name = strdup("uname");
	opt2->type = OC_FORM_OPT_TEXT;

	opt3 = opt2->next = calloc(1, sizeof(*opt3));
	if (!opt3)
		goto nomem;
	opt3->label = strdup("password:");
	opt3->name = strdup("pwd");
	opt3->type = OC_FORM_OPT_PASSWORD;
	return form;
}

int array_obtain_cookie(struct openconnect_info *vpninfo)
{
	struct oc_auth_form *form = plain_auth_form();
	if (!form)
		return -ENOMEM;

	struct oc_text_buf *req_buf = buf_alloc();
	int ret;
	if ((ret = buf_error(req_buf)))
		goto out;

	do {
		ret = process_auth_form(vpninfo, form);
	} while (ret == OC_FORM_RESULT_NEWGROUP);
	if (ret)
		goto out;

	append_form_opts(vpninfo, form, req_buf);
	if ((ret = buf_error(req_buf)))
		goto out;

	free(vpninfo->urlpath);
	vpninfo->urlpath = strdup("prx/000/http/localhost/login");
	if (!vpninfo->urlpath) {
		ret = -ENOMEM;
		goto out;
	}

	char *resp_buf = NULL;
	ret = do_https_request(vpninfo, "POST",
			       "application/x-www-form-urlencoded",
			       req_buf, &resp_buf, NULL, HTTP_REDIRECT_TO_GET);
	free(resp_buf);
	if (ret <= 0)
		goto out;

	struct oc_vpn_option *cookie;
	for (cookie = vpninfo->cookies; cookie; cookie = cookie->next) {
		if (!strncmp(cookie->option, "ANsession", 9)) {
			free(vpninfo->cookie);
			if (asprintf(&vpninfo->cookie, "%s=%s", cookie->option, cookie->value) <= 0)
				return -ENOMEM;
			ret = 0;
			goto out;
		}
	}
	vpn_progress(vpninfo, PRG_INFO, _("No ANsession cookie found\n"));
	ret = -EPERM;

 out:
	if (form) free_auth_form(form);
	if (req_buf) buf_free(req_buf);
	printf("obtain return %d\n", ret);
	return ret;
}

/* XXX: Lifted from oncp.c. Share it. */
static int parse_cookie(struct openconnect_info *vpninfo)
{
	char *p = vpninfo->cookie;

	/* We currently expect the "cookie" to contain multiple cookies:
	 * DSSignInUrl=/; DSID=xxx; DSFirstAccess=xxx; DSLastAccess=xxx
	 * Process those into vpninfo->cookies unless we already had them
	 * (in which case they may be newer). */
	while (p && *p) {
		char *semicolon = strchr(p, ';');
		char *equals;

		if (semicolon)
			*semicolon = 0;

		equals = strchr(p, '=');
		if (!equals) {
			vpn_progress(vpninfo, PRG_ERR, _("Invalid cookie '%s'\n"), p);
			return -EINVAL;
		}
		*equals = 0;
		http_add_cookie(vpninfo, p, equals+1, 0);
		*equals = '=';

		p = semicolon;
		if (p) {
			*p = ';';
			p++;
			while (*p && isspace((int)(unsigned char)*p))
				p++;
		}
	}

	return 0;
}

/* No idea what these structures are yet... */
static const unsigned char conf50[] = { 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const unsigned char conf54[] = { 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
					0x01, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x02, 0x0f,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x52, 0x54, 0x00, 0xde, 0xa2, 0xa6, 0x00, 0x00 };

static const unsigned char ipff[] = { 0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
				      0x00, 0xff, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
				      0x00, 0x00, 0x00, 0x00 };

static const struct pkt dpd_pkt = {
	.next = NULL,
	.data =  { 0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		   0x00, 0x00, 0x00, 0x00 },
	.len = 20,
};

static const struct pkt nodtls_pkt = {
	.next = NULL,
	.data =  { 0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00,
		   0x00, 0xff, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
		   0x00, 0x00, 0x00, 0x00 },
	.len = 20,
};


static int parse_one_inc_exc(struct openconnect_info *vpninfo, struct oc_vpn_option **opts,
			     struct oc_ip_info *ip_info, int incl, int ipv6, json_value *val)
{
	if (val->type != json_object) {
		vpn_progress(vpninfo, PRG_ERR, "Include not object\n");
		return -EINVAL;
	}

	/* We have no idea how they expose IPv6 yet. Hopefully not
	   as wrong-endian integers like Legacy IP! */
	if (ipv6)
		return 0;

	uint32_t route_ip = 0, route_mask = 0;
	int route_ip_found = 0, route_mask_found = 0;

	for (int i = 0; i < val->u.object.length; i++) {
		json_char *child_name = val->u.object.values[i].name;
		json_value *child_val = val->u.object.values[i].value;

		if (child_val->type != json_integer)
			continue;

		if (!strcmp(child_name, "ip")) {
			store_le32(&route_ip, child_val->u.integer);
			route_ip_found = 1;
		} else if (!strcmp(child_name, "mask")) {
			store_le32(&route_mask, child_val->u.integer);
			route_mask_found = 1;
		}
	}
	if (route_ip_found && route_mask_found) {
		char buf[64];
		if (!inet_ntop(AF_INET, &route_ip, buf, sizeof(buf)/2))
			return -errno;
		char *p = buf + strlen(buf);
		*(p++) = '/';
		if (!inet_ntop(AF_INET, &route_mask, p, sizeof(buf) - (p - buf)))
			return -errno;

		vpn_progress(vpninfo, PRG_INFO, "Found split route %s\n", buf);

		struct oc_split_include *inc = malloc(sizeof (*inc));
		if (!inc)
			return -ENOMEM;

		struct oc_split_include **list;
		if (incl)
			list = &ip_info->split_includes;
		else
			list = &ip_info->split_excludes;

		inc->route = add_option_dup(opts, "split-include", buf, -1);
		inc->next = *list;
		*list = inc;
	}

	return 0;
}

static int parse_network_inc_exc(struct openconnect_info *vpninfo, struct oc_vpn_option **opts,
				 struct oc_ip_info *ip_info, int incl, json_value *val)
{
	int ret = 0;

	if (val->type != json_object) {
		vpn_progress(vpninfo, PRG_ERR, "Includes not object\n");
		return -EINVAL;
	}

	for (int i = 0; i < val->u.object.length; i++) {
		json_char *child_name = val->u.object.values[i].name;
		json_value *child_val = val->u.object.values[i].value;
		int is_ipv6;

		if (child_val->type != json_array)
			continue;

		if (!strcmp(child_name, "ipv6"))
			is_ipv6 = 1;
		else if (!strcmp(child_name, "ipv4"))
			is_ipv6 = 0;
		else
			continue;

		for (int j = 0; j < child_val->u.array.length; j++) {
			ret = parse_one_inc_exc(vpninfo, opts, ip_info, incl, is_ipv6,
						child_val->u.array.values[j]);
			if (ret)
				goto out;
		}
	}
 out:
	return ret;
}

static int parse_proxy_script(struct openconnect_info *vpninfo, struct oc_vpn_option **opts,
			      struct oc_ip_info *ip_info, json_value *val)
{
	return 0;
}

static int parse_dns_servers(struct openconnect_info *vpninfo, struct oc_vpn_option **opts,
			     struct oc_ip_info *ip_info, json_value *val)
{
	int servers_found = 0;

	if (val->type != json_array)
		return -EINVAL;
	/*
	 * The 'dns_servers' object is an array, containing object[s] with
	 * children named 'ipv4' and, presumably, 'ipv6'. Each of those is
	 * *itself* an array. It isn't clear why we need an array of arrays.
	 * Nor why IPv6 and Legacy IP need to be separate at all.
	 *
	 * "dns_servers": [{
	 *			"ipv4":	[67373064, 134744072]
	 *		  }],
	*/
	for (int i = 0; i < val->u.array.length; i++) {
		json_value *elem1 = val->u.array.values[i];

		if (elem1->type != json_object)
			continue;

		for (int j = 0; j < elem1->u.object.length; j++) {
			json_char *child_name = elem1->u.object.values[j].name;
			json_value *child_val = elem1->u.object.values[j].value;

			if (child_val->type != json_array)
				continue;

			int legacyip;

			if (!strcmp(child_name, "ipv4"))
				legacyip = 1;
			else if (!strcmp(child_name, "ipv6"))
				legacyip = 0;
			else
				continue;

			for (int k = 0; k < child_val->u.array.length; k++) {
				json_value *elem2 = child_val->u.array.values[k];
				char buf[32];
				const char *server = buf;

				if (legacyip && elem2->type == json_integer) {
					uint32_t addr;
					store_le32(&addr, elem2->u.integer);
					if (!inet_ntop(AF_INET, &addr, buf, sizeof(buf)))
						return -errno;
				} else if (!legacyip && elem2->type == json_string) {
					server = elem2->u.string.ptr;
				} else continue;

				vpn_progress(vpninfo, PRG_INFO, _("Found DNS server %s\n"), server);

				if (servers_found < 3 &&
				    (ip_info->dns[servers_found] =
				     add_option_dup(opts, "DNS", server, -1)))
					servers_found++;
			}
		}
	}

	return 0;
}

static int parse_search_domains(struct openconnect_info *vpninfo, struct oc_vpn_option **opts,
				struct oc_ip_info *ip_info, json_value *val)
{
	if (val->type != json_array)
		return -EINVAL;

	struct oc_text_buf *domains = buf_alloc();

	for (int i = 0; i < val->u.array.length; i++) {
		json_value *elem = val->u.array.values[i];

		if (elem->type != json_string)
			continue;

		vpn_progress(vpninfo, PRG_INFO, _("Got search domain '%s'\n"),
			     elem->u.string.ptr);

		buf_append(domains, "%s ", elem->u.string.ptr);
	}

	if (buf_error(domains))
		return buf_free(domains);

	if (domains->pos) {
		domains->data[domains->pos - 1] = '\0';
		ip_info->domain = add_option_steal(opts, "search", &domains->data);
	}

	buf_free(domains);
	return 0;
}

static int parse_interface_info(struct openconnect_info *vpninfo,
				json_value *val)
{
	struct oc_vpn_option *new_opts = NULL;
	struct oc_ip_info new_ip_info = {};
	int i, ret = 0;

	if (val->type != json_object)
		return -EINVAL;

	for (i = 0; i < val->u.object.length; i++) {
		json_char *child_name = val->u.object.values[i].name;
		json_value *child_val = val->u.object.values[i].value;

		if (child_val->type == json_integer) {
			json_int_t ival = child_val->u.integer;

			/* The Array server gives us Legacy IP addresses as
			 * decimal integers, in wrong-endian form. So an IP
			 * address of e.g. 1.2.3.4 is presented as 0x04030201
			 * or "client_ipv4: 67305985" in the JSON response.
			 * Obviously, integers represented as decimal strings
			 * don't have an endianness on the wire per se; this
			 * is only "wrong" endian. So... since the address in
			 * struct in_addr is supposed to be stored in network
			 * (big) endian form, we need to store the
			 * wrong-endian integer as *little* endian in order
			 * end up with the correct result. */

			if (!strcmp(child_name, "client_ipv4")) {
				uint32_t ip;
				store_le32(&ip, ival);
				new_ip_info.addr = add_option_ipaddr(&new_opts,
								     "client_ipv4",
								     AF_INET, &ip);
				printf("Found Legacy IP address %s\n", new_ip_info.addr);
			} else if (!strcmp(child_name, "client_ipv4_mask")) {
				uint32_t mask;
				store_le32(&mask, ival);
				new_ip_info.netmask = add_option_ipaddr(&new_opts,
									"client_ipv4_mask",
									AF_INET, &mask);
				printf("Found Legacy IP netmask %s\n", new_ip_info.netmask);
			}
			else goto unknown;
		} else if (child_val->type == json_object) {
			if (!strcmp(child_name, "include_network_resource")) {
				ret = parse_network_inc_exc(vpninfo, &new_opts, &new_ip_info,
							    1, child_val);
			} else if (!strcmp(child_name, "exclude_network_resource")) {
				ret = parse_network_inc_exc(vpninfo, &new_opts, &new_ip_info,
							    0, child_val);
			} else if (!strcmp(child_name, "proxy_script")) {
				ret = parse_proxy_script(vpninfo, &new_opts, &new_ip_info,
							 child_val);
			}
			else goto unknown;
		} else if (child_val->type == json_array) {
			if (!strcmp(child_name, "dns_servers")) {
				ret = parse_dns_servers(vpninfo, &new_opts, &new_ip_info,
							child_val);
			} else if (!strcmp(child_name, "search_domains")) {
				ret = parse_search_domains(vpninfo, &new_opts, &new_ip_info,
							   child_val);
			}
			else goto unknown;
		} else {
		unknown:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Unknown Array config element '%s'\n"),
				     child_name);
		}
		if (ret)
			goto out;
	}

	if (!ret)
		ret = install_vpn_opts(vpninfo, new_opts, &new_ip_info);
 out:
	if (ret) {
		free_optlist(new_opts);
		free_split_routes(&new_ip_info);
	}
	return ret;
}

static int parse_speed_tunnel(struct openconnect_info *vpninfo,
			      json_value *val)
{
	int speed_tunnel = 0, speed_tunnel_enc = 0, dpd = 0;
	int i;
	for (i = 0; i < val->u.object.length; i++) {
		json_char *child_name = val->u.object.values[i].name;
		json_value *child_val = val->u.object.values[i].value;

		if (child_val->type == json_integer) {
			json_int_t ival = child_val->u.integer;

			if (!strcmp(child_name, "allow_speed_tunnel"))
				speed_tunnel = ival;
			else if (!strcmp(child_name, "speed_tunnel_encryption"))
				speed_tunnel_enc = ival;
			else if (!strcmp(child_name, "keepalive_interval"))
				dpd = ival;
		}
	}

	vpn_progress(vpninfo, PRG_INFO,
		     _("Initial config: Speed tunnel %d, enc %d, DPD %d\n"),
		     speed_tunnel, speed_tunnel_enc, dpd);

	if (!speed_tunnel)
		vpninfo->dtls_state = DTLS_DISABLED;

	/* We don't support DPD yet...*/
	if (dpd) {
		if (!vpninfo->ssl_times.dpd)
			vpninfo->ssl_times.dpd = dpd;
		if (!vpninfo->dtls_times.dpd)
			vpninfo->dtls_times.dpd = dpd;
	}

	return 0;
}

static int do_json_request(struct openconnect_info *vpninfo, void *req, int reqlen,
			   int (*rq_parser)(struct openconnect_info *vpninfo,
					    json_value *val))
{
	unsigned char bytes[16384];
	int ret;

	if (vpninfo->dump_http_traffic)
		dump_buf_hex(vpninfo, PRG_DEBUG, '>', req, reqlen);

	ret = vpninfo->ssl_write(vpninfo, req, reqlen);
	if (ret != reqlen) {
		if (ret >= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Short write in Array JSON negotiation\n"));
			return -EIO;
		}
		return ret;
	}

	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to read Array JSON response\n"));
		return ret;
	}

	if (vpninfo->dump_http_traffic)
		dump_buf_hex(vpninfo, PRG_DEBUG, '<', bytes, ret);

	if (ret <= 16 || bytes[16] != '{') {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected response to Array JSON request\n"));
		return -EINVAL;
	}

	dump_buf(vpninfo, '<', (char *)bytes + 16);

	json_settings settings = { 0 };
	char json_err[json_error_max];

	json_value *val = json_parse_ex(&settings, (json_char *)bytes + 16, ret - 16, json_err);
	if (!val) {
	eparse:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse Array JSON response\n"));
		return -EINVAL;
	}

	if (vpninfo->verbose >= PRG_DEBUG)
		dump_json(vpninfo, PRG_DEBUG, val);

	if (val->type != json_object) {
		json_value_free(val);
		goto eparse;
	}

	ret = rq_parser(vpninfo, val);

	json_value_free(val);

	return ret;
}


int array_connect(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *reqbuf;
	unsigned char bytes[65536];

	if (!vpninfo->cookies) {
		ret = parse_cookie(vpninfo);
		if (ret)
			return ret;
	}

	/* We abuse ppp_tls_connect_req for the random client-id */
	if (!vpninfo->ppp_tls_connect_req) {
		unsigned char bin[16];

		ret = openconnect_random(bin, sizeof(bin));
		if (ret)
			return ret;

		struct oc_text_buf *buf = buf_alloc();
		buf_append(buf, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
			   bin[0], bin[1], bin[2], bin[3], bin[4], bin[5], bin[6], bin[7],
			   bin[8], bin[9], bin[10], bin[11], bin[12], bin[13], bin[14], bin[15]);
		if (buf_error(buf))
			return buf_free(buf);

		vpninfo->ppp_tls_connect_req = buf;

		/* Now build the request we actually send over DTLS, which
		 * must have "13" following the client-id. Without that at
		 * the end, we can send over DTLS but the worker process
		 * seems to crash as soon as it needs to send us anything
		 * more than a keepalive response. */
		buf = buf_alloc();
		buf_append(buf, "%s13", vpninfo->ppp_tls_connect_req->data);
		if (buf_error(buf))
			return buf_free(buf);

		vpninfo->ppp_dtls_connect_req = buf;
	}

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();

	buf_append(reqbuf, "GET /vpntunnel HTTP/1.1\r\n");
	http_common_headers(vpninfo, reqbuf);
	buf_append(reqbuf, "appid: SSPVPN\r\n");
	buf_append(reqbuf, "clientid: %s\r\n", vpninfo->ppp_tls_connect_req->data);
	buf_append(reqbuf, "cpuid: %s\r\n", vpninfo->ppp_tls_connect_req->data);
	buf_append(reqbuf, "hostname: %s\r\n", vpninfo->localname);
	buf_append(reqbuf, "payload-ip-version: 6\r\n");
	buf_append(reqbuf, "x-devtype: 6\r\n");
	buf_append(reqbuf, "\r\n");

	if (buf_error(reqbuf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error creating array negotiation request\n"));
		ret = buf_error(reqbuf);
		goto out;
	}
	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);
	ret = vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);
	if (ret < 0)
		goto out;

	ret = process_http_response(vpninfo, 1, NULL, reqbuf);
	if (ret < 0)
		goto out;

	if (ret != 201 && ret != 200) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unexpected %d result from server\n"),
			     ret);
		/* We get a redirect to /prx/000/http/localhost/cookietest when
		 * the cookie has expired. */
		if (ret == 302 || vpninfo->redirect_url)
			ret = -EPERM;
		else
			ret = -EINVAL;
		goto out;
	}

	ret = do_json_request(vpninfo, (void *)conf50, sizeof(conf50),
			      parse_speed_tunnel);
	if (ret)
		goto out;

	ret = do_json_request(vpninfo, (void *)conf54, sizeof(conf54),
			      parse_interface_info);
	if (ret)
		goto out;

	if (vpninfo->dtls_state != DTLS_DISABLED) {
		struct oc_text_buf *dtlsbuf = buf_alloc();
		buf_append_bytes(dtlsbuf, (void *)ipff, 16);
		buf_append(dtlsbuf, "%s", vpninfo->ppp_tls_connect_req->data);

		if (buf_error(dtlsbuf)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Error building Array DTLS negotiation packet\n"));
			vpninfo->dtls_state = DTLS_DISABLED;
			ret = buf_free(dtlsbuf);
			goto out;
		}

		store_be16(dtlsbuf->data + 12, 4);
		store_be16(dtlsbuf->data + 2, dtlsbuf->pos);

		if (vpninfo->dump_http_traffic)
			dump_buf_hex(vpninfo, PRG_DEBUG, '>', (void *)dtlsbuf->data,
				     dtlsbuf->pos);

		ret = vpninfo->ssl_write(vpninfo, (void *)dtlsbuf->data, dtlsbuf->pos);
		if (ret != dtlsbuf->pos) {
			buf_free(dtlsbuf);
			if (ret >= 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Short write in array negotiation\n"));
				ret = -EIO;
			}
			goto out;
		}
		buf_free(dtlsbuf);

		ret = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
		if (ret < 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to read UDP negotiation response\n"));
			ret = -EIO;
			goto out;
		}

		/* Parse it, learn what we need from it */
		if (vpninfo->dump_http_traffic)
			dump_buf_hex(vpninfo, PRG_DEBUG, '<', bytes, ret);

		if (ret == 0x25 && !memcmp(bytes + 0x14, "DTLS SPEED TUNNEL", 0x11)) {
			int udp_port = load_be16(bytes + 0x12);

			vpn_progress(vpninfo, PRG_INFO, _("DTLS enabled on port %d\n"),
				     udp_port);

			udp_sockaddr(vpninfo, udp_port);

			if (vpninfo->dtls_state == DTLS_NOSECRET)
				vpninfo->dtls_state = DTLS_SECRET;
		} else {
			/* The 'encrypted' UDP tunnel without DTLS looks like it's using
			 * the same key repeatedly without IV or replay protection. I'm
			 * not touching it with a bargepole, or the unencrypted one. */
			vpn_progress(vpninfo, PRG_INFO,
				     _("Refusing non-DTLS UDP tunnel\n"));
			vpninfo->dtls_state = DTLS_DISABLED;
		}
	}

#if 0
	/* Send third request 'ipff' */
	dump_buf_hex(vpninfo, PRG_DEBUG, '>', (void *)ipff, sizeof(ipff));
	ret = vpninfo->ssl_write(vpninfo,  (void *)ipff, sizeof(ipff));
	if (ret != sizeof(ipff)) {
		shortwrite:
			if (ret >= 0) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Short write in array negotiation\n"));
			ret = -EIO;
		}
		goto out;
	}

	ret = vpninfo->ssl_read(vpninfo, (void *)bytes, sizeof(bytes));
	if (ret < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to read ipff response\n"));
		goto out;
	}

	/* Parse it, learn what we need from it */
	dump_buf_hex(vpninfo, PRG_DEBUG, '<', bytes, ret);
#endif
	vpninfo->tcp_blocked_for_udp = 0;

	ret = 0; /* success */
 out:
	if (ret)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
		vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);
	}
	buf_free(reqbuf);

	free_pkt(vpninfo, vpninfo->cstp_pkt);
	vpninfo->cstp_pkt = NULL;

	vpninfo->ip_info.mtu = 1400;

	return ret;
}

int array_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int ret;
	int work_done = 0;

	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

	/* FIXME: The poll() handling here is fairly simplistic. Actually,
	   if the SSL connection stalls it could return a WANT_WRITE error
	   on _either_ of the SSL_read() or SSL_write() calls. In that case,
	   we should probably remove POLLIN from the events we're looking for,
	   and add POLLOUT. As it is, though, it'll just chew CPU time in that
	   fairly unlikely situation, until the write backlog clears. */
	while (readable) {
		/* Some servers send us packets that are larger than
		   negotiated MTU. We reserve some extra space to
		   handle that */
		int receive_mtu = MAX(16384, vpninfo->deflate_pkt_size ? : vpninfo->ip_info.mtu);
		int len;

		if (!vpninfo->cstp_pkt) {
			vpninfo->partial_rec_size = 0;
			vpninfo->cstp_pkt = alloc_pkt(vpninfo, receive_mtu);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		len = ssl_nonblock_read(vpninfo, 0,
					vpninfo->cstp_pkt->data + vpninfo->partial_rec_size,
					receive_mtu - vpninfo->partial_rec_size);
		if (!len)
			break;
		if (len < 0)
			goto do_reconnect;

		if (vpninfo->partial_rec_size) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received %d more bytes after partial %d\n"),
				     len, vpninfo->partial_rec_size);
			len += vpninfo->partial_rec_size;
			vpninfo->partial_rec_size = 0;
		}

		vpninfo->ssl_times.last_rx = time(NULL);
		work_done = 1;

		unsigned char *buf = vpninfo->cstp_pkt->data;
		int iplen;
	next_ip:
		if (len < sizeof(struct ip)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received partial packet, %d bytes\n"), len);
			vpninfo->partial_rec_size = len;
			continue;
		}

		switch (buf[0] >> 4) {
		case 4:
			iplen = load_be16(buf + 2);
			break;
		case 6:
			iplen = load_be16(buf + 4) + 40;
			break;
		default:
		badiplen:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unrecognised data packet, len %d\n"), len);
			dump_buf_hex(vpninfo, PRG_DEBUG, '<', buf, len);
			continue;
		}

		if (iplen > receive_mtu)
			goto badiplen;

		/* Argh. It even splits IP packets across TLS records. */
		if (iplen > len) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received partial packet, %d of %d bytes\n"),
				     len, iplen);
			vpninfo->partial_rec_size = len;
			continue;
		}

		/* Dump control packets but don't queue them */
		if (buf[0] == 0x45 && buf[9] == 0xff) {
			uint16_t ctrl_type = load_be16(buf + 12);
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Receive control packet of type %x:\n"),
				     ctrl_type);
			dump_buf_hex(vpninfo, PRG_DEBUG, '<', buf, len);
			if (iplen == len)
				continue;
		} else {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received data packet of %d bytes\n"),
				     iplen);
			if (iplen == len) {
				/* This buffer (now) contains just a single IP packet */
				vpninfo->cstp_pkt->len = iplen;
				queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
				vpninfo->cstp_pkt = NULL;
				continue;
			} else {
				/* Awfully inefficient for now. We *copy* the packet into
				 * a new buffer and then memmove the subsequent one(s)
				 * down in the original buffer. */
				queue_new_packet(vpninfo, &vpninfo->incoming_queue,
						 buf, iplen);
			}
		}

		/* Move the next packet(s) up to the head of the existing buffer */
		len -= iplen;
		memmove(buf, buf + iplen, len);
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Moved down %d bytes after previous packet\n"), len);
		goto next_ip;
	}

	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

		ret = ssl_nonblock_write(vpninfo, 0,
					 vpninfo->current_ssl_pkt->data,
					 vpninfo->current_ssl_pkt->len);
		if (ret < 0)
			goto do_reconnect;
		else if (!ret) {
			/* -EAGAIN: ssl_nonblock_write() will have added the SSL
			   fd to ->select_wfds if appropriate, so we can just
			   return and wait. Unless it's been stalled for so long
			   that DPD kicks in and we kill the connection. */
			switch (ka_stalled_action(&vpninfo->ssl_times, timeout)) {
			case KA_DPD_DEAD:
				goto peer_dead;
			case KA_REKEY:
				goto do_rekey;
			case KA_NONE:
				return work_done;
			default:
				/* This should never happen */
				break;
			}
		}

		if (ret != vpninfo->current_ssl_pkt->len) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 8, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt != &dpd_pkt &&
		    vpninfo->current_ssl_pkt != &nodtls_pkt)
			free_pkt(vpninfo, vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_REKEY:
	do_rekey:
		/* Not that this will ever happen; we don't even process
		   the setting when we're asked for it. */
		vpn_progress(vpninfo, PRG_INFO, _("CSTP rekey due\n"));
		if (vpninfo->ssl_times.rekey_method == REKEY_TUNNEL)
			goto do_reconnect;
		else if (vpninfo->ssl_times.rekey_method == REKEY_SSL) {
			ret = cstp_handshake(vpninfo, 0);
			if (ret) {
				/* if we failed rehandshake try establishing a new-tunnel instead of failing */
				vpn_progress(vpninfo, PRG_ERR, _("Rehandshake failed; attempting new-tunnel\n"));
				goto do_reconnect;
			}
			goto do_dtls_reconnect;
		}
		break;

	case KA_DPD_DEAD:
	peer_dead:
		vpn_progress(vpninfo, PRG_ERR,
			     _("TCP Dead Peer Detection detected dead peer!\n"));
	do_reconnect:
		ret = ssl_reconnect(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("TCP reconnect failed\n"));
			vpninfo->quit_reason = "TCP reconnect failed";
			return ret;
		}

	do_dtls_reconnect:
		/* succeeded, let's rekey DTLS, if it is not rekeying
		 * itself. */
		if (vpninfo->dtls_state > DTLS_SLEEPING &&
		    vpninfo->dtls_times.rekey_method == REKEY_NONE) {
			vpninfo->dtls_need_reconnect = 1;
		}

		return 1;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send TCP DPD\n"));

		/* last_dpd will just have been set */
		vpninfo->dtls_times.last_tx = vpninfo->dtls_times.last_dpd;
		work_done = 1;

		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_pkt;
		goto handle_outgoing;
		break;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_state != DTLS_ESTABLISHED &&
		    vpninfo->outgoing_queue.head)
			break;

		vpn_progress(vpninfo, PRG_DEBUG, _("Send TCP Keepalive\n"));

		//vpninfo->current_ssl_pkt = (struct pkt *)&keepalive_pkt;
		//goto handle_outgoing;
		break;

	case KA_NONE:
		;
	}

	if (vpninfo->dtls_state != DTLS_ESTABLISHED &&
	    vpninfo->tcp_blocked_for_udp) {
		vpninfo->current_ssl_pkt = (struct pkt *)&nodtls_pkt;
		vpninfo->tcp_blocked_for_udp = 0;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending DTLS off packet\n"));
		goto handle_outgoing;
	}

	/* Service outgoing packet queue, if no DTLS */
	while (vpninfo->dtls_state != DTLS_ESTABLISHED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending uncompressed data packet of %d bytes\n"),
			     this->len);

		vpninfo->current_ssl_pkt = this;
		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

int array_dtls_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int work_done = 0;
	time_t now = time(NULL);
	int first_connected = 0;

	if (vpninfo->dtls_need_reconnect) {
		vpninfo->dtls_need_reconnect = 0;
		dtls_reconnect(vpninfo, timeout);
		return 1;
	}

	if (vpninfo->dtls_state == DTLS_CONNECTING) {
		dtls_try_handshake(vpninfo, timeout);
		if (vpninfo->dtls_state == DTLS_CONNECTED) {
			first_connected = 1;
			goto newly_connected;
		}

		vpninfo->delay_tunnel_reason = "DTLS establishing";
		return 0;
	}

	if (vpninfo->dtls_state == DTLS_SLEEPING) {
		int when = vpninfo->new_dtls_started + vpninfo->dtls_attempt_period - time(NULL);

		if (when <= 0) {
			vpn_progress(vpninfo, PRG_DEBUG, _("Attempt new DTLS connection\n"));
			if (dtls_reconnect(vpninfo, timeout) < 0)
				*timeout = 1000;
		} else if ((when * 1000) < *timeout) {
			*timeout = when * 1000;
		}
		return 0;
	}

	/* Nothing to do here for Cisco DTLS as it is preauthenticated */
	if (vpninfo->dtls_state == DTLS_CONNECTED) {
		/* First, see if there's a response for us. */
		while (readable) {
			int receive_mtu = MAX(16384, vpninfo->ip_info.mtu);
			int len;

			/* cstp_pkt is used by PPP over either transport, and TCP
			 * may be in active use while we attempt to connect DTLS.
			 * So use vpninfo->dtls_pkt for this. */
			if (!vpninfo->dtls_pkt)
				vpninfo->dtls_pkt = alloc_pkt(vpninfo, receive_mtu);
			if (!vpninfo->dtls_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				dtls_close(vpninfo);
				vpninfo->dtls_state = DTLS_DISABLED;
				return 1;
			}

			struct pkt *this =  vpninfo->dtls_pkt;
			len = ssl_nonblock_read(vpninfo, 1, this->data, receive_mtu);
			if (!len)
				break;
			if (len < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to receive authentication response from DTLS\n"));
				dtls_close(vpninfo);
				return 1;
			}

			this->len = len;

			if (vpninfo->dump_http_traffic)
				dump_buf_hex(vpninfo, PRG_DEBUG, '<', this->data, len);

			if (len >= 6 && !memcmp(this->data, "200 OK", 6)) {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("DTLS session established\n"));
				vpninfo->dtls_state = DTLS_ESTABLISHED;
				vpninfo->tcp_blocked_for_udp = 1;
				goto established;
			}
			/* The '200 OK' packet might get dropped; we *assume* the server
			 * won't resend it even if we send the clientip again, so let's
			 * take IP traffic as 'success' too. */
			if (len >= sizeof(struct ip) && (this->data[0] >> 4) == 4 &&
			    load_be16(this->data + 2) == len) {
				/* Looks like a Legacy IP packet; the '200 OK' was
				 * probably dropped. */
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Received Legacy IP over DTLS; assuming established\n"));
				vpninfo->dtls_state = DTLS_ESTABLISHED;
				vpninfo->tcp_blocked_for_udp = 1;
				goto got_pkt;
			}
			if (len >= sizeof(struct ip6_hdr) && (this->data[0] >> 4) == 6 &&
			    len == load_be16(this->data + 4) + sizeof(struct ip6_hdr)) {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Received IPv6 over DTLS; assuming established\n"));
				vpninfo->dtls_state = DTLS_ESTABLISHED;
				vpninfo->tcp_blocked_for_udp = 1;
				goto got_pkt;
			}
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received unknown DTLS packet\n"));
		}

		/* Resend the connect request every second */
		if (ka_check_deadline(timeout, now, vpninfo->dtls_times.last_tx + 1)) {
		newly_connected:
			if (buf_error(vpninfo->ppp_dtls_connect_req)) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Error creating connect request for DTLS session\n"));
				dtls_close(vpninfo);
				vpninfo->dtls_state = DTLS_DISABLED;
				return 1;
			}

			if (vpninfo->dump_http_traffic)
				dump_buf_hex(vpninfo, PRG_DEBUG, '>',
					     (void *)vpninfo->ppp_dtls_connect_req->data,
					     vpninfo->ppp_dtls_connect_req->pos);

			int ret = ssl_nonblock_write(vpninfo, 1,
						     vpninfo->ppp_dtls_connect_req->data,
						     vpninfo->ppp_dtls_connect_req->pos);
			if (ret < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to write connect request to DTLS session\n"));
				dtls_close(vpninfo);
				vpninfo->dtls_state = DTLS_DISABLED;
				return 1;
			}

			/* On the second and subsequent attempt, send a keepalive packet
			 * too. The server will *ignore* the clientid packet on a resend
			 * so we have to send this too to elicit a response. Sadly, if
			 * this ends up being the *first* packet it receives, it cuts
			 * us off. */
			if (!first_connected) {
				if (vpninfo->dump_http_traffic)
					dump_buf_hex(vpninfo, PRG_DEBUG, '>',
						     (void *)dpd_pkt.data, dpd_pkt.len);
				ssl_nonblock_write(vpninfo, 1, (void *)dpd_pkt.data, dpd_pkt.len);
			}

			vpninfo->dtls_times.last_tx = now;
		}

		return 0;
	}

	if (vpninfo->dtls_state != DTLS_ESTABLISHED)
		return 0;

 established:
	while (readable) {
		int len = MAX(16384, vpninfo->ip_info.mtu);
		unsigned char *buf;

		if (!vpninfo->dtls_pkt) {
			vpninfo->dtls_pkt = alloc_pkt(vpninfo, len);
			if (!vpninfo->dtls_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		buf = vpninfo->dtls_pkt->data;
		len = ssl_nonblock_read(vpninfo, 1, buf, len);
		if (len <= 0)
			break;

		vpninfo->dtls_pkt->len = len;

		if (0) {
		got_pkt:
			len = vpninfo->dtls_pkt->len;
			buf = vpninfo->dtls_pkt->data;
		}
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Received DTLS packet 0x%02x of %d bytes\n"),
			     buf[0], len);

		vpninfo->dtls_times.last_rx = time(NULL);

		if (len >= sizeof(struct ip) && buf[0] == 0x45 &&
		    load_be16(buf + 2) == len && buf[9] == 0xff) {
			uint16_t ctrl_type = load_be16(buf + 12);
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Receive control packet of type %x:\n"),
				     ctrl_type);
			dump_buf_hex(vpninfo, PRG_DEBUG, '<', buf, len);
			continue;
		}

		queue_packet(&vpninfo->incoming_queue, vpninfo->dtls_pkt);
		vpninfo->dtls_pkt = NULL;
		work_done = 1;
	}

	switch (keepalive_action(&vpninfo->dtls_times, timeout)) {
	case KA_REKEY: {
		int ret;

		vpn_progress(vpninfo, PRG_INFO, _("DTLS rekey due\n"));

		if (vpninfo->dtls_times.rekey_method == REKEY_SSL) {
			time(&vpninfo->new_dtls_started);
			vpninfo->dtls_state = DTLS_CONNECTING;
			ret = dtls_try_handshake(vpninfo, timeout);
			if (ret) {
				vpn_progress(vpninfo, PRG_ERR, _("DTLS Rehandshake failed; reconnecting.\n"));
				return dtls_reconnect(vpninfo, timeout);
			}
		}

		return 1;
	}

	case KA_DPD_DEAD:
		vpn_progress(vpninfo, PRG_ERR, _("DTLS Dead Peer Detection detected dead peer!\n"));
		/* Fall back to SSL, and start a new DTLS connection */
		dtls_reconnect(vpninfo, timeout);
		return 1;

	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send DTLS DPD\n"));

		if (ssl_nonblock_write(vpninfo, 1, (void *)dpd_pkt.data, dpd_pkt.len) != dpd_pkt.len)
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to send DPD request. Expect disconnect\n"));

		/* last_dpd will just have been set */
		vpninfo->dtls_times.last_tx = vpninfo->dtls_times.last_dpd;
		work_done = 1;
		break;

	case KA_KEEPALIVE: /* We don't do keepalive; only DPD */
	case KA_NONE:
		;
	}

	/* Service outgoing packet queue */
	unmonitor_write_fd(vpninfo, dtls);
	while (vpninfo->outgoing_queue.head) {
		struct pkt *this = dequeue_packet(&vpninfo->outgoing_queue);
		struct pkt *send_pkt = this;
		int ret;

		/* If TOS optname is set, we want to copy the TOS/TCLASS header
		   to the outer UDP packet */
		if (vpninfo->dtls_tos_optname)
			udp_tos_update(vpninfo, this);

		ret = ssl_nonblock_write(vpninfo, 1, send_pkt->data, send_pkt->len);
		if (ret <= 0) {
			/* Zero is -EAGAIN; just requeue. dtls_nonblock_write()
			 * will have added the socket to the poll wfd list. */
			requeue_packet(&vpninfo->outgoing_queue, this);
			if (ret < 0) {
				/* If it's a real error, kill the DTLS connection so
				   the requeued packet will be sent over SSL */
				dtls_reconnect(vpninfo, timeout);
				work_done = 1;
			}
			return work_done;
		}
		time(&vpninfo->dtls_times.last_tx);
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sent DTLS packet of %d bytes; DTLS send returned %d\n"),
			     this->len, ret);
		free_pkt(vpninfo, this);
	}

	return work_done;
}

int array_bye(struct openconnect_info *vpninfo, const char *reason)
{
	char *orig_path;
	char *res_buf=NULL;
	int ret;

	/* We need to close and reopen the HTTPS connection (to kill
	 * the array tunnel) and submit a new HTTPS request to logout.
	 */
	openconnect_close_https(vpninfo, 0);

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup("prx/000/http/localhost/logout"); /* redirect segfaults without strdup */
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
