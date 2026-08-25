/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2016-2017 Daniel Lenski
 *
 * Author: Daniel Lenski <dlenski@gmail.com>
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

#if HAVE_JSON
#include "json.h"
#endif

#ifdef HAVE_LZ4
#include <lz4.h>
#endif

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#ifdef _WIN32
#include "win32-ipicmp.h"
#else
#include <sys/wait.h>
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

#if defined(__linux__)
/* For TCP_INFO */
# include <linux/tcp.h>
#endif

#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

/*
 * Data packets are encapsulated in the SSL stream as follows:
 *
 * 0000: Magic "\x1a\x2b\x3c\x4d"
 * 0004: Big-endian EtherType (0x0800 for IPv4)
 * 0006: Big-endian 16-bit length (not including 16-byte header)
 * 0008: Always "\x01\0\0\0\0\0\0\0"
 * 0010: data payload
 */

/* Strange initialisers here to work around GCC PR#10676 (which was
 * fixed in GCC 4.6 but it takes a while for some systems to catch
 * up. */
static const struct pkt dpd_pkt = {
	.next = NULL,
	{ .gpst.hdr = { 0x1a, 0x2b, 0x3c, 0x4d } }
};

static int filter_opts(struct oc_text_buf *buf, const char *query, const char *incexc, int include)
{
	const char *f, *endf, *eq;
	const char *found, *comma;

	for (f = query; *f; f=(*endf) ? endf+1 : endf) {
		endf = strchrnul(f, '&');
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

/* Parse a JavaScript/JSON string to handle non-literal escape
   characters.

   Falls back to naïvely returning everything between the "..."
   delimiters if JSON is not available in this build, or if the string
   is mangled and not legal JavaScript/JSON (e.g. contains '\u' followed by
   anything other than 4 hex digits).
*/
static char *json_get_string(const char *start, size_t length)
{
	char *s;
	if (!length)
		length = strlen(start);
#if HAVE_JSON
	json_value *val = json_parse(start, length);
	if (val && val->type == json_string) {
		/* XX: will need to switch to strdup() if we ever use a custom allocator for JSON */
		s = val->u.string.ptr;
		val->u.string.ptr = NULL;
	} else
#endif
		s = length < 2 ? NULL : strndup(start+1, length-2);
#if HAVE_JSON
	json_value_free(val);
#endif
	return s;
}

/* Parse this JavaScript-y mess:

	"var respStatus = \"Challenge|Error\";\n"
	"var respMsg = \"<prompt>\";\n"
	"thisForm.inputStr.value = "<inputStr>";\n"
*/
static int parse_javascript(char *buf, char **prompt, char **inputStr)
{
	const char *start, *end = buf;
	int status;

	const char *pre_status = "var respStatus = \"",
	           *pre_prompt = "var respMsg = \"",
	           *pre_inputStr = "thisForm.inputStr.value = \"";

	/* Status */
	while (isspace(*end))
		end++;
	if (strncmp(end, pre_status, strlen(pre_status)))
		goto err;

	start = end+strlen(pre_status);
	end = strchr(start, '"');
	if (!end)
		goto err;

	if (!strncmp(start, "Challenge", 8))    status = 0;
	else if (!strncmp(start, "Error", 5))   status = 1;
	else                                    goto err;

	/* Prompt */
	end++;
	while (*end == ';' || isspace(*end))
		end++;
	if (strncmp(end, pre_prompt, strlen(pre_prompt)))
		goto err;

	end = start = end+strlen(pre_prompt);
	do {
		end = strchr(end+1, '"');
	} while (end && end[-1] == '\\');
	if (!end)
		goto err;

	if (prompt)
		*prompt = json_get_string(start-1, end-start+2);

	/* inputStr */
	end++;
	while (*end == ';' || isspace(*end))
		end++;
	if (strncmp(end, pre_inputStr, strlen(pre_inputStr)))
		goto err2;

	start = end+strlen(pre_inputStr);
	end = strchr(start, '"');
	if (!end)
		goto err2;

	if (inputStr)
		*inputStr = strndup(start, end-start);

	end++;
	while (*end == ';' || isspace(*end))
		end++;
	if (*end != '\0')
		goto err3;

	return status;

err3:
	if (inputStr) free(*inputStr);
err2:
	if (prompt) free(*prompt);
err:
	return -EINVAL;
}

int gpst_xml_or_error(struct openconnect_info *vpninfo, char *response,
					  int (*xml_cb)(struct openconnect_info *, xmlNode *xml_node, void *cb_data),
					  int (*challenge_cb)(struct openconnect_info *, char *prompt, char *inputStr, void *cb_data),
					  void *cb_data)
{
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	char *err = NULL;
	char *prompt = NULL, *inputStr = NULL;
	int result = -EINVAL;

	if (!response) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Empty response from server\n"));
		return -EINVAL;
	}

	/* We need to distinguish XML from non-XML input, since GlobalProtect servers can
	 * provide challenge-based 2FA in any of the following formats with no warning:
	 *   XML (reasonable)
	 *   Javascript-y (stupid)
	 *   Javascript wrapped in HTML (stupidest)
	 * See the initial discovery of this at
	 * https://github.com/dlenski/openconnect/issues/109#issuecomment-391025707,
	 * and the HTML-wrapped version at
	 * https://gitlab.com/openconnect/openconnect/-/issues/495
	 *
	 * However, we also want to be able to use XML_PARSE_RECOVER in order to
	 * parse XML leniently. With this flag, xmlReadMemory won't return NULL,
	 * but will return an "empty" XML document, with a NULL root node.
	 */
	xml_doc = xmlReadMemory(response, strlen(response), NULL, NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	xml_node = xmlDocGetRootElement(xml_doc);

	if (!xml_node) {
	try_javascript:
		/* is it Javascript? */
		result = parse_javascript(response, &prompt, &inputStr);
		switch (result) {
		case 1:
			vpn_progress(vpninfo, PRG_ERR, _("%s\n"), prompt);
			break;
		case 0:
			vpn_progress(vpninfo, PRG_DEBUG, _("Challenge: %s\n"), prompt);
			result = challenge_cb ? challenge_cb(vpninfo, prompt, inputStr, cb_data) : -EINVAL;
			break;
		default:
			vpn_progress(vpninfo, PRG_ERR, _("Failed to parse non-XML server response\n"));
			vpn_progress(vpninfo, PRG_DEBUG, _("Response was: %s\n"), response);
			goto out;
		}
		free(prompt);
		free(inputStr);
	} else {
		xml_node = xmlDocGetRootElement(xml_doc);

		/* is it <response status="error"><error>..</error></response> ? */
		if (xmlnode_is_named(xml_node, "response")
		    && !xmlnode_match_prop(xml_node, "status", "error")) {
			for (xml_node=xml_node->children; xml_node; xml_node=xml_node->next) {
				if (!xmlnode_get_val(xml_node, "error", &err))
					goto out;
			}
		}

		/* Is it <prelogin-response><status>Error</status><msg>..</msg></prelogin-response> ? */
		else if (xmlnode_is_named(xml_node, "prelogin-response")) {
			char *s = NULL;
			int has_err = 0;
			xmlNode *x;
			for (x=xml_node->children; x; x=x->next) {
				if (!xmlnode_get_val(x, "status", &s))
					has_err = strcmp(s, "Success");
				else
					xmlnode_get_val(x, "msg", &err);
			}
			free(s);
			if (has_err)
				goto out;
			free(err);
			err = NULL;
			goto xml_callback;
		}

		/* is it <challenge><user>user.name</user><inputstr>...</inputstr><respmsg>...</respmsg></challenge> */
	        else if (xmlnode_is_named(xml_node, "challenge")) {
			for (xml_node=xml_node->children; xml_node; xml_node=xml_node->next) {
				xmlnode_get_val(xml_node, "inputstr", &inputStr);
				xmlnode_get_val(xml_node, "respmsg", &prompt);
				/* XXX: override the username passed to the next form from <user> ? */
			}
			result = challenge_cb ? challenge_cb(vpninfo, prompt, inputStr, cb_data) : -EINVAL;
			free(prompt);
			free(inputStr);
		}

		/* is it <html><head></head><body>$JAVASCRIPT_JAMMED_IN_HERE</body></html> ? */
		else if (xmlnode_is_named(xml_node, "html")) {
			for (xml_node=xml_node->children; xml_node; xml_node=xml_node->next) {
				if (xmlnode_is_named(xml_node, "body")) {
					response = (char *)xmlNodeGetContent(xml_node);
					goto try_javascript;
				}
			}
		}

		/* invoke XML callback (or default to success) */
		else
		xml_callback:
			result = xml_cb ? xml_cb(vpninfo, xml_node, cb_data) : 0;

		if (result == -EINVAL) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse XML server response\n"));
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Response was: %s\n"), response);
		}
	}

out:
	if (err) {
		if (!strcmp(err, "GlobalProtect gateway does not exist")
		    || !strcmp(err, "GlobalProtect portal does not exist")) {
			vpn_progress(vpninfo, PRG_DEBUG, "%s\n", err);
			result = -EEXIST;
		} else if (!strcmp(err, "Invalid authentication cookie")           /* equivalent to custom HTTP status 512 */
			   || !strcmp(err, "Portal name not found")                /* cookie is bogus */
		           || !strcmp(err, "Valid client certificate is required") /* equivalent to custom HTTP status 513 */
		           || !strcmp(err, "Allow Automatic Restoration of SSL VPN is disabled")) {
			/* Any of these errors indicates that retrying won't help us reconnect (EPERM signals this to mainloop.) */
			vpn_progress(vpninfo, PRG_ERR, "%s\n", err);
			result = -EPERM;
		} else {
			vpn_progress(vpninfo, PRG_ERR, "%s\n", err);
			result = -EINVAL;
		}
		free(err);
	}
	if (xml_doc)
		xmlFreeDoc(xml_doc);
	return result;
}

#define ESP_HEADER_SIZE (4 /* SPI */ + 4 /* sequence number */)
#define ESP_FOOTER_SIZE (1 /* pad length */ + 1 /* next header */)

#ifdef HAVE_ESP
static int check_hmac_algo(struct openconnect_info *v, const char *s)
{
	if (!strcmp(s, "sha1"))	  return HMAC_SHA1;
	if (!strcmp(s, "md5"))    return HMAC_MD5;
	if (!strcmp(s, "sha256")) return HMAC_SHA256;
	vpn_progress(v, PRG_ERR, _("Unknown ESP MAC algorithm: %s\n"), s);
	return -ENOENT;
}

static int check_enc_algo(struct openconnect_info *v, const char *s)
{
	if (!strcmp(s, "aes128") || !strcmp(s, "aes-128-cbc")) return ENC_AES_128_CBC;
	if (!strcmp(s, "aes-256-cbc"))                         return ENC_AES_256_CBC;
	vpn_progress(v, PRG_ERR, _("Unknown ESP encryption algorithm: %s\n"), s);
	return -ENOENT;
}

/* Reads <KEYTAG/><bits>N</bits><val>hex digits</val></KEYTAG> and saves the
 * key in dest, returning its length in bytes.
 */
static int xml_to_key(xmlNode *xml_node, unsigned char *dest, int dest_size)
{
	int explen = -1, len = 0;
	xmlNode *child;
	char *p, *s = NULL;

	for (child = xml_node->children; child; child=child->next) {
		if (xmlnode_get_val(child, "bits", &s) == 0) {
			explen = atoi(s);
			if (explen & 0x07) goto out;
			explen >>= 3;
		} else if (xmlnode_get_val(child, "val", &s) == 0) {
			for (p=s; p[0] && p[1]; p+=2)
				if (len++ < dest_size)
					*dest++ = unhex(p);
		}
	}
out:
	free(s);
	return (len == explen) ? len : -EINVAL;
}
#endif

/* Return value:
 *  < 0, on error
 *  = 0, on success; *form is populated
 */
static int gpst_parse_config_xml(struct openconnect_info *vpninfo, xmlNode *xml_node, void *cb_data)
{
	xmlNode *member;
	int n_dns = 0;
	int ret = 0;
	char *s = NULL;
	int ii;

#ifdef HAVE_ESP
	int esp_keys = 0, have_esp_magic_v4 = 0, have_esp_magic_v6 = 0;
	struct in6_addr esp_magic_v6;
	struct in_addr esp_magic_v4;
#endif /* HAVE_ESP */

	if (!xml_node || !xmlnode_is_named(xml_node, "response"))
		return -EINVAL;


	struct oc_vpn_option *new_opts = NULL;
	struct oc_ip_info new_ip_info = {};

	vpninfo->esp_replay_protect = 1;
	vpninfo->ssl_times.rekey_method = REKEY_NONE;

	/* Parse config */
	for (xml_node = xml_node->children; xml_node; xml_node=xml_node->next) {
		if (!xmlnode_get_val(xml_node, "ip-address", &s))
			new_ip_info.addr = add_option_steal(&new_opts, "ipaddr", &s);
		else if (!xmlnode_get_val(xml_node, "ip-address-v6", &s)) {
			if (!vpninfo->disable_ipv6)
				new_ip_info.addr6 = add_option_steal(&new_opts, "ipaddr6", &s);
		} else if (!xmlnode_get_val(xml_node, "netmask", &s)) {
			new_ip_info.netmask = add_option_steal(&new_opts, "netmask", &s);
		} else if (!xmlnode_get_val(xml_node, "mtu", &s))
			new_ip_info.mtu = atoi(s);
		else if (!xmlnode_get_val(xml_node, "lifetime", &s))
			vpninfo->auth_expiration = time(NULL) + atol(s);
		else if (!xmlnode_get_val(xml_node, "quarantine", &s)) {
			if (strcmp(s, "no"))
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("WARNING: Config XML contains <quarantine> tag with value of \"%s\".\n"
					       "    VPN connectivity may be disabled or limited.\n"), s);
		} else if (!xmlnode_get_val(xml_node, "disconnect-on-idle", &s)) {
			int sec = atoi(s);
			vpn_progress(vpninfo, PRG_INFO, _("Idle timeout is %d minutes.\n"), sec/60);
			vpninfo->idle_timeout = sec;
		} else if (!xmlnode_get_val(xml_node, "ssl-tunnel-url", &s)) {
			free(vpninfo->urlpath);
			vpninfo->urlpath = s;
			if (strcmp(s, "/ssl-tunnel-connect.sslvpn"))
				vpn_progress(vpninfo, PRG_INFO, _("Non-standard SSL tunnel path: %s\n"), s);
			s = NULL;
		} else if (!xmlnode_get_val(xml_node, "timeout", &s)) {
			int sec = atoi(s);
			vpn_progress(vpninfo, PRG_INFO, _("Tunnel timeout (rekey interval) is %d minutes.\n"), sec/60);
			vpninfo->ssl_times.last_rekey = time(NULL);
			vpninfo->ssl_times.rekey = sec - 60;
			vpninfo->ssl_times.rekey_method = REKEY_TUNNEL;
		} else if (!xmlnode_get_val(xml_node, "gw-address", &s)) {
			/* As remarked in oncp.c, "this is a tunnel; having a
			 * gateway is meaningless." See esp_send_probes_gp for the
			 * gory details of what this field actually means.
			 */
			if (vpninfo->peer_addr->sa_family == IPPROTO_IP &&
			    vpninfo->ip_info.gateway_addr && strcmp(s, vpninfo->ip_info.gateway_addr))
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Legacy IP gateway address in config XML (%s) differs from external gateway address (%s).\n"), s, vpninfo->ip_info.gateway_addr);
#ifdef HAVE_ESP
			have_esp_magic_v4 = 1;
			inet_pton(AF_INET, s, &esp_magic_v4);
#endif /* HAVE_ESP */
		} else if (!xmlnode_get_val(xml_node, "gw-address-v6", &s)) {
			if (vpninfo->peer_addr->sa_family == IPPROTO_IPV6 &&
			    vpninfo->ip_info.gateway_addr && strcmp(s, vpninfo->ip_info.gateway_addr))
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("IPv6 gateway address in config XML (%s) differs from external gateway address (%s).\n"), s, vpninfo->ip_info.gateway_addr);
#ifdef HAVE_ESP
			have_esp_magic_v6 = 1;
			inet_pton(AF_INET6, s, &esp_magic_v6);
#endif /* HAVE_ESP */
		} else if (!xmlnode_get_val(xml_node, "connected-gw-ip", &s)) {
			if (vpninfo->ip_info.gateway_addr && strcmp(s, vpninfo->ip_info.gateway_addr))
				vpn_progress(vpninfo, PRG_DEBUG, _("Config XML <connected-gw-ip> address (%s) differs from external\n"
				                                   "gateway address (%s). Please report this to\n"
								   "<%s>, including any problems\n"
								   "with ESP or other apparent loss of connectivity or performance.\n"),
					     s, vpninfo->ip_info.gateway_addr, "openconnect-devel@lists.infradead.org");
		} else if (xmlnode_is_named(xml_node, "dns-v6") ||
			   xmlnode_is_named(xml_node, "dns")) {
			for (member = xml_node->children; member && n_dns<3; member=member->next) {
				if (!xmlnode_get_val(member, "member", &s)) {
					for (ii=0; ii<n_dns; ii++)
						/* XX: frequent duplicates between <dns> and <dns-v6> */
						if (!strcmp(s, new_ip_info.dns[ii]))
							break;
					if (ii==n_dns)
						new_ip_info.dns[n_dns++] = add_option_steal(&new_opts, "DNS", &s);
				}
			}
		} else if (xmlnode_is_named(xml_node, "wins")) {
			for (ii=0, member = xml_node->children; member && ii<3; member=member->next)
				if (!xmlnode_get_val(member, "member", &s))
					new_ip_info.nbns[ii++] = add_option_steal(&new_opts, "WINS", &s);
		} else if (xmlnode_is_named(xml_node, "dns-suffix")) {
			struct oc_text_buf *domains = buf_alloc();
			for (member = xml_node->children; member; member=member->next)
				if (!xmlnode_get_val(member, "member", &s))
					buf_append(domains, "%s ", s);
			if (buf_error(domains) == 0 && domains->pos > 0) {
				domains->data[domains->pos-1] = '\0';
				new_ip_info.domain = add_option_steal(&new_opts, "search", &domains->data);
			}
			buf_free(domains);
		} else if (xmlnode_is_named(xml_node, "access-routes-v6") || xmlnode_is_named(xml_node, "exclude-access-routes-v6") ||
			   xmlnode_is_named(xml_node, "access-routes") || xmlnode_is_named(xml_node, "exclude-access-routes")) {
			for (member = xml_node->children; member; member=member->next) {
				if (!xmlnode_get_val(member, "member", &s)) {
					int is_exclude = (xml_node->name[0] == 'e');
					struct oc_split_include *inc = malloc(sizeof(*inc));
					if (!inc) {
						ret = -ENOMEM;
						goto err;
					}
					if (!is_exclude) {
						inc->route = add_option_steal(&new_opts, "split-include", &s);
						inc->next = new_ip_info.split_includes;
						new_ip_info.split_includes = inc;
					} else {
						inc->route = add_option_steal(&new_opts, "split-exclude", &s);
						inc->next = new_ip_info.split_excludes;
						new_ip_info.split_excludes = inc;
					}
				}
			}
		} else if (xmlnode_is_named(xml_node, "ipsec")) {
#ifdef HAVE_ESP
			if (vpninfo->dtls_state != DTLS_DISABLED) {
				int c = (vpninfo->current_esp_in ^= 1);
				struct esp *ei = &vpninfo->esp_in[c], *eo = &vpninfo->esp_out;
				vpninfo->old_esp_maxseq = vpninfo->esp_in[c^1].seq + 32;
				for (member = xml_node->children; member; member=member->next) {
					if (!xmlnode_get_val(member, "udp-port", &s))		udp_sockaddr(vpninfo, atoi(s));
					else if (!xmlnode_get_val(member, "enc-algo", &s))	vpninfo->esp_enc = check_enc_algo(vpninfo, s);
					else if (!xmlnode_get_val(member, "hmac-algo", &s))	vpninfo->esp_hmac = check_hmac_algo(vpninfo, s);
					else if (!xmlnode_get_val(member, "c2s-spi", &s))	eo->spi = htonl(strtoul(s, NULL, 16));
					else if (!xmlnode_get_val(member, "s2c-spi", &s))	ei->spi = htonl(strtoul(s, NULL, 16));
					else if (xmlnode_is_named(member, "ekey-c2s"))		vpninfo->enc_key_len = xml_to_key(member, eo->enc_key, sizeof(eo->enc_key));
					else if (xmlnode_is_named(member, "ekey-s2c"))		vpninfo->enc_key_len = xml_to_key(member, ei->enc_key, sizeof(ei->enc_key));
					else if (xmlnode_is_named(member, "akey-c2s"))		vpninfo->hmac_key_len = xml_to_key(member, eo->hmac_key, sizeof(eo->hmac_key));
					else if (xmlnode_is_named(member, "akey-s2c"))		vpninfo->hmac_key_len = xml_to_key(member, ei->hmac_key, sizeof(ei->hmac_key));
					else if (!xmlnode_get_val(member, "ipsec-mode", &s) && strcmp(s, "esp-tunnel"))
						vpn_progress(vpninfo, PRG_ERR, _("GlobalProtect config sent ipsec-mode=%s (expected esp-tunnel)\n"), s);
				}
				if (!(vpninfo->esp_enc > 0 && vpninfo->esp_hmac > 0 && vpninfo->enc_key_len > 0 && vpninfo->hmac_key_len > 0))
					vpn_progress(vpninfo, PRG_ERR, "Server's ESP configuration is incomplete or uses unknown algorithms.\n");
				else
					esp_keys = 1;
			}
#else
			vpn_progress(vpninfo, PRG_DEBUG, _("Ignoring ESP keys since ESP support not available in this build\n"));
#endif
		} else if (xmlnode_is_named(xml_node, "need-tunnel")
			   || xmlnode_is_named(xml_node, "bw-c2s")
			   || xmlnode_is_named(xml_node, "bw-s2c")
			   || xmlnode_is_named(xml_node, "default-gateway")
			   || xmlnode_is_named(xml_node, "default-gateway-v6")
			   || xmlnode_is_named(xml_node, "no-direct-access-to-local-network")
			   || xmlnode_is_named(xml_node, "ip-address-preferred")
			   || xmlnode_is_named(xml_node, "ip-address-v6-preferred")
			   || xmlnode_is_named(xml_node, "ipv6-connection")
			   || xmlnode_is_named(xml_node, "portal")
			   || xmlnode_is_named(xml_node, "user")) {
			/* XX: Do these have any potential value at all for routing configuration or diagnostics? */
		} else if (xml_node->type == XML_ELEMENT_NODE) {
			free(s);
			s = (char *)xmlNodeGetContent(xml_node);
			if (strchr((char *)xml_node->name, '6'))
				vpn_progress(vpninfo, PRG_ERR, _("Potential IPv6-related GlobalProtect config tag <%s>: %s\n"), xml_node->name, s);
			else
				vpn_progress(vpninfo, PRG_DEBUG, _("Unknown GlobalProtect config tag <%s>: %s\n"), xml_node->name, s);
		}
	}

	/* Set 10-second DPD/keepalive (same as Windows client) unless
	 * overridden with --force-dpd */
	if (!vpninfo->ssl_times.dpd)
		vpninfo->ssl_times.dpd = 10;
	vpninfo->ssl_times.keepalive = vpninfo->esp_ssl_fallback = vpninfo->ssl_times.dpd;

	/* Warn about IPv6 config, if present, and ESP config, if absent */
	if (new_ip_info.addr6)
		vpn_progress(vpninfo, PRG_ERR,
			     _("GlobalProtect IPv6 support is experimental. Please report results to <%s>.\n"),
			     "openconnect-devel@lists.infradead.org");
#ifdef HAVE_ESP
	if (esp_keys) {
		/* If we get both Legacy IP and IPv6 magic addresses, then we must use the IPv6
		 * value in order for both AFs to work over the tunnel (see 5b98b628
		 * "GlobalProtect IPv6 ESP support").
		 */
		if (have_esp_magic_v6 && new_ip_info.addr6) {
			/* We got ESP keys, an IPv6 esp_magic address, and an IPv6 client address */
			vpninfo->esp_magic_af = AF_INET6;
			memcpy(vpninfo->esp_magic, &esp_magic_v6, sizeof(esp_magic_v6));
		} else if (have_esp_magic_v4 && new_ip_info.addr) {
			/* We got ESP keys, a Legacy IP esp_magic address, and a Legacy IP client address */
			vpninfo->esp_magic_af = AF_INET;
			memcpy(vpninfo->esp_magic, &esp_magic_v4, sizeof(esp_magic_v4));
		} else
			goto cannot_esp;

		if (openconnect_setup_esp_keys(vpninfo, 0)) {
			vpn_progress(vpninfo, PRG_ERR, "Failed to setup ESP keys.\n");
		} else {
			/* prevent race condition between esp_mainloop() and gpst_mainloop() timers */
			vpninfo->dtls_times.last_rekey = time(&vpninfo->new_dtls_started);
			vpninfo->delay_tunnel_reason = "awaiting GPST ESP connection";
		}
	} else if (vpninfo->dtls_state != DTLS_DISABLED)
cannot_esp:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Did not receive ESP keys and matching gateway in GlobalProtect config; tunnel will be TLS only.\n"));
#endif

	free(s);

	ret = install_vpn_opts(vpninfo, new_opts, &new_ip_info);
	if (ret) {
	err:
		free_optlist(new_opts);
		free_split_routes(&new_ip_info);
	}

	return ret;
}

static int gpst_get_config(struct openconnect_info *vpninfo)
{
	char *orig_path;
	int result;
	struct oc_text_buf *request_body = buf_alloc();
	const char *old_addr = vpninfo->ip_info.addr;
	const char *old_addr6 = vpninfo->ip_info.addr6;
	char *xml_buf = NULL;


	/* submit getconfig request */
	buf_append(request_body, "client-type=1&protocol-version=p1&internal=no");
	append_opt(request_body, "app-version", vpninfo->csd_ticket ? : "6.3.0-33");
	append_opt(request_body, "ipv6-support", vpninfo->disable_ipv6 ? "no" : "yes");
	append_opt(request_body, "clientos", gpst_os_name(vpninfo));
	append_opt(request_body, "os-version", vpninfo->platname);
	append_opt(request_body, "hmac-algo", "sha1,md5,sha256");
	append_opt(request_body, "enc-algo", "aes-128-cbc,aes-256-cbc");
	if (old_addr || old_addr6) {
		append_opt(request_body, "preferred-ip", old_addr);
		append_opt(request_body, "preferred-ipv6", old_addr6);
		filter_opts(request_body, vpninfo->cookie, "preferred-ip,preferred-ipv6", 0);
	} else
		buf_append(request_body, "&%s", vpninfo->cookie);
	if ((result = buf_error(request_body)))
		goto out;

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup("ssl-vpn/getconfig.esp");
	result = do_https_request(vpninfo, "POST", "application/x-www-form-urlencoded", request_body, &xml_buf, NULL, HTTP_NO_FLAGS);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;

	/* parse getconfig result */
	if (result >= 0)
		result = gpst_xml_or_error(vpninfo, xml_buf, gpst_parse_config_xml, NULL, NULL);
	if (result) {
		/* XX: if our "cookie" is bogus (doesn't include at least 'user', 'authcookie',
		 * and 'portal' fields) the server will respond like this.
		 */
		if (result == -EINVAL && xml_buf && !strcmp(xml_buf, "errors getting SSL/VPN config"))
			result = -EPERM;
		goto out;
	}

	if (!vpninfo->ip_info.mtu) {
		/* FIXME: GP gateway config always seems to be <mtu>0</mtu> */
		char *no_esp_reason = NULL;
#ifdef HAVE_ESP
		if (vpninfo->dtls_state == DTLS_DISABLED)
			no_esp_reason = _("ESP disabled");
		else if (vpninfo->dtls_state == DTLS_NOSECRET)
			no_esp_reason = _("No ESP keys received");
#else
		no_esp_reason = _("ESP support not available in this build");
#endif
		if (!no_esp_reason)
			vpninfo->ip_info.mtu = calculate_mtu(
				vpninfo, 1,
				ESP_HEADER_SIZE + vpninfo->hmac_out_len + MAX_IV_SIZE, /* ESP header size */
				ESP_FOOTER_SIZE, /* ESP footer (contributes to payload before padding) */
				16 /* blocksize for both AES-128 and AES-256 */ );
		else
			vpninfo->ip_info.mtu = calculate_mtu(vpninfo, 0, TLS_OVERHEAD, 0, 1);

		vpn_progress(vpninfo, PRG_ERR,
			     _("No MTU received. Calculated %d for %s%s\n"), vpninfo->ip_info.mtu,
			     no_esp_reason ? "SSL tunnel. " : "ESP tunnel", no_esp_reason ? : "");
		/* return -EINVAL; */
	}

out:
	buf_free(request_body);
	free(xml_buf);
	return result;
}

static int gpst_connect(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *reqbuf;
	static const char start_tunnel[12] __attribute__((nonstring)) = "START_TUNNEL"; /* NOT NUL-terminated */
	char buf[256];

	/* We do NOT actually start the HTTPS tunnel if ESP is enabled and we received
	 * ESP keys, because the ESP keys become invalid as soon as the HTTPS tunnel
	 * is connected! >:-(
	 */
	if (vpninfo->dtls_state != DTLS_DISABLED && vpninfo->dtls_state != DTLS_NOSECRET)
		return 0;

	/* Connect to SSL VPN tunnel */
	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Connecting to HTTPS tunnel endpoint ...\n"));

	ret = openconnect_open_https(vpninfo);
	if (ret)
		return ret;

	reqbuf = buf_alloc();
	buf_append(reqbuf, "GET %s?", vpninfo->urlpath);
	filter_opts(reqbuf, vpninfo->cookie, "user,authcookie", 1);
	buf_append(reqbuf, " HTTP/1.1\r\n\r\n");
	if ((ret = buf_error(reqbuf)))
		goto out;

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', reqbuf->data);

	vpninfo->ssl_write(vpninfo, reqbuf->data, reqbuf->pos);

	if ((ret = vpninfo->ssl_read(vpninfo, buf, 12)) < 0) {
		if (ret == -EINTR)
			goto out;
		vpn_progress(vpninfo, PRG_ERR,
		             _("Error fetching GET-tunnel HTTPS response.\n"));
		ret = -EINVAL;
		goto out;
	}

	if (!strncmp(buf, start_tunnel, sizeof(start_tunnel))) {
		ret = 0;
	} else if (ret==0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Gateway disconnected immediately after GET-tunnel request.\n"));
		ret = -EPIPE;
	} else {
		if (ret==sizeof(start_tunnel)) {
			ret = vpninfo->ssl_gets(vpninfo, buf+sizeof(start_tunnel), sizeof(buf)-sizeof(start_tunnel));
			ret = (ret>0 ? ret : 0) + sizeof(start_tunnel);
			dump_buf(vpninfo, '<', buf);
		}
		int status = check_http_status(buf, ret);
		/* XX: GP servers return 502 when they don't like the cookie */
		if (status == 502)
			ret = -EPERM;
		else {
			vpn_progress(vpninfo, PRG_ERR, _("Got unexpected HTTP response: %.*s\n"),
				     ret, buf);
			ret = -EINVAL;
		}
	}

	if (ret < 0)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
		vpninfo->ssl_times.last_rx = vpninfo->ssl_times.last_tx = time(NULL);
		/* connecting the HTTPS tunnel totally invalidates the ESP keys,
		   hence shutdown */
		if (vpninfo->proto->udp_shutdown)
			vpninfo->proto->udp_shutdown(vpninfo);
	}

out:
	buf_free(reqbuf);
	return ret;
}

static int parse_hip_report_check(struct openconnect_info *vpninfo, xmlNode *xml_node, void *cb_data)
{
	char *s = NULL;
	int result = -EINVAL;

	if (!xml_node || !xmlnode_is_named(xml_node, "response"))
		goto out;

	for (xml_node = xml_node->children; xml_node; xml_node=xml_node->next) {
		if (!xmlnode_get_val(xml_node, "hip-report-needed", &s)) {
			if (!strcmp(s, "no"))
				result = 0;
			else if (!strcmp(s, "yes"))
				result = -EAGAIN;
			else
				result = -EINVAL;
			goto out;
		}
	}

out:
	free(s);
	return result;
}

/* Unlike CSD, the HIP security checker runs during the connection
 * phase, not during the authentication phase.
 *
 * The HIP security checker will (probably) ask us to resubmit the
 * HIP report if either of the following changes:
 *   - Client IP address
 *   - Client HIP report md5sum
 *
 * I'm not sure what the md5sum is computed over in the official
 * client, but it doesn't really matter.
 *
 * We just need an identifier for the combination of the local host
 * and the VPN gateway which won't change when our IP address
 * or authcookie are changed.
 */
static int build_csd_token(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *buf;
	unsigned char md5[16];
	int i;

	if (vpninfo->csd_token)
		return 0;

	vpninfo->csd_token = malloc(MD5_SIZE * 2 + 1);
	if (!vpninfo->csd_token)
		return -ENOMEM;

	/* use cookie (excluding volatile authcookie and preferred-ip/ipv6) to build md5sum */
	buf = buf_alloc();
	filter_opts(buf, vpninfo->cookie, "authcookie,preferred-ip,preferred-ipv6", 0);
	if (buf_error(buf))
		goto out;

	/* save as csd_token */
	openconnect_md5(md5, buf->data, buf->pos);
	for (i=0; i < MD5_SIZE; i++)
		sprintf(&vpninfo->csd_token[i*2], "%02x", md5[i]);

out:
	return buf_free(buf);
}

/* check if HIP report is needed (to ssl-vpn/hipreportcheck.esp) or submit HIP report contents (to ssl-vpn/hipreport.esp) */
static int check_or_submit_hip_report(struct openconnect_info *vpninfo, const char *report)
{
	int result;

	struct oc_text_buf *request_body = buf_alloc();
	char *xml_buf=NULL, *orig_path;

	/* cookie gives us these fields: authcookie, portal, user, domain, computer, and (maybe the unnecessary) preferred-ip/ipv6 */
	buf_append(request_body, "client-role=global-protect-full&%s", vpninfo->cookie);
	if (vpninfo->ip_info.addr)
		append_opt(request_body, "client-ip", vpninfo->ip_info.addr);
	if (vpninfo->ip_info.addr6)
		append_opt(request_body, "client-ipv6", vpninfo->ip_info.addr6);
	if (report) {
		/* XML report contains many characters requiring URL-encoding (%xx) */
		buf_ensure_space(request_body, strlen(report)*3);
		append_opt(request_body, "report", report);
	} else {
		result = build_csd_token(vpninfo);
		if (result)
			goto out;
		append_opt(request_body, "md5", vpninfo->csd_token);
	}
	if ((result = buf_error(request_body)))
		goto out;

	orig_path = vpninfo->urlpath;
	vpninfo->urlpath = strdup(report ? "ssl-vpn/hipreport.esp" : "ssl-vpn/hipreportcheck.esp");
	result = do_https_request(vpninfo, "POST", "application/x-www-form-urlencoded", request_body, &xml_buf, NULL, HTTP_NO_FLAGS);
	free(vpninfo->urlpath);
	vpninfo->urlpath = orig_path;

	if (result >= 0)
		result = gpst_xml_or_error(vpninfo, xml_buf, report ? NULL : parse_hip_report_check, NULL, NULL);

out:
	buf_free(request_body);
	free(xml_buf);
	return result;
}

static int run_hip_script(struct openconnect_info *vpninfo)
{
#if !defined(_WIN32) && !defined(__native_client__)
	int pipefd[2];
	int ret;
	pid_t child;
#endif

	if (!vpninfo->csd_wrapper) {
		/* Only warn once */
		if (!vpninfo->last_trojan) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("WARNING: Server asked us to submit HIP report with md5sum %s.\n"
				       "    VPN connectivity may be disabled or limited without HIP report submission.\n    %s\n"),
				     vpninfo->csd_token,
#if defined(_WIN32) || defined(__native_client__)
				     _("However, running the HIP report submission script on this platform is not yet implemented.")
#else
				     _("You need to provide a --csd-wrapper argument with the HIP report submission script.")
#endif
				);
			/* XXX: Many GlobalProtect VPNs work fine despite allegedly requiring HIP report submission */
		}
		return 0;
	}

#if defined(_WIN32) || defined(__native_client__)
	vpn_progress(vpninfo, PRG_ERR,
		     _("Error: Running the 'HIP Report' script on this platform is not yet implemented.\n"));
	return -EPERM;
#else

	vpn_progress(vpninfo, PRG_INFO,
		     _("Trying to run HIP Trojan script '%s'.\n"),
		     vpninfo->csd_wrapper);

#ifdef __linux__
	if (pipe2(pipefd, O_CLOEXEC))
#endif
	{
		if (pipe(pipefd)) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to create pipe for HIP script\n"));
			return -EPERM;
		}
		set_fd_cloexec(pipefd[0]);
		set_fd_cloexec(pipefd[1]);
	}
	child = fork();
	if (child == -1) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to fork for HIP script\n"));
		return -EPERM;
	} else if (child > 0) {
		/* in parent: read report from child */
		struct oc_text_buf *report_buf = buf_alloc();
		char b[256];
		int i, status;
		close(pipefd[1]);

		buf_truncate(report_buf);
		while ((i = read(pipefd[0], b, sizeof(b))) > 0)
			buf_append_bytes(report_buf, b, i);

		waitpid(child, &status, 0);
		if (!WIFEXITED(status)) {
			vpn_progress(vpninfo, PRG_ERR,
						 _("HIP script '%s' exited abnormally\n"),
						 vpninfo->csd_wrapper);
			ret = -EINVAL;
		} else if (WEXITSTATUS(status) != 0) {
			vpn_progress(vpninfo, PRG_ERR,
						 _("HIP script '%s' returned non-zero status: %d\n"),
						 vpninfo->csd_wrapper, WEXITSTATUS(status));
			ret = -EINVAL;
		} else {
			vpn_progress(vpninfo, PRG_INFO,
				     _("HIP script '%s' completed successfully (report is %d bytes).\n"),
				     vpninfo->csd_wrapper, report_buf->pos);

			ret = check_or_submit_hip_report(vpninfo, report_buf->data);
			if (ret < 0)
				vpn_progress(vpninfo, PRG_ERR, _("HIP report submission failed.\n"));
			else {
				vpn_progress(vpninfo, PRG_INFO, _("HIP report submitted successfully.\n"));
				ret = 0;
			}
		}
		buf_free(report_buf);
		return ret;
	} else {
		/* in child: run HIP script */
		const char *hip_argv[32];
		int i = 0;
		close(pipefd[0]);
		/* The duplicated fd does not have O_CLOEXEC */
		dup2(pipefd[1], 1);

		if (set_csd_user(vpninfo) < 0)
			exit(1);

		hip_argv[i++] = openconnect_utf8_to_legacy(vpninfo, vpninfo->csd_wrapper);
		hip_argv[i++] = "--cookie";
		hip_argv[i++] = vpninfo->cookie;
		if (vpninfo->ip_info.addr) {
			hip_argv[i++] = "--client-ip";
			hip_argv[i++] = vpninfo->ip_info.addr;
		}
		if (vpninfo->ip_info.addr6) {
			hip_argv[i++] = "--client-ipv6";
			hip_argv[i++] = vpninfo->ip_info.addr6;
		}
		hip_argv[i++] = "--md5";
		hip_argv[i++] = vpninfo->csd_token;
		hip_argv[i++] = "--client-os";
		hip_argv[i++] = gpst_os_name(vpninfo);
		hip_argv[i++] = NULL;

		/* XX: Sending the above parameters as --long-options was a mistake that was
		 * based on overly-close replication of the invocation of the CSD script/binary
		 * (see auth.c). In the case of CSD, some parameters *need* to be sent on the
		 * command line to maintain compatibility with opaque Cisco CSD binaries.
		 *
		 * For GlobalProtect/HIP, we have no need to maintain compatibility with any
		 * opaque binaries sent by the server.
		 *
		 * For anything that hasn't already shipped in a released version, we should use
		 * environment variables as the standard way to send values to the HIP script,
		 * particularly because it makes it easier for a shell script to parse them and
		 * accept new ones.
		 */
		unsetenv("APP_VERSION");
		if (vpninfo->csd_ticket)
			if (setenv("APP_VERSION", vpninfo->csd_ticket, 1))
				goto out;

		execv(hip_argv[0], (char **)hip_argv);

	out:
		vpn_progress(vpninfo, PRG_ERR,
				 _("Failed to exec HIP script %s\n"), hip_argv[0]);
		exit(1);
	}

#endif /* !_WIN32 && !__native_client__ */
}

static int check_and_maybe_submit_hip_report(struct openconnect_info *vpninfo)
{
	int ret;

	ret = check_or_submit_hip_report(vpninfo, NULL);
	if (ret == -EAGAIN) {
		vpn_progress(vpninfo, PRG_DEBUG,
					 _("Gateway says HIP report submission is needed.\n"));
		ret = run_hip_script(vpninfo);
	} else if (ret == 0)
		vpn_progress(vpninfo, PRG_DEBUG,
					 _("Gateway says no HIP report submission is needed.\n"));

	return ret;
}

int gpst_setup(struct openconnect_info *vpninfo)
{
	int ret;

	/* ESP keys are invalid as soon as we (re-)fetch the configuration, hence shutdown */
	if (vpninfo->proto->udp_shutdown)
		vpninfo->proto->udp_shutdown(vpninfo);

	/* Get configuration */
	ret = gpst_get_config(vpninfo);
	if (ret)
		goto out;

	/* Always check HIP after getting configuration */
	ret = check_and_maybe_submit_hip_report(vpninfo);
	if (ret)
		goto out;

	/* XX: last_trojan is used both as a sentinel to detect the
	 * first time we check/submit HIP, and for the mainloop to timeout
	 * when periodic re-checking is required.
	 */
	vpninfo->last_trojan = time(NULL);

	/* Default HIP re-checking to 3600 seconds unless already set by
	 * --force-trojan or portal config.
	 */
	if (!vpninfo->trojan_interval)
		vpninfo->trojan_interval = 3600;

	/* Connect tunnel immediately if ESP is not going to be used */
	ret = gpst_connect(vpninfo);

out:
	return ret;
}

int gpst_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int ret;
	int work_done = 0;
	uint16_t ethertype;
	uint32_t one, zero, magic;

	/* Starting the HTTPS tunnel kills ESP, so we avoid starting
	 * it if the ESP tunnel is connected or connecting.
	 */
	switch (vpninfo->dtls_state) {
	case DTLS_CONNECTING: /* Can never happen */
	case DTLS_CONNECTED:
		openconnect_close_https(vpninfo, 0); /* don't keep stale HTTPS socket */
		vpn_progress(vpninfo, PRG_INFO,
			     _("ESP tunnel connected; exiting HTTPS mainloop.\n"));
		vpninfo->dtls_state = DTLS_ESTABLISHED;
		/* Now that we are connected, let's ensure timeout is less than
		 * or equal to DTLS DPD/keepalive else we might over sleep, eg
		 * if timeout is set to DTLS attempt period from ESP mainloop,
		 * and falsely detect dead peer. */
		if (vpninfo->dtls_times.dpd)
			if (*timeout > vpninfo->dtls_times.dpd * 1000)
				*timeout = vpninfo->dtls_times.dpd * 1000;
		/* fall through */
	case DTLS_ESTABLISHED:
		/* Rekey or check-and-resubmit HIP if needed */
		if (keepalive_action(&vpninfo->ssl_times, timeout) == KA_REKEY)
			goto do_rekey;
		else if (trojan_check_deadline(vpninfo, timeout))
			goto do_recheck_hip;
		return 0;
	case DTLS_SECRET:
	case DTLS_SLEEPING:
		/* Allow 5 seconds after configuration for ESP to start */
		if (!ka_check_deadline(timeout, time(NULL), vpninfo->new_dtls_started + 5)) {
			vpninfo->delay_tunnel_reason = "awaiting GPST ESP connection";
			return 0;
		}

		/* ... before we switch to HTTPS instead */
		vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to connect ESP tunnel; using HTTPS instead.\n"));
		/* XX: gpst_connect does nothing if ESP is enabled and has secrets */
		vpninfo->dtls_state = DTLS_NOSECRET;
		if ((ret = gpst_connect(vpninfo))) {
			vpninfo->quit_reason = "GPST connect failed";
			return ret;
		}
		break;
	case DTLS_NOSECRET:
		/* HTTPS tunnel already started, or getconfig.esp did not provide any ESP keys */
	case DTLS_DISABLED:
		/* ESP is disabled */
		;
	}

	if (vpninfo->ssl_fd == -1)
		goto do_reconnect;

	while (readable) {
		/* Some servers send us packets that are larger than
		   negotiated MTU. We reserve some extra space to
		   handle that */
		int receive_mtu = MAX(16384, vpninfo->ip_info.mtu);
		int len, payload_len;

		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = alloc_pkt(vpninfo, receive_mtu);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}

		len = ssl_nonblock_read(vpninfo, 0, vpninfo->cstp_pkt->gpst.hdr, receive_mtu + 16);
		if (!len)
			break;
		if (len < 0) {
			vpn_progress(vpninfo, PRG_ERR, _("Packet receive error: %s\n"), strerror(-len));
			goto do_reconnect;
		}
		if (len < 16) {
			vpn_progress(vpninfo, PRG_ERR, _("Short packet received (%d bytes)\n"), len);
			vpninfo->quit_reason = "Short packet received";
			return 1;
		}

		/* check packet header */
		magic = load_be32(vpninfo->cstp_pkt->gpst.hdr);
		ethertype = load_be16(vpninfo->cstp_pkt->gpst.hdr + 4);
		payload_len = load_be16(vpninfo->cstp_pkt->gpst.hdr + 6);
		one = load_le32(vpninfo->cstp_pkt->gpst.hdr + 8);
		zero = load_le32(vpninfo->cstp_pkt->gpst.hdr + 12);

		if (magic != 0x1a2b3c4d)
			goto unknown_pkt;

		if (len != 16 + payload_len) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Unexpected packet length. SSL_read returned %d (includes 16 header bytes) but header payload_len is %d\n"),
			             len, payload_len);
			dump_buf_hex(vpninfo, PRG_ERR, '<', vpninfo->cstp_pkt->gpst.hdr, 16);
			continue;
		}

		vpninfo->ssl_times.last_rx = time(NULL);
		switch (ethertype) {
		case 0:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Got GPST DPD/keepalive response\n"));

			if (one != 0 || zero != 0) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Expected 0000000000000000 as last 8 bytes of DPD/keepalive packet header, but got:\n"));
				dump_buf_hex(vpninfo, PRG_DEBUG, '<', vpninfo->cstp_pkt->gpst.hdr + 8, 8);
			}
			continue;
		case 0x0800:
		case 0x86DD:
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Received IPv%d data packet of %d bytes\n"),
				     ethertype == 0x86DD ? 6 : 4, payload_len);

			if (one != 1 || zero != 0) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Expected 0100000000000000 as last 8 bytes of data packet header, but got:\n"));
				dump_buf_hex(vpninfo, PRG_DEBUG, '<', vpninfo->cstp_pkt->gpst.hdr + 8, 8);
			}

			vpninfo->cstp_pkt->len = payload_len;
			queue_packet(&vpninfo->incoming_queue, vpninfo->cstp_pkt);
			vpninfo->cstp_pkt = NULL;
			work_done = 1;
			continue;
		}

	unknown_pkt:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown packet. Header dump follows:\n"));
		dump_buf_hex(vpninfo, PRG_ERR, '<', vpninfo->cstp_pkt->gpst.hdr, 16);
		vpninfo->quit_reason = "Unknown packet received";
		return 1;
	}


	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if (vpninfo->current_ssl_pkt) {
	handle_outgoing:
		vpninfo->ssl_times.last_tx = time(NULL);
		unmonitor_write_fd(vpninfo, ssl);

		ret = ssl_nonblock_write(vpninfo, 0,
					 vpninfo->current_ssl_pkt->gpst.hdr,
					 vpninfo->current_ssl_pkt->len + 16);
		if (ret < 0)
			goto do_reconnect;
		else if (!ret) {
			switch (ka_stalled_action(&vpninfo->ssl_times, timeout)) {
			case KA_REKEY:
				goto do_rekey;
			case KA_DPD_DEAD:
				goto peer_dead;
			case KA_NONE:
				return work_done;
			}
		}

		if (ret != vpninfo->current_ssl_pkt->len + 16) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     vpninfo->current_ssl_pkt->len + 16, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}
		/* Don't free the 'special' packets */
		if (vpninfo->current_ssl_pkt != &dpd_pkt)
			free_pkt(vpninfo, vpninfo->current_ssl_pkt);

		vpninfo->current_ssl_pkt = NULL;
	}

	if (trojan_check_deadline(vpninfo, timeout)) {
	do_recheck_hip:
		vpn_progress(vpninfo, PRG_INFO, _("GlobalProtect HIP check due\n"));
		/* We could just be lazy and treat this as a reconnect, but that
		 * would require us to repull the routing configuration and new ESP
		 * keys, instead of just redoing the HIP check/submission.
		 *
		 * Therefore we'll just close the HTTPS tunnel (if up),
		 * redo the HIP check/submission, and reconnect the HTTPS tunnel
		 * if needed.
		 */
		openconnect_close_https(vpninfo, 0);
		ret = check_and_maybe_submit_hip_report(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("HIP check or report failed\n"));
			vpninfo->quit_reason = "HIP check or report failed";
			return ret;
		}
		/* XX: no need to do_reconnect, since ESP doesn't need reconnection */
		if ((ret = gpst_connect(vpninfo)))
			vpninfo->quit_reason = "GPST connect failed";
		return ret;
	}

	switch (keepalive_action(&vpninfo->ssl_times, timeout)) {
	case KA_REKEY:
	do_rekey:
		vpn_progress(vpninfo, PRG_INFO, _("GlobalProtect rekey due\n"));
		goto do_reconnect;
	case KA_DPD_DEAD:
	peer_dead:
		vpn_progress(vpninfo, PRG_ERR,
			     _("GPST Dead Peer Detection detected dead peer!\n"));
	do_reconnect:
		ret = ssl_reconnect(vpninfo);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
			vpninfo->quit_reason = "GPST connect failed";
			return ret;
		}
		if (vpninfo->proto->udp_setup)
			vpninfo->proto->udp_setup(vpninfo);
		return 1;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->dtls_state != DTLS_ESTABLISHED &&
		    vpninfo->outgoing_queue.head)
			break;
		/* fall through */
	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send GPST DPD/keepalive request\n"));

		vpninfo->current_ssl_pkt = (struct pkt *)&dpd_pkt;
		goto handle_outgoing;
	}


	/* Service outgoing packet queue */
	while (vpninfo->dtls_state != DTLS_ESTABLISHED &&
	       (vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		struct pkt *this = vpninfo->current_ssl_pkt;

		/* IPv4 or IPv6 EtherType */
		int ethertype = this->len && (this->data[0] & 0xF0) == 0x60 ? 0x86DD : 0x0800;

		/* store header */
		store_be32(this->gpst.hdr, 0x1a2b3c4d);
		store_be16(this->gpst.hdr + 4, ethertype);
		store_be16(this->gpst.hdr + 6, this->len);
		store_le32(this->gpst.hdr + 8, 1);
		store_le32(this->gpst.hdr + 12, 0);

		vpn_progress(vpninfo, PRG_TRACE,
			     _("Sending IPv%d data packet of %d bytes\n"),
			     (ethertype == 0x86DD ? 6 : 4), this->len);

		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

int gpst_sso_detect_done(struct openconnect_info *vpninfo,
			 const struct oc_webview_result *result)
{
	int i;

	for (i=0; result->headers != NULL && result->headers[i] != NULL; i+=2) {
		const char *hname = result->headers[i], *hval = result->headers[i+1];
		if (!strcasecmp(hname, "saml-username")) {
			free(vpninfo->sso_username);
			vpninfo->sso_username = strdup(hval);
		} else if (!strcasecmp(hname, "prelogin-cookie") ||
			   !strcasecmp(hname, "portal-userauthcookie")) {
			free(vpninfo->sso_token_cookie);
			free(vpninfo->sso_cookie_value);
			vpninfo->sso_token_cookie = strdup(hname);
			vpninfo->sso_cookie_value = strdup(hval);
		}
	}

	if (vpninfo->sso_username && vpninfo->sso_token_cookie && vpninfo->sso_cookie_value) {
		/* Not actually used at the moment, so don't fail if not set by the caller */
		if (result->uri)
			vpninfo->sso_login_final = strdup(result->uri);
		return 0;
	} else
		return -EAGAIN;
}

#ifdef HAVE_ESP
static inline uint32_t csum_partial(void *_buf, int nwords)
{
	char *buf = _buf; /* So we can do pointer arithmetic on it portably */
	uint32_t sum = 0;

	for(sum=0; nwords>0; nwords--) {
		sum += load_be16(buf);
		buf += 2;
	}
	return sum;
}

static inline uint16_t csum_finish(uint32_t sum)
{
	sum = (sum >> 16) + (sum &0xffff);
	sum += (sum >> 16);
	return htons((uint16_t)(~sum));
}

static inline uint16_t csum(void *buf, int nwords)
{
	return csum_finish(csum_partial(buf, nwords));
}

static char magic_ping_payload[16] __attribute__((nonstring)) = "monitor\x00\x00pan ha "; /* NOT NUL-terminated */

int gpst_esp_send_probes(struct openconnect_info *vpninfo)
{
	/* The GlobalProtect VPN initiates and maintains the ESP connection
	 * using specially-crafted ICMP ("ping") packets.
	 *
	 * 1) These ping packets have a special magic payload. It must
	 *    include at least the 16 bytes below. The Windows client actually
	 *    sends this 56-byte version, but the remaining bytes don't
	 *    seem to matter:
	 *
	 *    "monitor\x00\x00pan ha 0123456789:;<=>? !\"#$%&\'()*+,-./\x10\x11\x12\x13\x14\x15\x16\x17";
	 *
	 * 2) The ping packets are addressed to the IP supplied in the
	 *    config XML as <gw-address>. In most cases, this is the
	 *    same as the *external* IP address of the VPN gateway
	 *    (vpninfo->ip_info.gateway_addr), but in some cases it is a
	 *    separate address.
	 *
	 *    Don't blame me. I didn't design this.
	 */
	const int icmplen = ICMP_MINLEN + sizeof(magic_ping_payload);
	int plen, seq = vpninfo->udp_probes_sent;

	if (vpninfo->esp_magic_af == AF_INET6)
		plen = sizeof(struct ip6_hdr) + icmplen;
	else
		plen = sizeof(struct ip) + icmplen;
	struct pkt *pkt = alloc_pkt(vpninfo, plen + vpninfo->pkt_trailer);
	if (!pkt)
		return -ENOMEM;

	if (vpninfo->dtls_fd == -1) {
		int fd = udp_connect(vpninfo);
		if (fd < 0) {
			free_pkt(vpninfo, pkt);
			return fd;
		}
		/* We are not connected until we get an ESP packet back */
		vpninfo->dtls_state = DTLS_SLEEPING;
		vpninfo->dtls_fd = fd;
		monitor_fd_new(vpninfo, dtls);
		monitor_read_fd(vpninfo, dtls);
		monitor_except_fd(vpninfo, dtls);
	}

	if (vpninfo->esp_magic_af == AF_INET6) {
		memset(pkt, 0, sizeof(*pkt) + plen);
		pkt->len = plen;
		struct ip6_hdr *iph = (void *)pkt->data;
		struct icmp6_hdr *icmph = (void *)(pkt->data + sizeof(*iph));

		/* IPv6 Header */
		iph->ip6_flow = htonl((6 << 28) + /* version 6 */
				      (0 << 20) + /* traffic class; match Windows client */
				      (0 << 0));  /* flow ID; match Windows client */
		iph->ip6_nxt = IPPROTO_ICMPV6;
		iph->ip6_plen = htons(icmplen);
		iph->ip6_hlim = 128; /* what the Windows client uses */
		inet_pton(AF_INET6, vpninfo->ip_info.addr6, &iph->ip6_src);
		memcpy(&iph->ip6_dst, vpninfo->esp_magic, 16);

		/* ICMPv6 echo request */
		icmph->icmp6_type = ICMP6_ECHO_REQUEST;
		icmph->icmp6_code = 0;
		/* Windows client seemingly uses random IDs here but fall back to
		 * 0x4747 even if only to keep Coverity happy about error checking. */
		if (openconnect_random(&icmph->icmp6_data16[0], 2))
			icmph->icmp6_data16[0] = htons(0x4747);
		icmph->icmp6_data16[1] = htons(seq);            /* sequence */

		/* required to get gateway to respond */
		memcpy(&icmph[1], magic_ping_payload, sizeof(magic_ping_payload));

		/*
		 * IPv6 upper-layer checksums include a pseudo-header
		 * for IPv6 which contains the source address, the
		 * destination address, the upper-layer packet length
		 * and next-header field. See RFC8200 §8.1. The
		 * checksum is as follows:
		 *
		 *   checksum 32 bytes of real IPv6 header:
		 *     src addr (16 bytes)
		 *     dst addr (16 bytes)
		 *   8 bytes more:
		 *     length of ICMPv6 in bytes (be32)
		 *     3 bytes of 0
		 *     next header byte (IPPROTO_ICMPV6)
		 *   Then the actual ICMPv6 bytes
		 */
		uint32_t sum = csum_partial(&iph->ip6_src, 8);      /* 8 uint16_t */
		sum += csum_partial(&iph->ip6_dst, 8);              /* 8 uint16_t */

		/* The easiest way to checksum the following 8-byte
		 * part of the pseudo-header without horridly violating
		 * C type aliasing rules is *not* to build it in memory
		 * at all. We know the length fits in 16 bits so the
		 * partial checksum of 00 00 LL LL 00 00 00 NH ends up
		 * being just LLLL + NH.
		 */
		sum += IPPROTO_ICMPV6;
		sum += ICMP_MINLEN + sizeof(magic_ping_payload);

		sum += csum_partial(icmph, icmplen / 2);
		icmph->icmp6_cksum = csum_finish(sum);
	} else {
		memset(pkt, 0, sizeof(*pkt) + plen);
		pkt->len = plen;
		struct ip *iph = (void *)pkt->data;
		struct icmp *icmph = (void *)(pkt->data + sizeof(*iph));
		char *pmagic = (void *)(pkt->data + sizeof(*iph) + ICMP_MINLEN);

		/* IP Header */
		iph->ip_hl = 5;
		iph->ip_v = 4;
		iph->ip_len = htons(sizeof(*iph) + icmplen);
		iph->ip_id = htons(0x4747); /* what the Windows client uses */
		iph->ip_off = htons(IP_DF); /* don't fragment, frag offset = 0 */
		iph->ip_ttl = 64; /* hops */
		iph->ip_p = IPPROTO_ICMP;
		iph->ip_src.s_addr = inet_addr(vpninfo->ip_info.addr);
		memcpy(&iph->ip_dst.s_addr, vpninfo->esp_magic, 4);
		iph->ip_sum = csum(iph, sizeof(*iph)/2);

		/* ICMP echo request */
		icmph->icmp_type = ICMP_ECHO;
		icmph->icmp_hun.ih_idseq.icd_id = htons(0x4747);
		icmph->icmp_hun.ih_idseq.icd_seq = htons(seq);
		memcpy(pmagic, magic_ping_payload, sizeof(magic_ping_payload)); /* required to get gateway to respond */
		icmph->icmp_cksum = csum(icmph, (ICMP_MINLEN+sizeof(magic_ping_payload))/2);
	}

	if (vpninfo->dtls_state != DTLS_ESTABLISHED) {
		vpn_progress(vpninfo, PRG_TRACE, _("ICMPv%d probe packet (seq %d) for GlobalProtect ESP:\n"),
			     vpninfo->esp_magic_af == AF_INET6 ? 6 : 4, seq);
		dump_buf_hex(vpninfo, PRG_TRACE, '>', pkt->data, pkt->len);
	}

	int pktlen = construct_esp_packet(vpninfo, pkt, vpninfo->esp_magic_af == AF_INET6 ? IPPROTO_IPV6 : IPPROTO_IPIP);
	if (pktlen < 0 || send(vpninfo->dtls_fd, (void *)&pkt->esp, pktlen, 0) < 0)
		vpn_progress(vpninfo, PRG_DEBUG, _("Failed to send ESP probe\n"));

	free_pkt(vpninfo, pkt);

	return 0;
}

int gpst_esp_catch_probe(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	if (vpninfo->esp_magic_af == AF_INET6) {
		struct ip6_hdr *iph = (void *)(pkt->data);
		return ( pkt->len >= 41 && (ntohl(iph->ip6_flow) >> 28)==6 /* IPv6 header */
			 && iph->ip6_nxt == IPPROTO_ICMPV6 /* IPv6 next header field = ICMPv6 */
			 && !memcmp(&iph->ip6_src, vpninfo->esp_magic, 16) /* source == magic address */
			 && pkt->len >= 40 + ICMP_MINLEN + sizeof(magic_ping_payload) /* No short-packet segfaults */
			 && pkt->data[40]==ICMP6_ECHO_REPLY /* ICMPv6 reply */
			 && !memcmp(&pkt->data[40 + ICMP_MINLEN], magic_ping_payload, sizeof(magic_ping_payload)) /* Same magic payload in response */
			 );
	} else {
		struct ip *iph = (void *)(pkt->data);
		return ( pkt->len >= 21 && iph->ip_v==4 /* IPv4 header */
			 && iph->ip_p==IPPROTO_ICMP /* IPv4 protocol field == ICMP */
			 && !memcmp(&iph->ip_src.s_addr, vpninfo->esp_magic, 4) /* source == magic address */
			 && pkt->len >= (iph->ip_hl<<2) + ICMP_MINLEN + sizeof(magic_ping_payload) /* No short-packet segfaults */
			 && pkt->data[iph->ip_hl<<2]==ICMP_ECHOREPLY /* ICMP reply */
			 && !memcmp(&pkt->data[(iph->ip_hl<<2) + ICMP_MINLEN], magic_ping_payload, sizeof(magic_ping_payload)) /* Same magic payload in response */
			 );
	}
}
#endif /* HAVE_ESP */
