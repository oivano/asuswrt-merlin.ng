/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 * Copyright © 2013 John Morrissey <jwm@horde.net>
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
#include <sys/stat.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/wait.h>
#include <pwd.h>
#include <grp.h>
#endif

#include <stdio.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

enum {
	CERT1_REQUESTED = (1<<0),
	CERT1_AUTHENTICATED = (1<<1),
	CERT2_REQUESTED = (1<<2),
};

struct cert_request {
	unsigned int state:16;
	unsigned int hashes:16;
};

static int xmlpost_append_form_opts(struct openconnect_info *vpninfo,
				    struct oc_auth_form *form, struct oc_text_buf *body);
static int cstp_can_gen_tokencode(struct openconnect_info *vpninfo,
				  struct oc_auth_form *form,
				  struct oc_form_opt *opt);

/* multiple certificate-based authentication */
static void parse_multicert_request(struct openconnect_info *vpninfo,
				    xmlNodePtr node, struct cert_request *cert_rq);
static int prepare_multicert_response(struct openconnect_info *vpninfo,
			      struct cert_request cert_rq, const char *challenge,
			      struct oc_text_buf *body);

int openconnect_set_option_value(struct oc_form_opt *opt, const char *value)
{
	if (opt->type == OC_FORM_OPT_SELECT) {
		struct oc_form_opt_select *sopt = (void *)opt;
		int i;

		for (i=0; i<sopt->nr_choices; i++) {
			if (!strcmp(value, sopt->choices[i]->name)) {
				opt->_value = sopt->choices[i]->name;
				return 0;
			}
		}
		return -EINVAL;
	}

	opt->_value = strdup(value);
	if (!opt->_value)
		return -ENOMEM;

	return 0;
}

static int prop_equals(xmlNode *xml_node, const char *name, const char *value)
{
	char *tmp = (char *)xmlGetProp(xml_node, (unsigned char *)name);
	int ret = 0;

	if (tmp && !strcasecmp(tmp, value))
		ret = 1;
	free(tmp);
	return ret;
}

static int parse_auth_choice(struct openconnect_info *vpninfo, struct oc_auth_form *form,
			     xmlNode *xml_node)
{
	struct oc_form_opt_select *opt;
	xmlNode *opt_node;
	int max_choices = 0, selection = 0;

	for (opt_node = xml_node->children; opt_node; opt_node = opt_node->next)
		max_choices++;

	/* Return early when there is a <select/> tag with no children */
	if (max_choices == 0) {
		return 0;
	}

	opt = calloc(1, sizeof(*opt));
	if (!opt)
		return -ENOMEM;

	opt->form.type = OC_FORM_OPT_SELECT;
	opt->form.name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");
	opt->form.label = (char *)xmlGetProp(xml_node, (unsigned char *)"label");

	if (!opt->form.name) {
		vpn_progress(vpninfo, PRG_ERR, _("Form choice has no name\n"));
		free_opt((struct oc_form_opt *)opt);
		return -EINVAL;
	}


	opt->choices = calloc(1, max_choices * sizeof(struct oc_choice *));
	if (!opt->choices) {
		free_opt((struct oc_form_opt *)opt);
		return -ENOMEM;
	}

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		char *form_id;
		struct oc_choice *choice;

		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (strcmp((char *)xml_node->name, "option"))
			continue;

		form_id = (char *)xmlGetProp(xml_node, (unsigned char *)"value");
		if (!form_id)
			form_id = (char *)xmlNodeGetContent(xml_node);
		if (!form_id)
			continue;

		choice = calloc(1, sizeof(*choice));
		if (!choice) {
			free_opt((struct oc_form_opt *)opt);
			return -ENOMEM;
		}

		choice->name = form_id;
		choice->label = (char *)xmlNodeGetContent(xml_node);
		choice->auth_type = (char *)xmlGetProp(xml_node, (unsigned char *)"auth-type");
		choice->override_name = (char *)xmlGetProp(xml_node, (unsigned char *)"override-name");
		choice->override_label = (char *)xmlGetProp(xml_node, (unsigned char *)"override-label");

		choice->second_auth = prop_equals(xml_node, "second-auth", "1");
		choice->secondary_username = (char *)xmlGetProp(xml_node,
			(unsigned char *)"secondary_username");
		choice->secondary_username_editable = prop_equals(xml_node,
			"secondary_username_editable", "true");
		choice->noaaa = prop_equals(xml_node, "noaaa", "1");

		if (prop_equals(xml_node, "selected", "true"))
			selection = opt->nr_choices;

		opt->choices[opt->nr_choices++] = choice;
	}

	if (!strcmp(opt->form.name, "group_list")) {
		form->authgroup_opt = opt;
		form->authgroup_selection = selection;
	}

	/* We link the choice _first_ so it's at the top of what we present
	   to the user */
	opt->form.next = form->opts;
	form->opts = &opt->form;
	return 0;
}

static int parse_form(struct openconnect_info *vpninfo, struct oc_auth_form *form,
		      xmlNode *xml_node)
{
	char *input_type, *input_name, *input_label;

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		struct oc_form_opt *opt, **p;

		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (!strcmp((char *)xml_node->name, "select")) {
			if (parse_auth_choice(vpninfo, form, xml_node))
				return -EINVAL;
			continue;
		}
		if (strcmp((char *)xml_node->name, "input")) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("name %s not input\n"), xml_node->name);
			continue;
		}

		input_type = (char *)xmlGetProp(xml_node, (unsigned char *)"type");
		if (!input_type) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("No input type in form\n"));
			continue;
		}

		if (!strcmp(input_type, "submit") || !strcmp(input_type, "reset")) {
			free(input_type);
			continue;
		}

		input_name = (char *)xmlGetProp(xml_node, (unsigned char *)"name");
		if (!input_name) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("No input name in form\n"));
			free(input_type);
			continue;
		}
		input_label = (char *)xmlGetProp(xml_node, (unsigned char *)"label");
		if (!input_label && asprintf(&input_label, "%s:", input_name) == -1)
			goto nomem;

		opt = calloc(1, sizeof(*opt));
		if (!opt) {
		nomem:
			free(input_type);
			free(input_name);
			free(input_label);
			return -ENOMEM;
		}

		opt->name = input_name;
		opt->label = input_label;
		opt->flags = prop_equals(xml_node, "second-auth", "1") ? OC_FORM_OPT_SECOND_AUTH : 0;

		if (!strcmp(input_type, "hidden")) {
			opt->type = OC_FORM_OPT_HIDDEN;
			opt->_value = (char *)xmlGetProp(xml_node, (unsigned char *)"value");
		} else if (!strcmp(input_type, "text")) {
			opt->type = OC_FORM_OPT_TEXT;
		} else if (!strcmp(input_type, "sso")) {
			opt->type = OC_FORM_OPT_SSO_TOKEN;
		} else if (!strcmp(input_type, "password")) {
			if (!cstp_can_gen_tokencode(vpninfo, form, opt))
				opt->type = OC_FORM_OPT_TOKEN;
			else
				opt->type = OC_FORM_OPT_PASSWORD;
		} else {
			vpn_progress(vpninfo, PRG_INFO,
				     _("Unknown input type %s in form\n"),
				     input_type);
			free(input_type);
			free(input_name);
			free(input_label);
			free(opt);
			continue;
		}

		free(input_type);

		p = &form->opts;
		while (*p)
			p = &(*p)->next;

		*p = opt;
	}

	return 0;
}

static char *xmlnode_msg(xmlNode *xml_node)
{
	char *fmt = (char *)xmlNodeGetContent(xml_node);
	char *result, *params[2], *pct;
	int len;
	int nr_params = 0;

	if (!fmt || !fmt[0]) {
		free(fmt);
		return NULL;
	}

	len = strlen(fmt) + 1;

	params[0] = (char *)xmlGetProp(xml_node, (unsigned char *)"param1");
	if (params[0])
		len += strlen(params[0]);
	params[1] = (char *)xmlGetProp(xml_node, (unsigned char *)"param2");
	if (params[1])
		len += strlen(params[1]);

	result = malloc(len);
	if (!result) {
		result = fmt;
		goto out;
	}

	strcpy(result, fmt);
	free(fmt);

	for (pct = strchr(result, '%'); pct;
	     (pct = strchr(pct, '%'))) {
		int paramlen;

		/* We only cope with '%s' */
		if (pct[1] != 's')
			goto out;

		if (params[nr_params]) {
			paramlen = strlen(params[nr_params]);
			/* Move rest of fmt string up... */
			memmove(pct + paramlen, pct + 2, strlen(pct + 2) + 1);
			/* ... and put the string parameter in where the '%s' was */
			memcpy(pct, params[nr_params], paramlen);
			pct += paramlen;
		} else
			pct++;

		if (++nr_params == 2)
			break;
	}
 out:
	free(params[0]);
	free(params[1]);
	return result;
}

static int xmlnode_get_text(xmlNode *xml_node, const char *name, char **var)
{
	char *str;

	if (name && !xmlnode_is_named(xml_node, name))
		return -EINVAL;

	str = xmlnode_msg(xml_node);
	if (!str)
		return -ENOENT;

	free(*var);
	*var = str;
	return 0;
}

/*
 * Legacy server response looks like:
 *
 * <auth id="<!-- "main" for initial attempt, "success" means we have a cookie -->">
 *   <title><!-- title to display to user --></title>
 *   <csd
 *        token="<!-- save to vpninfo->csd_token -->"
 *        ticket="<!-- save to vpninfo->csd_ticket -->" />
 *   <csd
 *        stuburl="<!-- save to vpninfo->csd_stuburl if --os=win -->"
 *        starturl="<!-- save to vpninfo->csd_starturl if --os=win -->"
 *        waiturl="<!-- save to vpninfo->csd_waiturl if --os=win -->"
 *   <csdMac
 *        stuburl="<!-- save to vpninfo->csd_stuburl if --os=mac-intel -->"
 *        starturl="<!-- save to vpninfo->csd_starturl if --os=mac-intel -->"
 *        waiturl="<!-- save to vpninfo->csd_waiturl if --os=mac-intel -->" />
 *   <csdLinux
 *        stuburl="<!-- same as above, for Linux -->"
 *        starturl="<!-- same as above, for Linux -->"
 *        waiturl="<!-- same as above, for Linux -->" />
 *   <banner><!-- display this to the user --></banner>
 *   <message>Please enter your username and password.</message>
 *   <form method="post" action="/+webvpn+/index.html">
 *     <input type="text" name="username" label="Username:" />
 *     <input type="password" name="password" label="Password:" />
 *     <input type="hidden" name="<!-- save these -->" value="<!-- ... -->" />
 *     <input type="submit" name="Login" value="Login" />
 *     <input type="reset" name="Clear" value="Clear" />
 *   </form>
 * </auth>
 *
 * New server response looks like:
 *
 * <config-auth>
 *   <version><!-- whatever --></version>
 *   <session-token><!-- if present, save to vpninfo->cookie --></session-token>
 *   <opaque>
 *     <!-- this could contain anything; copy to vpninfo->opaque_srvdata -->
 *     <tunnel-group>foobar</tunnel-group>
 *     <config-hash>1234567</config-hash>
 *   </opaque>
 *   <auth id="<!-- see above -->
 *     <!-- all of our old familiar fields -->
 *   </auth>
 *   <host-scan>
 *     <host-scan-ticket><!-- save to vpninfo->csd_ticket --></host-scan-ticket>
 *     <host-scan-token><!-- save to vpninfo->csd_token --></host-scan-token>
 *     <host-scan-base-uri><!-- save to vpninfo->csd_starturl --></host-scan-base-uri>
 *     <host-scan-wait-uri><!-- save to vpninfo->csd_waiturl --></host-scan-wait-uri>
 *   </host-scan>
 * </config-auth>
 *
 * Notes:
 *
 * 1) The new host-scan-*-uri nodes do not map directly to the old CSD fields.
 *
 * 2) The new <form> tag tends to omit the method/action properties.
 */

/* Translate platform names (derived from AnyConnect) into the relevant
 * CSD tag names
 */
static inline const char *csd_tag_name(struct openconnect_info *vpninfo)
{
	if (!strcmp(vpninfo->platname, "mac-intel"))
		return "csdMac";
	else if (!strcmp(vpninfo->platname, "win"))
		return "csd";
	else
		/* linux, linux-64, android, apple-ios */
		return "csdLinux";
}

/* Ignore stubs on mobile platforms */
static inline int csd_use_stub(struct openconnect_info *vpninfo)
{
	if (!strcmp(vpninfo->platname, "android") || !strcmp(vpninfo->platname, "apple-ios"))
		return 0;
	else
		return 1;
}

static int parse_auth_node(struct openconnect_info *vpninfo, xmlNode *xml_node,
			   struct oc_auth_form *form)
{
	int ret = 0;

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		xmlnode_get_text(xml_node, "banner", &form->banner);
		xmlnode_get_text(xml_node, "message", &form->message);
		xmlnode_get_text(xml_node, "error", &form->error);
		xmlnode_get_text(xml_node, "sso-v2-login", &vpninfo->sso_login);
		xmlnode_get_text(xml_node, "sso-v2-login-final", &vpninfo->sso_login_final);
		xmlnode_get_text(xml_node, "sso-v2-token-cookie-name", &vpninfo->sso_token_cookie);
		xmlnode_get_text(xml_node, "sso-v2-error-cookie-name", &vpninfo->sso_error_cookie);
		xmlnode_get_text(xml_node, "sso-v2-browser-mode", &vpninfo->sso_browser_mode);

		if (xmlnode_is_named(xml_node, "form")) {

			/* defaults for new XML POST */
			form->method = strdup("POST");

			xmlnode_get_prop(xml_node, "method", &form->method);
			xmlnode_get_prop(xml_node, "action", &form->action);

			/* - expect unset action (reuse current URL) or non-empty action="..."
			 * - expect unset method (defaults to "POST") or explicit method="POST"
			 */
			if ((form->action && !form->action[0]) ||
			    !form->method || strcasecmp(form->method, "POST")) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Cannot handle form method='%s', action='%s'\n"),
					     form->method, form->action);
				ret = -EINVAL;
				goto out;
			}

			ret = parse_form(vpninfo, form, xml_node);
			if (ret < 0)
				goto out;
		} else if (!vpninfo->csd_scriptname && xmlnode_is_named(xml_node, "csd")) {
			xmlnode_get_prop(xml_node, "token", &vpninfo->csd_token);
			xmlnode_get_prop(xml_node, "ticket", &vpninfo->csd_ticket);
		} else if (xmlnode_is_named(xml_node, "authentication-complete")) {
			/* Ick. Since struct oc_auth_form is public there's no
			 * simple way to add a flag to it. So let's abuse the
			 * auth_id string instead. */
			free(form->auth_id);
			form->auth_id = strdup("openconnect_authentication_complete");
		}
		/* For Windows, vpninfo->csd_xmltag will be "csd" and there are *two* <csd>
		   nodes; one with token/ticket and one with the URLs. Process them both
		   the same and rely on the fact that xmlnode_get_prop() will not *clear*
		   the variable if no such property is found. */
		if (!vpninfo->csd_scriptname && xmlnode_is_named(xml_node, csd_tag_name(vpninfo))) {
			/* ignore the CSD trojan binary on mobile platforms */
			if (csd_use_stub(vpninfo))
				xmlnode_get_prop(xml_node, "stuburl", &vpninfo->csd_stuburl);
			xmlnode_get_prop(xml_node, "starturl", &vpninfo->csd_starturl);
			xmlnode_get_prop(xml_node, "waiturl", &vpninfo->csd_waiturl);
			vpninfo->csd_preurl = strdup(vpninfo->urlpath);
		}
	}

out:
	return ret;
}

static int parse_host_scan_node(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	/* ignore this whole section if the CSD trojan has already run */
	if (vpninfo->csd_scriptname)
		return 0;

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		xmlnode_get_text(xml_node, "host-scan-ticket", &vpninfo->csd_ticket);
		xmlnode_get_text(xml_node, "host-scan-token", &vpninfo->csd_token);
		xmlnode_get_text(xml_node, "host-scan-base-uri", &vpninfo->csd_starturl);
		xmlnode_get_text(xml_node, "host-scan-wait-uri", &vpninfo->csd_waiturl);
	}
	return 0;
}

static void parse_profile_node(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	/* ignore this whole section if we already have a URL */
	if (vpninfo->profile_url && vpninfo->profile_sha1)
		return;

	/* Find <vpn rev="1.0"> child... */
	xml_node = xml_node->children;
	while (1) {
		if (!xml_node)
			return;

		if (xml_node->type == XML_ELEMENT_NODE &&
		    xmlnode_is_named(xml_node, "vpn") &&
		    !xmlnode_match_prop(xml_node, "rev", "1.0"))
			break;

		xml_node = xml_node->next;
	}

	/* Find <file type="profile" service-type="user"> */
	xml_node = xml_node->children;
	while (1) {
		if (!xml_node)
			return;

		if (xml_node->type == XML_ELEMENT_NODE &&
		    xmlnode_is_named(xml_node, "file") &&
		    !xmlnode_match_prop(xml_node, "type", "profile") &&
		    !xmlnode_match_prop(xml_node, "service-type", "user"))
			break;

		xml_node = xml_node->next;
	}

	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		xmlnode_get_text(xml_node, "uri", &vpninfo->profile_url);
		/* FIXME: Check for <hash type="sha1"> */
		xmlnode_get_text(xml_node, "hash", &vpninfo->profile_sha1);
	}
}

static void parse_config_node(struct openconnect_info *vpninfo, xmlNode *xml_node)
{
	for (xml_node = xml_node->children; xml_node; xml_node = xml_node->next) {
		if (xml_node->type != XML_ELEMENT_NODE)
			continue;

		if (xmlnode_is_named(xml_node, "vpn-profile-manifest"))
			parse_profile_node(vpninfo, xml_node);
	}
}

/* Return value:
 *  < 0, on error
 *  = 0, on success; *form is populated
 */
static int parse_xml_response(struct openconnect_info *vpninfo,
			      char *response,struct oc_auth_form **formp,
			      struct cert_request *cert_rq)
{
	struct oc_auth_form *form;
	xmlDocPtr xml_doc;
	xmlNode *xml_node;
	int old_cert_rq_state = 0;
	int ret;

	if (*formp) {
		free_auth_form(*formp);
		*formp = NULL;
	}
	if (cert_rq) {
		old_cert_rq_state = cert_rq->state;
		*cert_rq = (struct cert_request) { 0 };
	}

	if (!response) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Empty response from server\n"));
		return -EINVAL;
	}

	form = calloc(1, sizeof(*form));
	if (!form)
		return -ENOMEM;
	xml_doc = xmlReadMemory(response, strlen(response), NULL, NULL,
				XML_PARSE_NOERROR|XML_PARSE_RECOVER);
	if (!xml_doc) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to parse server response\n"));
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Response was:%s\n"), response);
		free(form);
		return -EINVAL;
	}

	xml_node = xmlDocGetRootElement(xml_doc);
	while (xml_node) {
		ret = 0;

		if (xml_node->type != XML_ELEMENT_NODE) {
			xml_node = xml_node->next;
			continue;
		}
		if (xmlnode_is_named(xml_node, "config-auth")) {
			/* if we do have a config-auth node, it is the root element */
			xml_node = xml_node->children;
			continue;
		} else if (xmlnode_is_named(xml_node, "client-cert-request")) {
			if (cert_rq)
				cert_rq->state |= CERT1_REQUESTED;
			else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Received <client-cert-request> when not expected.\n"));
				ret = -EINVAL;
			}
		} else if (xmlnode_is_named(xml_node, "multiple-client-cert-request")) {
			if (cert_rq) {
				cert_rq->state |= CERT1_REQUESTED|CERT2_REQUESTED;
				parse_multicert_request(vpninfo, xml_node, cert_rq);
			} else {
				vpn_progress(vpninfo, PRG_ERR,
		     _("Received <multiple-client-cert-request> when not expected.\n"));
				ret = -EINVAL;
			}
		} else if (xmlnode_is_named(xml_node, "cert-authenticated")) {
			/**
			 * cert-authenticated indicates that the certificate for the
			 * TLS session is valid.
			 */
			if (cert_rq)
				cert_rq->state |= CERT1_AUTHENTICATED;
		} else if (xmlnode_is_named(xml_node, "auth")) {
			xmlnode_get_prop(xml_node, "id", &form->auth_id);
			ret = parse_auth_node(vpninfo, xml_node, form);
		} else if (xmlnode_is_named(xml_node, "opaque")) {
			if (vpninfo->opaque_srvdata)
				xmlFreeNode(vpninfo->opaque_srvdata);
			vpninfo->opaque_srvdata = xmlCopyNode(xml_node, 1);
			if (!vpninfo->opaque_srvdata)
				ret = -ENOMEM;
		} else if (xmlnode_is_named(xml_node, "host-scan")) {
			ret = parse_host_scan_node(vpninfo, xml_node);
		} else if (xmlnode_is_named(xml_node, "config")) {
			parse_config_node(vpninfo, xml_node);
		} else if (xmlnode_is_named(xml_node, "session-token")) {
			http_add_cookie(vpninfo, "webvpn",
					(const char *)xmlNodeGetContent(xml_node), 1);
		} else {
			xmlnode_get_text(xml_node, "error", &form->error);
		}

		if (ret)
			goto out;
		xml_node = xml_node->next;
	}

	if ((old_cert_rq_state & CERT2_REQUESTED) && form->error) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Server reported certificate error: %s.\n"), form->error);
		ret = -EINVAL;
		goto out;
	}

	if (!form->auth_id && (!cert_rq || !cert_rq->state)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("XML response has no \"auth\" node\n"));
		ret = -EINVAL;
		goto out;
	}

	*formp = form;
	xmlFreeDoc(xml_doc);
	return 0;

 out:
	xmlFreeDoc(xml_doc);
	free_auth_form(form);
	return ret;
}

/* Return value:
 *  < 0, on error
 *  = OC_FORM_RESULT_OK (0), when form parsed and POST required
 *  = OC_FORM_RESULT_CANCELLED, when response was cancelled by user
 *  = OC_FORM_RESULT_LOGGEDIN, when form indicates that login was already successful
 */
static int handle_auth_form(struct openconnect_info *vpninfo, struct oc_auth_form *form,
			    struct oc_text_buf *request_body, const char **method,
			    const char **request_body_type)
{
	int ret;
	struct oc_vpn_option *opt, *next;

	if (!form) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     "The authentication form is NULL\n");
		return -EPERM;
	}

	if (!strcmp(form->auth_id, "success"))
		return OC_FORM_RESULT_LOGGEDIN;

	if (vpninfo->nopasswd) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Asked for password but '--no-passwd' set\n"));
		return -EPERM;
	}

	if (vpninfo->csd_token && vpninfo->csd_ticket && vpninfo->csd_starturl && vpninfo->csd_waiturl) {
		/* AB: remove all cookies */
		for (opt = vpninfo->cookies; opt; opt = next) {
			next = opt->next;

			free(opt->option);
			free(opt->value);
			free(opt);
		}
		vpninfo->cookies = NULL;
		return OC_FORM_RESULT_OK;
	}
	if (!form->opts) {
		if (form->message)
			vpn_progress(vpninfo, PRG_INFO, "%s\n", form->message);
		if (form->error) {
			if (!strcmp(form->error, "Certificate Validation Failure")) {
				/* XX: Cisco servers send this ambiguous error string when the CLIENT certificate
				 * is absent or incorrect. We rewrite it to make this clearer, while preserving
				 * the original error as a substring.
				 */
				free(form->error);
				if (!(form->error = strdup(_("Client certificate missing or incorrect (Certificate Validation Failure)"))))
					return -ENOMEM;
			} else
				vpn_progress(vpninfo, PRG_ERR, "%s\n", form->error);
		}
		if (!strcmp(form->auth_id, "openconnect_authentication_complete"))
			goto justpost;
		return -EPERM;
	}

	ret = process_auth_form(vpninfo, form);
	if (ret)
		return ret;

	/* tokencode generation is deferred until after username prompts and CSD */
	ret = do_gen_tokencode(vpninfo, form);
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to generate OTP tokencode; disabling token\n"));
		vpninfo->token_bypassed = 1;
		return ret;
	}
 justpost:
	ret = vpninfo->xmlpost ?
	      xmlpost_append_form_opts(vpninfo, form, request_body) :
	      append_form_opts(vpninfo, form, request_body);
	if (!ret) {
		*method = "POST";
		*request_body_type = vpninfo->xmlpost ? "application/xml; charset=utf-8" : "application/x-www-form-urlencoded";
	}
	return ret;
}

/*
 * Old submission format is just an HTTP query string:
 *
 * password=12345678&username=joe
 *
 * New XML format is more complicated:
 *
 * <config-auth client="vpn" type="<!-- init or auth-reply -->">
 *   <version who="vpn"><!-- currently just the OpenConnect version --></version>
 *   <device-id><!-- linux, linux-64, win, ... --></device-id>
 *   <opaque is-for="<!-- some name -->">
 *     <!-- just copy this verbatim from whatever the gateway sent us -->
 *   </opaque>
 *
 * For init only, add:
 *   <group-access>https://<!-- insert hostname here --></group-access>
 *
 * For auth-reply only, add:
 *   <auth>
 *     <username><!-- same treatment as the old form options --></username>
 *     <password><!-- ditto -->
 *   </auth>
 *   <group-select><!-- name of selected authgroup --></group-select>
 *   <host-scan-token><!-- vpninfo->csd_ticket --></host-scan-token>
 */

#define XCAST(x) ((const xmlChar *)(x))

static xmlDocPtr xmlpost_new_query(struct openconnect_info *vpninfo, const char *type,
				   xmlNodePtr *rootp)
{
	xmlDocPtr doc;
	xmlNodePtr root, node, capabilities;

	doc = xmlNewDoc(XCAST("1.0"));
	if (!doc)
		return NULL;

	root = xmlNewNode(NULL, XCAST("config-auth"));
	if (!root)
		goto bad;
	xmlDocSetRootElement(doc, root);

	if (!xmlNewProp(root, XCAST("client"), XCAST("vpn")))
		goto bad;
	if (!xmlNewProp(root, XCAST("type"), XCAST(type)))
		goto bad;
	if (!xmlNewProp(root, XCAST("aggregate-auth-version"), XCAST("2")))
		goto bad;

	node = xmlNewTextChild(root, NULL, XCAST("version"),
			       XCAST(vpninfo->version_string ? : openconnect_version_str));
	if (!node)
		goto bad;
	if (!xmlNewProp(node, XCAST("who"), XCAST("vpn")))
		goto bad;

	node = xmlNewTextChild(root, NULL, XCAST("device-id"), XCAST(vpninfo->platname));
	if (!node)
		goto bad;
	if (vpninfo->mobile_platform_version) {
		if (!xmlNewProp(node, XCAST("platform-version"), XCAST(vpninfo->mobile_platform_version)) ||
		    !xmlNewProp(node, XCAST("device-type"), XCAST(vpninfo->mobile_device_type)) ||
		    !xmlNewProp(node, XCAST("unique-id"), XCAST(vpninfo->mobile_device_uniqueid)))
			goto bad;
	}

	capabilities = xmlNewNode(NULL, XCAST("capabilities"));
	if (!capabilities)
		goto bad;
	capabilities = xmlAddChild(root, capabilities);
	if (!capabilities)
		goto bad;

	if (!vpninfo->no_external_auth) {
		node = xmlNewTextChild(capabilities, NULL, XCAST("auth-method"), XCAST("single-sign-on-v2"));
		if (!node)
			goto bad;

#ifdef HAVE_HPKE_SUPPORT
		node = xmlNewTextChild(capabilities, NULL, XCAST("auth-method"), XCAST("single-sign-on-external-browser"));
		if (!node)
			goto bad;
#endif
	}

	if (vpninfo->certinfo[1].cert) {
		node = xmlNewTextChild(capabilities, NULL, XCAST("auth-method"), XCAST("multiple-cert"));
		if (!node)
			goto bad;
	}

	*rootp = root;
	return doc;

bad:
	xmlFreeDoc(doc);
	return NULL;
}

static int xmlpost_complete(xmlDocPtr doc, struct oc_text_buf *body)
{
	xmlChar *mem = NULL;
	int len, ret = 0;

	if (!body) {
		xmlFree(doc);
		return 0;
	}

	xmlDocDumpMemoryEnc(doc, &mem, &len, "UTF-8");
	if (!mem) {
		xmlFreeDoc(doc);
		return -ENOMEM;
	}

	buf_append_bytes(body, mem, len);

	xmlFreeDoc(doc);
	xmlFree(mem);

	return ret;
}

static int xmlpost_initial_req(struct openconnect_info *vpninfo,
			       struct oc_text_buf *request_body, int cert_fail)
{
	xmlNodePtr root, node;
	xmlDocPtr doc = xmlpost_new_query(vpninfo, "init", &root);
	char *url;

	if (!doc)
		return -ENOMEM;

	url = internal_get_url(vpninfo);
	if (!url)
		goto bad;

	node = xmlNewTextChild(root, NULL, XCAST("group-access"), XCAST(url));
	if (!node)
		goto bad;

	if (cert_fail) {
		node = xmlNewTextChild(root, NULL, XCAST("client-cert-fail"), NULL);
		if (!node)
			goto bad;
	}
	if (vpninfo->authgroup) {
		node = xmlNewTextChild(root, NULL, XCAST("group-select"), XCAST(vpninfo->authgroup));
		if (!node)
			goto bad;
	}
	free(url);
	return xmlpost_complete(doc, request_body);

bad:
	xmlpost_complete(doc, NULL);
	return -ENOMEM;
}

static int xmlpost_append_form_opts(struct openconnect_info *vpninfo,
				    struct oc_auth_form *form, struct oc_text_buf *body)
{
	xmlNodePtr root, node;
	xmlDocPtr doc = xmlpost_new_query(vpninfo, "auth-reply", &root);
	struct oc_form_opt *opt;

	if (!doc)
		return -ENOMEM;

	if (vpninfo->opaque_srvdata) {
		node = xmlCopyNode(vpninfo->opaque_srvdata, 1);
		if (!node)
			goto bad;
		if (!xmlAddChild(root, node))
			goto bad;
	}

	node = xmlNewChild(root, NULL, XCAST("auth"), NULL);
	if (!node)
		goto bad;

	for (opt = form->opts; opt; opt = opt->next) {
		/* group_list: create a new <group-select> node under <config-auth> */
		if (!strcmp(opt->name, "group_list")) {
			if (!xmlNewTextChild(root, NULL, XCAST("group-select"), XCAST(opt->_value)))
				goto bad;
			continue;
		}

		/* answer,whichpin,new_password: rename to "password" */
		if (!strcmp(opt->name, "answer") ||
		    !strcmp(opt->name, "whichpin") ||
		    !strcmp(opt->name, "new_password")) {
			if (!xmlNewTextChild(node, NULL, XCAST("password"), XCAST(opt->_value)))
				goto bad;
			continue;
		}

		/* verify_pin,verify_password: ignore */
		if (!strcmp(opt->name, "verify_pin") ||
		    !strcmp(opt->name, "verify_password")) {
			continue;
		}

		/* everything else: create <foo>user_input</foo> under <auth> */
		if (!xmlNewTextChild(node, NULL, XCAST(opt->name), XCAST(opt->_value)))
			goto bad;
	}

	if (vpninfo->csd_token &&
	    !xmlNewTextChild(root, NULL, XCAST("host-scan-token"), XCAST(vpninfo->csd_token)))
		goto bad;

	return xmlpost_complete(doc, body);

bad:
	xmlpost_complete(doc, NULL);
	return -ENOMEM;
}

/* Return value:
 *  < 0, if unable to generate a tokencode
 *  = 0, on success
 */
static int cstp_can_gen_tokencode(struct openconnect_info *vpninfo,
				  struct oc_auth_form *form,
				  struct oc_form_opt *opt)
{
	if (vpninfo->token_mode == OC_TOKEN_MODE_NONE ||
	    vpninfo->token_bypassed)
		return -EINVAL;

#ifdef HAVE_LIBSTOKEN
	if (vpninfo->token_mode == OC_TOKEN_MODE_STOKEN) {
		if (strcmp(opt->name, "password") &&
		    strcmp(opt->name, "answer"))
			return -EINVAL;
		return can_gen_stoken_code(vpninfo, form, opt);
	}
#endif
	/* Otherwise it's an OATH token of some kind. */
	if (!strcmp(opt->name, "secondary_password") ||
	    (form->auth_id && !strcmp(form->auth_id, "challenge")))
		return can_gen_tokencode(vpninfo, form, opt);

	return -EINVAL;
}

static int fetch_config(struct openconnect_info *vpninfo)
{
	struct oc_text_buf *buf;
	int result;
	unsigned char local_sha1_bin[SHA1_SIZE];
	char local_sha1_ascii[(SHA1_SIZE * 2)+1];
	int i;

	if (!vpninfo->profile_url || !vpninfo->profile_sha1 || !vpninfo->write_new_config)
		return -ENOENT;

	if (!strncasecmp(vpninfo->xmlsha1, vpninfo->profile_sha1, SHA1_SIZE * 2)) {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Not downloading XML profile because SHA1 already matches\n"));
		return 0;
	}

	if ((result = openconnect_open_https(vpninfo))) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to open HTTPS connection to %s\n"),
			     vpninfo->hostname);
		return result;
	}

	buf = buf_alloc();

	if (vpninfo->port != 443)
		buf_append(buf, "GET %s:%d HTTP/1.1\r\n", vpninfo->profile_url, vpninfo->port);
	else
		buf_append(buf, "GET %s HTTP/1.1\r\n", vpninfo->profile_url);
	cstp_common_headers(vpninfo, buf);
	buf_append(buf, "\r\n");

	if (buf_error(buf))
		return buf_free(buf);

	if (vpninfo->dump_http_traffic)
		dump_buf(vpninfo, '>', buf->data);

	if (vpninfo->ssl_write(vpninfo, buf->data, buf->pos) != buf->pos) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to send GET request for new config\n"));
		buf_free(buf);
		return -EIO;
	}

	result = process_http_response(vpninfo, 0, NULL, buf);
	if (result < 0) {
		/* We'll already have complained about whatever offended us */
		buf_free(buf);
		return -EINVAL;
	}

	if (result != 200) {
		buf_free(buf);
		return -EINVAL;
	}

	openconnect_sha1(local_sha1_bin, buf->data, buf->pos);

	for (i = 0; i < SHA1_SIZE; i++)
		sprintf(&local_sha1_ascii[i*2], "%02x", local_sha1_bin[i]);

	if (strcasecmp(vpninfo->profile_sha1, local_sha1_ascii)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Downloaded config file did not match intended SHA1\n"));
		buf_free(buf);
		return -EINVAL;
	}

	vpn_progress(vpninfo, PRG_DEBUG, _("Downloaded new XML profile\n"));

	result = vpninfo->write_new_config(vpninfo->cbdata, buf->data, buf->pos);
	buf_free(buf);
	return result;
}

int set_csd_user(struct openconnect_info *vpninfo)
{
#if defined(_WIN32) || defined(__native_client__)
	vpn_progress(vpninfo, PRG_ERR,
		     _("Error: Running the 'Cisco Secure Desktop' trojan on this platform is not yet implemented.\n"));
	return -EPERM;
#else
	setsid();

	if (vpninfo->uid_csd_given && vpninfo->uid_csd != getuid()) {
		struct passwd pwd, *result;
		char buffer[2049]; /* should be sysconf(_SC_GETPW_R_SIZE_MAX) */
		int err;

		if (setgid(vpninfo->gid_csd)) {
			err = errno;
			fprintf(stderr, _("Failed to set gid %ld: %s\n"),
				(long)vpninfo->uid_csd, strerror(err));
			return -err;
		}

		if (setgroups(1, &vpninfo->gid_csd)) {
			err = errno;
			fprintf(stderr, _("Failed to set groups to %ld: %s\n"),
				(long)vpninfo->uid_csd, strerror(err));
			return -err;
		}

		if (setuid(vpninfo->uid_csd)) {
			err = errno;
			fprintf(stderr, _("Failed to set uid %ld: %s\n"),
				(long)vpninfo->uid_csd, strerror(err));
			return -err;
		}

		if ((err = getpwuid_r(vpninfo->uid_csd, &pwd, buffer, sizeof(buffer),
				&result)) || !result) {
			fprintf(stderr, _("Invalid user uid=%ld: %s\n"),
				(long)vpninfo->uid_csd, strerror(err));
			return -err;
		}
		setenv("HOME", result->pw_dir, 1);
		if (chdir(result->pw_dir)) {
			err = errno;
			fprintf(stderr, _("Failed to change to CSD home directory '%s': %s\n"),
				result->pw_dir, strerror(err));
			return -err;
		}
	}
	return 0;
#endif
}

static int run_csd_script(struct openconnect_info *vpninfo, char *buf, int buflen)
{
#if defined(_WIN32) || defined(__native_client__)
	vpn_progress(vpninfo, PRG_ERR,
		     _("Error: Running the 'Cisco Secure Desktop' trojan on this platform is not yet implemented.\n"));
	return -EPERM;
#else
	char fname[64];
	int fd, ret;
	pid_t child;

	if (!vpninfo->csd_wrapper && !buflen) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error: Server asked us to run CSD hostscan.\n"
			       "You need to provide a suitable --csd-wrapper argument.\n"));
		return -EINVAL;
	}

	if (!vpninfo->uid_csd_given && !vpninfo->csd_wrapper) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error: Server asked us to download and run a 'Cisco Secure Desktop' trojan.\n"
			       "This facility is disabled by default for security reasons, so you may wish to enable it.\n"));
		return -EPERM;
	}

	fname[0] = 0;
	if (buflen) {
		struct oc_vpn_option *opt;
		const char *tmpdir = NULL;

		/* If the caller wanted $TMPDIR set for the CSD script, that
		   means for us too; look through the csd_env for a TMPDIR
		   override. */
		for (opt = vpninfo->csd_env; opt; opt = opt->next) {
			if (!strcmp(opt->option, "TMPDIR")) {
				tmpdir = opt->value;
				break;
			}
		}
		if (!opt)
			tmpdir = getenv("TMPDIR");

		if (!tmpdir && !access("/var/tmp", W_OK))
			tmpdir = "/var/tmp";
		if (!tmpdir)
			tmpdir = "/tmp";

		if (access(tmpdir, W_OK))
			vpn_progress(vpninfo, PRG_ERR,
				     _("Temporary directory '%s' is not writable: %s\n"),
				     tmpdir, strerror(errno));

		snprintf(fname, 64, "%s/csdXXXXXX", tmpdir);
		fd = mkstemp(fname);
		if (fd < 0) {
			int err = -errno;
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to open temporary CSD script file: %s\n"),
				     strerror(errno));
			return err;
		}

		ret = write(fd, (void *)buf, buflen);
		if (ret != buflen) {
			int err = -errno;
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to write temporary CSD script file: %s\n"),
				     strerror(errno));
			return err;
		}
		fchmod(fd, 0755);
		close(fd);
	}

	vpn_progress(vpninfo, PRG_INFO,
		     _("Trying to run CSD Trojan script '%s'.\n"),
		     vpninfo->csd_wrapper ?: fname);

	child = fork();
	if (child == -1) {
		goto out;
	} else if (child > 0) {
		/* in parent: must reap child process */
		int status;
		waitpid(child, &status, 0);
		if (!WIFEXITED(status)) {
			vpn_progress(vpninfo, PRG_ERR,
			             _("CSD script '%s' exited abnormally\n"),
			             vpninfo->csd_wrapper ?: fname);
			ret = -EINVAL;
		} else {
			if (WEXITSTATUS(status) != 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("CSD script '%s' returned non-zero status: %d\n"),
					     vpninfo->csd_wrapper ?: fname, WEXITSTATUS(status));
				/* Some scripts do exit non-zero, and it's never mattered.
				 * Don't abort for now. */
				vpn_progress(vpninfo, PRG_ERR,
					     _("Authentication may fail. If your script is not returning zero, fix it.\n"
					       "Future versions of openconnect will abort on this error.\n"));
			} else {
				vpn_progress(vpninfo, PRG_INFO,
					     _("CSD script '%s' completed successfully.\n"),
					     vpninfo->csd_wrapper ?: fname);
			}

			free(vpninfo->urlpath);
			vpninfo->urlpath = strdup(vpninfo->csd_waiturl +
			                          (vpninfo->csd_waiturl[0] == '/' ? 1 : 0));
			vpninfo->csd_scriptname = strdup(fname);
			http_add_cookie(vpninfo, "sdesktop", vpninfo->csd_token, 1);
			ret = 0;
		}

		free(vpninfo->csd_stuburl);
		vpninfo->csd_stuburl = NULL;
		free(vpninfo->csd_waiturl);
		vpninfo->csd_waiturl = NULL;

		return ret;
	} else {
		/* in child: will be reaped by init */
		char scertbuf[MD5_SIZE * 2 + 1];
		char ccertbuf[MD5_SIZE * 2 + 1];
		char *csd_argv[32];
		int i = 0;

		if (set_csd_user(vpninfo) < 0)
			exit(1);
		if (getuid() == 0 && !vpninfo->csd_wrapper) {
			fprintf(stderr, _("Warning: you are running insecure CSD code with root privileges\n"
			                  "\t Use command line option \"--csd-user\"\n"));
		}
		/*
		 * Spurious stdout output from the CSD trojan will break both
		 * the NM tool and the various cookieonly modes.
		 * Also, gnome-shell *closes* stderr so attempt to cope with that
		 * by opening /dev/null, because otherwise some CSD scripts fail.
		 * Actually, perhaps we should set up our own pipes, and report
		 * the trojan's output via vpn_progress().
		 */
		if (ferror(stderr)) {
			int nulfd = open("/dev/null", O_WRONLY);
			if (nulfd >= 0) {
				dup2(nulfd, 2);
				close(nulfd);
			}
		}
		dup2(2, 1);
		if (vpninfo->csd_wrapper)
			csd_argv[i++] = openconnect_utf8_to_legacy(vpninfo,
			                                           vpninfo->csd_wrapper);
		csd_argv[i++] = fname;
		csd_argv[i++] = (char *)"-ticket";
		if (asprintf(&csd_argv[i++], "\"%s\"", vpninfo->csd_ticket) == -1)
			goto out;
		csd_argv[i++] = (char *)"-stub";
		csd_argv[i++] = (char *)"\"0\"";
		csd_argv[i++] = (char *)"-group";
		if (asprintf(&csd_argv[i++], "\"%s\"", vpninfo->authgroup?:"") == -1)
			goto out;

		openconnect_local_cert_md5(vpninfo, ccertbuf);
		scertbuf[0] = 0;
		get_cert_md5_fingerprint(vpninfo, vpninfo->peer_cert, scertbuf);
		csd_argv[i++] = (char *)"-certhash";
		if (asprintf(&csd_argv[i++], "\"%s:%s\"", scertbuf, ccertbuf) == -1)
			goto out;


		csd_argv[i++] = (char *)"-url";
		if (asprintf(&csd_argv[i++], "\"https://%s%s\"", openconnect_get_hostname(vpninfo), vpninfo->csd_starturl) == -1)
			goto out;

		csd_argv[i++] = (char *)"-langselen";
		csd_argv[i++] = NULL;

		if (setenv("CSD_SHA256", openconnect_get_peer_cert_hash(vpninfo)+11, 1))  /* remove initial 'pin-sha256:' */
			goto out;
		if (setenv("CSD_TOKEN", vpninfo->csd_token, 1))
			goto out;
		if (setenv("CSD_HOSTNAME", openconnect_get_hostname(vpninfo), 1))
			goto out;

		apply_script_env(vpninfo->csd_env);

		execv(csd_argv[0], csd_argv);

	out:
		vpn_progress(vpninfo, PRG_ERR,
		             _("Failed to exec CSD script %s\n"), vpninfo->csd_wrapper ?: fname);
		exit(1);
	}

#endif /* !_WIN32 && !__native_client__ */
}


/* Return value:
 *  < 0, if the data is unrecognized
 *  = 0, if the page contains an XML document
 *  = 1, if the page is a wait/refresh HTML page
 */
static int check_response_type(struct openconnect_info *vpninfo, char *form_buf)
{
	if (strncmp(form_buf, "<?xml", 5)) {
		/* Not XML? Perhaps it's HTML with a refresh... */
		if (strcasestr(form_buf, "http-equiv=\"refresh\""))
			return 1;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Unknown response from server\n"));
		return -EINVAL;
	}
	return 0;
}

/* Return value:
 *  < 0, on error
 *  > 0, no cookie (user cancel)
 *  = 0, obtained cookie
 */
int cstp_obtain_cookie(struct openconnect_info *vpninfo)
{
	struct oc_vpn_option *opt;
	char *form_buf = NULL;
	struct oc_auth_form *form = NULL;
	int result, buflen, tries;
	struct oc_text_buf *request_body = buf_alloc();
	const char *request_body_type;
	const char *method = "POST";
	char *orig_host = NULL, *orig_path = NULL, *form_path = NULL;
	int orig_port = 0;
	struct cert_request cert_rq = { 0 };
	int cert_sent = !vpninfo->certinfo[0].cert;
	int newgroup_attempts = 5;

	if (!vpninfo->xmlpost)
		goto no_xmlpost;

	/*
	 * Step 2: Probe for XML POST compatibility
	 *
	 * This can get stuck in a redirect loop, so give up after any of:
	 *
	 * a) HTTP error (e.g. 400 Bad Request)
	 * b) Same-host redirect (e.g. Location: /foo/bar)
	 * c) Three redirects without seeing a plausible login form
	 */
newgroup:
	if (newgroup_attempts-- <= 0) {
		result = -1;
		goto out;
	}

	buf_truncate(request_body);
	result = xmlpost_initial_req(vpninfo, request_body, 0);
	if (result < 0)
		goto out;

	free(orig_host);
	free(orig_path);
	orig_host = strdup(vpninfo->hostname);
	orig_path = vpninfo->urlpath ? strdup(vpninfo->urlpath) : NULL;
	orig_port = vpninfo->port;

	for (tries = 0; ; tries++) {
		/**
		 * Multiple certificate authentication requires an additional exchange.
		 * tries == 0: redirect
		 * tries == 1: !cert_sent + initial_req
		 * tries == 2: cert_sent + initial_req
		 * tries == 3: challenge response
		 */
		if (tries == 3 + !!(cert_rq.state&CERT2_REQUESTED)) {
		fail:
			if (vpninfo->xmlpost) {
			no_xmlpost:
				/* Try without XML POST this time... */
				tries = 0;
				vpninfo->xmlpost = 0;
				request_body_type = NULL;
				buf_truncate(request_body);
				method = "GET";
				if (orig_host) {
					openconnect_set_hostname(vpninfo, orig_host);
					free(orig_host);
					orig_host = NULL;
					free(vpninfo->urlpath);
					vpninfo->urlpath = orig_path;
					orig_path = NULL;
					vpninfo->port = orig_port;
				}
				openconnect_close_https(vpninfo, 0);
			} else {
				result = -EIO;
				goto out;
			}
		}

		request_body_type = vpninfo->xmlpost ? "application/xml; charset=utf-8" : "application/x-www-form-urlencoded";
		result = do_https_request(vpninfo, method, request_body_type, request_body, &form_buf, NULL, HTTP_NO_FLAGS);
		if (vpninfo->got_cancel_cmd) {
			result = 1;
			goto out;
		}
		if (result == -EINVAL)
			goto fail;
		if (result < 0)
			goto out;

		/* Some ASAs forget to send the TLS cert request on the initial connection.
		 * If we have a client cert, disable HTTP keepalive until we get a real
		 * login form (not a redirect). */
		if (!cert_sent)
			openconnect_close_https(vpninfo, 0);

		/* XML POST does not allow local redirects, but GET does. */
		if (vpninfo->xmlpost &&
		    vpninfo->redirect_type == REDIR_TYPE_LOCAL)
			goto fail;
		else if (vpninfo->redirect_type != REDIR_TYPE_NONE)
			continue;

		result = parse_xml_response(vpninfo, form_buf, &form, &cert_rq);
		if (result < 0)
			goto fail;

		if ((cert_rq.state&CERT1_REQUESTED) &&
		    !(cert_rq.state&CERT1_AUTHENTICATED)) {
			int cert_failed = 0;

			free_auth_form(form);
			form = NULL;

			if (!cert_sent && vpninfo->certinfo[0].cert) {
				/* Try again on a fresh connection. */
				cert_sent = 1;
			} else if (cert_sent && vpninfo->certinfo[0].cert) {
				/* Try again with <client-cert-fail/> in the request */
				vpn_progress(vpninfo, PRG_ERR,
					     _("Server requested SSL client certificate after one was provided\n"));
				cert_failed = 1;
			} else {
				vpn_progress(vpninfo, PRG_INFO,
					     _("Server requested SSL client certificate; none was configured\n"));
				cert_failed = 1;
			}
			buf_truncate(request_body);
			result = xmlpost_initial_req(vpninfo, request_body, cert_failed);
			if (result < 0)
				goto fail;
			continue;
		} else if (cert_rq.state&CERT2_REQUESTED) {

			free_auth_form(form); form = NULL;
			buf_truncate(request_body);

			/** load the second certificate */
			struct cert_info *certinfo = &vpninfo->certinfo[1];
			if (!certinfo->cert) {
				/* This is a fail safe; we should never get here */
				vpn_progress(vpninfo, PRG_ERR,
				_("Multiple-certificate authentication requires a second certificate; none were configured.\n"));
				result = -EINVAL;
				(void) xmlpost_initial_req(vpninfo, request_body, 1);
				goto out;
			}

			result = load_certificate(vpninfo, certinfo, MULTICERT_COMPAT);
			if (result < 0) {
				(void) xmlpost_initial_req(vpninfo, request_body, 1);
				goto out;
			}

			result = prepare_multicert_response(vpninfo, cert_rq, form_buf,
				  request_body);

			unload_certificate(certinfo, 1);

			if (result < 0) {
				(void) xmlpost_initial_req(vpninfo, request_body, 0);
				goto fail;
			}

			continue;
		}
		if (form && form->action) {
			vpninfo->redirect_url = strdup(form->action);
			handle_redirect(vpninfo);
		}
		break;
	}
	if (vpninfo->xmlpost)
		vpn_progress(vpninfo, PRG_INFO, _("XML POST enabled\n"));

	/* Step 4: Run the CSD trojan, if applicable */
	if (vpninfo->csd_starturl && vpninfo->csd_waiturl) {
		buflen = 0;

		if (vpninfo->urlpath) {
			form_path = strdup(vpninfo->urlpath);
			if (!form_path) {
				result = -ENOMEM;
				goto out;
			}
		}

		/* fetch the CSD program, if available */
		if (vpninfo->csd_stuburl) {
			vpninfo->redirect_url = vpninfo->csd_stuburl;
			vpninfo->csd_stuburl = NULL;
			handle_redirect(vpninfo);

			buflen = do_https_request(vpninfo, "GET", NULL, NULL, &form_buf, NULL, HTTP_NO_FLAGS);
			if (buflen <= 0) {
				if (vpninfo->csd_wrapper) {
					vpn_progress(vpninfo, PRG_ERR,
					             _("Couldn't fetch CSD stub. Proceeding anyway with CSD wrapper script.\n"));
					buflen = 0;
				} else {
					result = -EINVAL;
					goto out;
				}
			} else
				vpn_progress(vpninfo, PRG_INFO,
					     _("Fetched CSD stub for %s platform (size is %d bytes).\n"),
					     vpninfo->platname, buflen);
		}

		/* This is the CSD stub script, which we now need to run */
		result = run_csd_script(vpninfo, form_buf, buflen);
		if (result)
			goto out;

		/* vpninfo->urlpath now points to the wait page */
		while (1) {
			result = do_https_request(vpninfo, "GET", NULL, NULL, &form_buf, NULL, HTTP_NO_FLAGS);
			if (result <= 0)
				break;

			result = check_response_type(vpninfo, form_buf);
			if (result <= 0)
				break;

			vpn_progress(vpninfo, PRG_INFO,
				     _("Refreshing %s after 1 second...\n"),
				     vpninfo->urlpath);
			sleep(1);
		}
		if (result < 0)
			goto out;

		/* refresh the form page, to see if we're authorized now */
		free(vpninfo->urlpath);
		vpninfo->urlpath = form_path;
		form_path = NULL;

		result = do_https_request(vpninfo,
					  vpninfo->xmlpost ? "POST" : "GET",
					  request_body_type, request_body, &form_buf, NULL, HTTP_REDIRECT);
		if (result < 0)
			goto out;

		result = parse_xml_response(vpninfo, form_buf, &form, NULL);
		if (result < 0)
			goto out;
	}

	/* Step 5: Ask the user to fill in the auth form; repeat as necessary */
	while (1) {
		buf_truncate(request_body);
		result = handle_auth_form(vpninfo, form, request_body,
					  &method, &request_body_type);
		if (result < 0 || result == OC_FORM_RESULT_CANCELLED)
			goto out;
		if (result == OC_FORM_RESULT_LOGGEDIN)
			break;
		if (result == OC_FORM_RESULT_NEWGROUP) {
			free(form_buf);
			form_buf = NULL;
			free_auth_form(form);
			form = NULL;
			goto newgroup;
		}

		result = do_https_request(vpninfo, method, request_body_type, request_body, &form_buf, NULL, 1);
		if (result < 0)
			goto out;

		result = parse_xml_response(vpninfo, form_buf, &form, NULL);
		if (result < 0)
			goto out;
		if (form->action) {
			vpninfo->redirect_url = strdup(form->action);
			handle_redirect(vpninfo);
		}
	}

	/* A return value of 2 means the XML form indicated
	   success. We _should_ have a cookie... */

	struct oc_text_buf *cookie_buf = buf_alloc();
#ifdef HAVE_HPKE_SUPPORT
	if (!vpninfo->no_external_auth && vpninfo->strap_key) {
		buf_append(cookie_buf, "openconnect_strapkey=");
		append_strap_privkey(vpninfo, cookie_buf);
		buf_append(cookie_buf, "; webvpn=");
	}
#endif
	for (opt = vpninfo->cookies; opt; opt = opt->next) {
		if (!strcmp(opt->option, "webvpn")) {
			buf_append(cookie_buf, "%s", opt->value);
		} else if (vpninfo->write_new_config && !strcmp(opt->option, "webvpnc")) {
			char *tok = opt->value;
			char *bu = NULL, *fu = NULL, *sha = NULL;

			do {
				if (tok != opt->value)
					*(tok++) = 0;

				if (!strncmp(tok, "bu:", 3))
					bu = tok + 3;
				else if (!strncmp(tok, "fu:", 3))
					fu = tok + 3;
				else if (!strncmp(tok, "fh:", 3))
					sha = tok + 3;
			} while ((tok = strchr(tok, '&')));

			if (bu && fu && sha) {
				if (asprintf(&vpninfo->profile_url, "%s%s", bu, fu) == -1) {
					buf_free(cookie_buf);
					result = -ENOMEM;
					goto out;
				}
				vpninfo->profile_sha1 = strdup(sha);
			}
		}
	}
	if (buf_error(cookie_buf)) {
		result = buf_free(cookie_buf);
		goto out;
	}

	free(vpninfo->cookie);
	vpninfo->cookie = cookie_buf->data;
	cookie_buf->data = NULL;
	buf_free(cookie_buf);

	result = 0;

	fetch_config(vpninfo);
out:
	buf_free(request_body);

	free (orig_host);
	free (orig_path);

	free(form_path);
	free(form_buf);
	free_auth_form(form);

	if (vpninfo->csd_scriptname) {
		unlink(vpninfo->csd_scriptname);
		free(vpninfo->csd_scriptname);
		vpninfo->csd_scriptname = NULL;
	}

	return result;
}

/**
 * Multiple certificate authentication
 *
 * Two certificates are employed: a "machine" certificate and a
 * "user" certificate. The machine certificate is used to establish
 * the TLS session. The user certificate is used to sign a challenge.
 *
 * An example XML exchange follows. For brevity, tags and attributes whose
 * values are irrelevant (e.g. <opaque>) or well-understood from other auth
 * types are omitted:
 *
 * CLIENT's initial request should include multiple-cert in capabilities:
 *
 *   <config-auth client="vpn" type="init">
 *     <capabilities>
 *       <auth-method>multiple-cert</auth-method>
 *     </capabilities>
 *   </config-auth>
 *
 * SERVER's response should include <multiple-client-cert-request> with list
 * of hash algorithms, and empty <cert-authenticated> tag:
 *
 *   <config-auth client="vpn" type="auth-request">
 *     <multiple-client-cert-request>
 *       <hash-algorithm>sha256</hash-algorithm>
 *       <hash-algorithm>sha384</hash-algorithm>
 *       <hash-algorithm>sha512</hash-algorithm>
 *     </multiple-client-cert-request>
 *
 *     <!-- Ensures that the client has signed this specific request in subsequent reply -->
 *     <random>FA4003BD87436B227...C138A08FF724F0100015B863F750914839EE79C86DFE8F0B9A0199E2</random>
 *
 *     <!-- Appears to indicate that "machine" cert was accepted -->
 *     <cert-authenticated/>
 *   </config-auth>
 *
 * CLIENT's second request should include the "user" certificate (and any
 * required intermediates) in PKCS7 format, along with a signature of the
 * complete XML body of the server's prior response:
 *
 *   <config-auth client="vpn" type="auth-reply">
 *     <auth>
 *       <client-cert-chain cert-store="1M">
 *         <client-cert-sent-via-protocol/>
 *       </client-cert-chain>
 *       <client-cert-chain cert-store="1U">
 *         <client-cert cert-format="pkcs7">
 *           <!-- PKCS7 "user" certificate and intermediate (base64-encoded) -->
 *         </client-cert>
 *         <client-cert-auth-signature hash-algorithm-chosen="sha512">
 *           <!-- signature on server's prior response with private key of "user" certificate -->
 *         </client-cert-auth-signature>
 *       </client-cert-chain>
 *     </auth>
 *   </config-auth>
 */
static int to_base64(struct oc_text_buf **result,
		     const void *data, size_t data_len)
{
	const uint8_t *dp = data;
	struct oc_text_buf *buf;
	int ret;

	*result = NULL;

	/**
	 * Line feed every 64 characters. No feed needed on last line
	 * */
	buf = buf_alloc();
	if (!buf)
		return -ENOMEM;

	buf_append_base64(buf, dp, data_len, 64);

	ret = buf_error(buf);
	if (ret < 0)
		goto out;

	*result = buf;
	buf = NULL;

out:
	buf_free(buf);
	return ret;
}

/**
 * parse request
 */
void parse_multicert_request(struct openconnect_info *vpninfo,
		xmlNodePtr node, struct cert_request *cert_rq)
{
	xmlNodePtr child;
	char *content;
	openconnect_hash_type hash;
	unsigned int oldhashes = 0;

	/* node is a multiple-client-cert-request element */
	for (child = node->children; child; child = child->next) {
		if (child->type != XML_ELEMENT_NODE)
			continue;

		if (xmlStrcmp(child->name, XCAST("hash-algorithm")) != 0)
			continue;

		content = (char *)xmlNodeGetContent(child);
		if (content == NULL)
			continue;

		hash = multicert_hash_get_id(content);
		/* hash was not found */
		if (hash == OPENCONNECT_HASH_UNKNOWN) {
			vpn_progress(vpninfo, PRG_INFO,
			    _("Unsupported hash algorithm '%s' requested.\n"),
			    (char *) content);
			goto next;
		}

		oldhashes = cert_rq->hashes;
		cert_rq->hashes |= MULTICERT_HASH_FLAG(hash);
		if (oldhashes == cert_rq->hashes)
			vpn_progress(vpninfo, PRG_INFO,
			   _("Duplicate hash algorithm '%s' requested.\n"),
			   (char *) content);

	next:
		xmlFree(content);
	}
}

#define BUF_DATA(bp) ((bp)->data)
#define BUF_SIZE(bp) ((bp)->pos)

static int post_multicert_response(struct openconnect_info *vpninfo, const xmlChar *cert,
				   openconnect_hash_type hash, const xmlChar *signature,
				   struct oc_text_buf *body)
{
	static const xmlChar *strnull = XCAST("(null)");
	const xmlChar *hashname;
	xmlDocPtr doc;
	xmlNodePtr root, auth, node, chain;

	doc = xmlpost_new_query(vpninfo, "auth-reply", &root);
	if (!doc)
		goto bad;

	node = xmlNewChild(root, NULL, XCAST("session-token"), NULL);
	if (!node)
		goto bad;

	node = xmlNewChild(root, NULL, XCAST("session-id"), NULL);
	if (!node)
		goto bad;

	if (vpninfo->opaque_srvdata != NULL) {
		node = xmlCopyNode(vpninfo->opaque_srvdata, 1);
		if (!node || !xmlAddChild(root, node))
			goto bad;
	}
	// key1 ownership is proved by TLS session
	auth = xmlNewChild(root, NULL, XCAST("auth"), NULL);
	if (!auth)
		goto bad;

	chain = xmlNewChild(auth, NULL, XCAST("client-cert-chain"), NULL);
	if (!chain || !xmlNewProp(chain, XCAST("cert-store"), XCAST("1M")))
		goto bad;

	if (!xmlNewChild(chain, NULL, XCAST("client-cert-sent-via-protocol"),
		   NULL))
		goto bad;
	// key2 ownership is proved by signing the challenge
	chain = xmlNewChild(auth, NULL, XCAST("client-cert-chain"), NULL);
	if (!chain || !xmlNewProp(chain, XCAST("cert-store"), XCAST("1U")))
		goto bad;

	node = xmlNewTextChild(chain, NULL, XCAST("client-cert"), cert ? cert : strnull);
	if (!node || !xmlNewProp(node, XCAST("cert-format"), XCAST("pkcs7")))
		goto bad;

	hashname = XCAST(multicert_hash_get_name(hash));
	node = xmlNewTextChild(chain, NULL,
			       XCAST("client-cert-auth-signature"),
			       signature ? signature : strnull);
	if (!node || !xmlNewProp(node, XCAST("hash-algorithm-chosen"), hashname ? hashname : strnull))
		goto bad;

	return xmlpost_complete(doc, body);

 bad:
	xmlpost_complete(doc, NULL);
	return -ENOMEM;

}

int prepare_multicert_response(struct openconnect_info *vpninfo,
		       struct cert_request cert_rq, const char *challenge,
		       struct oc_text_buf *body)
{
	struct cert_info *certinfo = &vpninfo->certinfo[1];
	struct oc_text_buf *certdata = NULL, *certtext = NULL;
	struct oc_text_buf *signdata = NULL, *signtext = NULL;
	openconnect_hash_type hash;
	int ret;


	if (!cert_rq.hashes) {
		vpn_progress(vpninfo, PRG_ERR,
		 _("Multiple-certificate authentication signature hash algorithm negotiation failed.\n"));
		ret = -EIO;
		goto done;
	}

	ret = export_certificate_pkcs7(vpninfo, certinfo, CERT_FORMAT_ASN1, &certdata);

	if (ret >= 0)
		ret = to_base64(&certtext,
				BUF_DATA(certdata),
				BUF_SIZE(certdata));

	if (ret < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error exporting multiple-certificate signer's certificate chain.\n"));
		goto done;
	}

	ret = multicert_sign_data(vpninfo, certinfo, cert_rq.hashes,
				  challenge, strlen(challenge),
				  &signdata);
	if (ret < 0)
		goto done;

	hash = ret;

	if ((ret = to_base64(&signtext, BUF_DATA(signdata), BUF_SIZE(signdata))) < 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error encoding the challenge response.\n"));

		goto done;
	}

	ret = post_multicert_response(vpninfo, XCAST(BUF_DATA(certtext)),
				      hash, XCAST(BUF_DATA(signtext)),
				      body);

done:
	buf_free(certdata); buf_free(certtext);
	buf_free(signdata); buf_free(signtext);
	return ret;
}
