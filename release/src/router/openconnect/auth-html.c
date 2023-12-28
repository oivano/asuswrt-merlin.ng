/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2015-2021 David Woodhouse, Daniel Lenski
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

#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>

#include <errno.h>

xmlNodePtr htmlnode_next(xmlNodePtr top, xmlNodePtr node)
{
	while (!node->next) {
		node = node->parent;
		if (!node || node == top)
			return NULL;
	}
	return node->next;
}

xmlNodePtr htmlnode_dive(xmlNodePtr top, xmlNodePtr node)
{
	if (node->children)
		return node->children;
	return htmlnode_next(top, node);
}


xmlNodePtr find_form_node(xmlDocPtr doc)
{
	xmlNodePtr root, node;

	for (root = node = xmlDocGetRootElement(doc); node; node = htmlnode_dive(root, node)) {
		if (node->name && !strcasecmp((char *)node->name, "form"))
			return node;
	}
	return NULL;
}

int parse_input_node(struct openconnect_info *vpninfo, struct oc_auth_form *form,
		     xmlNodePtr node, const char *submit_button,
		     int (*can_gen_tokencode)(struct openconnect_info *vpninfo, struct oc_auth_form *form, struct oc_form_opt *opt))
{
	char *type = (char *)xmlGetProp(node, (unsigned char *)"type"), *style = (char *)xmlGetProp(node, (unsigned char *)"style");
	struct oc_form_opt **p = &form->opts;
	struct oc_form_opt *opt;
	int ret = 0;
	int nodisplay = style && !strcmp(style, "display: none;"); /* XX: Fortinet-specific */

	if (!type)
		return -EINVAL;

	opt = calloc(1, sizeof(*opt));
	if (!opt) {
	nomem:
		ret = -ENOMEM;
		goto out;
	}

	if (nodisplay || !strcasecmp(type, "hidden")) {
		opt->type = OC_FORM_OPT_HIDDEN;
		xmlnode_get_prop(node, "name", &opt->name);
		if (asprintf(&opt->label, "%s:", opt->name) == -1)
			goto nomem;
		xmlnode_get_prop(node, "value", &opt->_value);
		/* XXX: Handle tz_offset / tz */
	} else if (!strcasecmp(type, "password")) {
		opt->type = OC_FORM_OPT_PASSWORD;
		xmlnode_get_prop(node, "name", &opt->name);
		if (asprintf(&opt->label, "%s:", opt->name) == -1)
			goto nomem;
		if (can_gen_tokencode && !can_gen_tokencode(vpninfo, form, opt))
			opt->type = OC_FORM_OPT_TOKEN;
	} else if (!strcasecmp(type, "text") || !strcasecmp(type, "username") || !strcasecmp(type, "email")) {
		opt->type = OC_FORM_OPT_TEXT;
		xmlnode_get_prop(node, "name", &opt->name);
		if (asprintf(&opt->label, "%s:", opt->name) == -1)
			goto nomem;
		if (vpninfo->proto->proto == PROTO_NC &&
		    !strcmp(form->auth_id, "loginForm") &&
		    !strcmp(opt->name, "VerificationCode") &&
		    can_gen_tokencode && !can_gen_tokencode(vpninfo, form, opt))
			opt->type = OC_FORM_OPT_TOKEN;
	} else if (!strcasecmp(type, "submit")) {
		/* XX: can be ignored except for Juniper */
		if (vpninfo->proto->proto != PROTO_NC)
			goto free_out;

		xmlnode_get_prop(node, "name", &opt->name);
		if (opt->name && submit_button && (!strcmp(opt->name, submit_button) ||
						   !strcmp(opt->name, "sn-postauth-proceed") ||
						   !strcmp(opt->name, "sn-preauth-proceed") ||
						   !strcmp(opt->name, "secidactionEnter"))) {
			/* Use this as the 'Submit' action for the form, by
			   implicitly adding it as a hidden option. */
			xmlnode_get_prop(node, "value", &opt->_value);
			opt->type = OC_FORM_OPT_HIDDEN;
		} else {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Ignoring unknown form submit item '%s'\n"),
				     opt->name);
			ret = -EINVAL;
			goto out;
		}
	} else if (!strcasecmp(type, "checkbox")) {
		opt->type = OC_FORM_OPT_HIDDEN;
		xmlnode_get_prop(node, "name", &opt->name);
		xmlnode_get_prop(node, "value", &opt->_value);
	} else {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Ignoring unknown form input type '%s'\n"),
			     type);
		ret = -EINVAL;
		goto out;
	}

	/* Append to the existing list */
	while (*p) {
		if (!strcmp((*p)->name, opt->name)) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Discarding duplicate option '%s'\n"),
				     opt->name);
			free_opt(opt);
			goto out;
		}
		p = &(*p)->next;
	}
	*p = opt;
 out:
	if (ret)
	free_out:
		free_opt(opt);
	free(type);
	free(style);
	return ret;
}

int parse_select_node(struct openconnect_info *vpninfo, struct oc_auth_form *form,
		      xmlNodePtr node)
{
	xmlNodePtr child;
	struct oc_form_opt_select *opt;
	struct oc_choice *choice;

	opt = calloc(1, sizeof(*opt));
	if (!opt)
		return -ENOMEM;

	xmlnode_get_prop(node, "name", &opt->form.name);
	opt->form.label = strdup(opt->form.name);
	opt->form.type = OC_FORM_OPT_SELECT;
	if ((vpninfo->proto->proto == PROTO_NC && !strcmp(opt->form.name, "realm")) ||
	    (vpninfo->proto->proto == PROTO_F5 && !strcmp(opt->form.name, "domain")))
		form->authgroup_opt = opt;

	for (child = node->children; child; child = child->next) {
		struct oc_choice **new_choices;
		if (!child->name || strcasecmp((const char *)child->name, "option"))
			continue;

		choice = calloc(1, sizeof(*choice));
		if (!choice) {
			free_opt((void *)opt);
			return -ENOMEM;
		}

		xmlnode_get_prop(child, "value", &choice->name);
		choice->label = (char *)xmlNodeGetContent(child);
		new_choices = realloc(opt->choices, sizeof(opt->choices[0]) * (opt->nr_choices+1));
		if (!new_choices) {
			free_opt((void *)opt);
			free(choice);
			return -ENOMEM;
		}
		opt->choices = new_choices;
		opt->choices[opt->nr_choices++] = choice;
	}

	/* Prepend to the existing list */
	opt->form.next = form->opts;
	form->opts = &opt->form;
	return 0;
}

struct oc_auth_form *parse_form_node(struct openconnect_info *vpninfo,
				      xmlNodePtr node, const char *submit_button,
				      int (*can_gen_tokencode)(struct openconnect_info *vpninfo, struct oc_auth_form *form, struct oc_form_opt *opt))
{
	struct oc_auth_form *form = calloc(1, sizeof(*form));
	xmlNodePtr child;

	if (!form)
		return NULL;

	xmlnode_get_prop(node, "method", &form->method);
	xmlnode_get_prop(node, "action", &form->action);
	if (!form->method || strcasecmp(form->method, "POST")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Cannot handle form method='%s', action='%s'\n"),
			     form->method, form->action);
		free(form);
		return NULL;
	}

	if (vpninfo->proto->proto == PROTO_NC) {
		/* XX: some forms have 'id', but no 'name' */
		if (!xmlnode_get_prop(node, "name", &form->auth_id) ||
		    !xmlnode_get_prop(node, "id", &form->auth_id))
			form->banner = strdup(form->auth_id);
	} else if (vpninfo->proto->proto == PROTO_F5) {
		if (!xmlnode_get_prop(node, "id", &form->auth_id))
			form->banner = strdup(form->auth_id);
	}

	/* XX: fallback auth_id (since other functions expect it to exist) */
	if (!form->auth_id)
		form->auth_id = strdup("unknown");

	for (child = htmlnode_dive(node, node); child && child != node; child = htmlnode_dive(node, child)) {
		if (!child->name)
			continue;

		if (!strcasecmp((char *)child->name, "input"))
			parse_input_node(vpninfo, form, child, submit_button, can_gen_tokencode);
		else if (!strcasecmp((char *)child->name, "select")) {
			parse_select_node(vpninfo, form, child);
			/* Skip its children */
			while (child->children)
				child = child->last;
		} else if (vpninfo->proto->proto == PROTO_F5
			   && !strcasecmp((char *)child->name, "td")) {

			char *id = (char *)xmlGetProp(child, (unsigned char *)"id");
			if (id && !strcmp(id, "credentials_table_header")) {
				char *msg = (char *)xmlNodeGetContent(child);
				if (msg) {
					free(form->banner);
					form->banner = msg;
				}
			} else if (id && !strcmp(id, "credentials_table_postheader")) {
				char *msg = (char *)xmlNodeGetContent(child);
				if (msg) {
					free(form->message);
					form->message = msg;
				}
			}
			free(id);

		} else if (vpninfo->proto->proto == PROTO_NC &&
			   !strcasecmp((char *)child->name, "textarea")) {

			/* display the post sign-in message, if any */
			char *fieldname = (char *)xmlGetProp(child, (unsigned char *)"name");
			if (fieldname && (!strcasecmp(fieldname, "sn-postauth-text") || /* XX: Juniper-specific */
					  !strcasecmp(fieldname, "sn-preauth-text"))) {
				char *postauth_msg = (char *)xmlNodeGetContent(child);
				if (postauth_msg) {
					free(form->banner);
					form->banner = postauth_msg;
				}
			} else {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unknown textarea field: '%s'\n"), fieldname);
			}
			free(fieldname);

		} else if (vpninfo->proto->proto == PROTO_FORTINET &&
			   !strcasecmp((char *)child->name, "b")) {

			char *msg = (char *)xmlNodeGetContent(child);
			if (msg) {
				free(form->message);
				form->message = msg;
			}
		}
	}
	return form;
}
