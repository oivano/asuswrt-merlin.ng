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

/*
 * Grateful thanks to Tiebing Zhang, who did much of the hard work
 * of analysing and decoding the protocol.
 */

#include <config.h>

#include "openconnect-internal.h"

#include <libxml/HTMLparser.h>
#include <libxml/HTMLtree.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/wait.h>
#endif

#include <time.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

/* XX: This is actually a lot of duplication with the CSTP version. */
void oncp_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf)
{
	http_common_headers(vpninfo, buf);

//	buf_append(buf, "Content-Length: 256\r\n");
	buf_append(buf, "NCP-Version: 3\r\n");
//	buf_append(buf, "Accept-Encoding: gzip\r\n");
}

static int oncp_can_gen_tokencode(struct openconnect_info *vpninfo,
				  struct oc_auth_form *form,
				  struct oc_form_opt *opt)
{
	if (vpninfo->token_mode == OC_TOKEN_MODE_NONE ||
	    vpninfo->token_bypassed)
		return -EINVAL;

	if (opt->type == OC_FORM_OPT_PASSWORD &&
	    (!strcmp(form->auth_id, "frmLogin") ||
	     !strcmp(form->auth_id, "loginForm"))) {
		/* XX: The first occurrence of a password input field in frmLogin is likely to be a password,
		 * not token, input. However, if we have already added a password input field to this form,
		 * then a second one is likely to hold a token.
		 */
		struct oc_form_opt *p;
		for (p = form->opts; p; p = p->next) {
			if (p->type == OC_FORM_OPT_PASSWORD)
				goto okay;
		}
		return -EINVAL;
	}

	if (strcmp(form->auth_id, "frmDefender") &&
	    strcmp(form->auth_id, "frmNextToken") &&
	    strcmp(form->auth_id, "frmTotpToken") &&
	    strcmp(form->auth_id, "loginForm"))
		return -EINVAL;

 okay:
	return can_gen_tokencode(vpninfo, form, opt);
}


int oncp_send_tncc_command(struct openconnect_info *vpninfo, int start)
{
	const char *dspreauth = vpninfo->csd_token, *dsurl = vpninfo->csd_starturl ? : "null";
	struct oc_text_buf *buf;
	buf = buf_alloc();

	if (start) {
		buf_append(buf, "start\n");
		buf_append(buf, "IC=%s\n", vpninfo->hostname);
		buf_append(buf, "Cookie=%s\n", dspreauth);
		buf_append(buf, "DSSIGNIN=%s\n", dsurl);
	} else {
		buf_append(buf, "setcookie\n");
		buf_append(buf, "Cookie=%s\n", dspreauth);
	}

	if (buf_error(buf)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to allocate memory for communication with TNCC\n"));
		return buf_free(buf);
	}
	if (cancellable_send(vpninfo, vpninfo->tncc_fd, buf->data, buf->pos) != buf->pos) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to send command to TNCC\n"));
		buf_free(buf);
		return -EIO;
	}

       /* Mainloop timers need to know the last Trojan was invoked */
	vpninfo->last_trojan = time(NULL);
	return buf_free(buf);
}

static int check_cookie_success(struct openconnect_info *vpninfo)
{
	const char *dslast = NULL, *dsfirst = NULL, *dsurl = NULL, *dsid = NULL;
	struct oc_vpn_option *cookie;
	struct oc_text_buf *buf;

	for (cookie = vpninfo->cookies; cookie; cookie = cookie->next) {
		if (!strcmp(cookie->option, "DSFirstAccess"))
			dsfirst = cookie->value;
		else if (!strcmp(cookie->option, "DSLastAccess"))
			dslast = cookie->value;
		else if (!strcmp(cookie->option, "DSID"))
			dsid = cookie->value;
		else if (!strcmp(cookie->option, "DSSignInUrl"))
			dsurl = cookie->value;
		else if (!strcmp(cookie->option, "DSSIGNIN")) {
			free(vpninfo->csd_starturl);
			vpninfo->csd_starturl = strdup(cookie->value);
		} else if (!strcmp(cookie->option, "DSPREAUTH")) {
			free(vpninfo->csd_token);
			vpninfo->csd_token = strdup(cookie->value);
		}
	}
	if (!dsid)
		return -ENOENT;

	if (vpninfo->tncc_fd != -1) {
		/* update TNCC once we get a DSID cookie */
		oncp_send_tncc_command(vpninfo, 0);
	}

	/* XXX: Do these need escaping? Could they theoreetically have semicolons in? */
	buf = buf_alloc();
	buf_append(buf, "DSID=%s", dsid);
	if (dsfirst)
		buf_append(buf, "; DSFirst=%s", dsfirst);
	if (dslast)
		buf_append(buf, "; DSLast=%s", dslast);
	if (dsurl)
		buf_append(buf, "; DSSignInUrl=%s", dsurl);
	if (buf_error(buf))
		return buf_free(buf);
	free(vpninfo->cookie);
	vpninfo->cookie = buf->data;
	buf->data = NULL;
	buf_free(buf);
	return 0;
}
#ifdef _WIN32
static int tncc_preauth(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_ERR,
		     _("TNCC support not implemented yet on Windows\n"));
	return -EOPNOTSUPP;
}
#else
static int tncc_preauth(struct openconnect_info *vpninfo)
{
	int sockfd[2];
	pid_t pid;
	const char *dspreauth = vpninfo->csd_token;
	char recvbuf[1024];
	int len, count, ret;

	if (!dspreauth) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("No DSPREAUTH cookie; not attempting TNCC\n"));
		return -EINVAL;
	}

	vpn_progress(vpninfo, PRG_INFO,
		     _("Trying to run TNCC/Host Checker Trojan script '%s'.\n"),
		     vpninfo->csd_wrapper);

#ifdef SOCK_CLOEXEC
	if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockfd))
#endif
	{
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd))
			return -errno;

		set_fd_cloexec(sockfd[0]);
		set_fd_cloexec(sockfd[1]);
	}
	pid = fork();
	if (pid == -1) {
		close(sockfd[0]);
		close(sockfd[1]);
		return -errno;
	}

	if (!pid) {
		int i;
		/* Fork again to detach grandchild */
		if (fork())
			exit(1);

		close(sockfd[1]);
		/* The duplicated fd does not have O_CLOEXEC */
		dup2(sockfd[0], 0);
		/* We really don't want anything going to our stdout.
		   Redirect the child's stdout, to our stderr. */
		dup2(2, 1);
		/* And close everything else.*/
		for (i = 3; i < 1024 ; i++)
			close(i);

		if (setenv("TNCC_SHA256", openconnect_get_peer_cert_hash(vpninfo)+11, 1))  /* remove initial 'pin-sha256:' */
			goto out;
		if (setenv("TNCC_HOSTNAME", vpninfo->localname, 1))
			goto out;
		if (!vpninfo->trojan_interval) {
			char is[32];
			snprintf(is, 32, "%d", vpninfo->trojan_interval);
			if (setenv("TNCC_INTERVAL", is, 1))
				goto out;
		}

		execl(vpninfo->csd_wrapper, vpninfo->csd_wrapper, vpninfo->hostname, NULL);
	out:
		fprintf(stderr, _("Failed to exec TNCC script %s: %s\n"),
			vpninfo->csd_wrapper, strerror(errno));
		exit(1);
	}
	waitpid(pid, NULL, 0);
	close(sockfd[0]);
	vpninfo->tncc_fd = sockfd[1];

	ret = oncp_send_tncc_command(vpninfo, 1);
	if (ret < 0) {
	err:
		close(vpninfo->tncc_fd);
		vpninfo->tncc_fd = -1;
		return ret;
	}

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Sent start; waiting for response from TNCC\n"));

	/* First line: HTTP-like response code. */
	len = cancellable_gets(vpninfo, sockfd[1], recvbuf, sizeof(recvbuf));
	if (len < 0) {
	respfail:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to read response from TNCC\n"));
		ret = -EIO;
		goto err;
	}

	if (strcmp(recvbuf, "200")) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Received unsuccessful %s response from TNCC\n"),
			     recvbuf);
		ret = -EINVAL;
		goto err;
	}

	vpn_progress(vpninfo, PRG_TRACE, _("TNCC response 200 OK\n"));

	/* We're not sure what the second line is. We ignore it. */
	len = cancellable_gets(vpninfo, sockfd[1], recvbuf, sizeof(recvbuf));
	if (len < 0)
		goto respfail;

	vpn_progress(vpninfo, PRG_TRACE, _("Second line of TNCC response: '%s'\n"),
		     recvbuf);

	/* Third line is the DSPREAUTH cookie */
	len = cancellable_gets(vpninfo, sockfd[1], recvbuf, sizeof(recvbuf));
	if (len < 0)
		goto respfail;

	vpn_progress(vpninfo, PRG_DEBUG,
		     _("Got new DSPREAUTH cookie from TNCC: %s\n"),
		     recvbuf);
	http_add_cookie(vpninfo, "DSPREAUTH", recvbuf, 1);

	/* Fourth line, if present, is the interval to rerun TNCC */
	len = cancellable_gets(vpninfo, sockfd[1], recvbuf, sizeof(recvbuf));
	if (len < 0)
		goto respfail;
	if (len > 0) {
		int interval = atoi(recvbuf);
		if (interval != 0) {
			vpninfo->trojan_interval = interval;
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Got reauth interval from TNCC: %d seconds\n"),
				     interval);
		}
	}

	count = 0;
	do {
		len = cancellable_gets(vpninfo, sockfd[1], recvbuf,
				       sizeof(recvbuf));
		if (len < 0)
			goto respfail;
		if (len > 0)
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Unexpected non-empty line from TNCC after DSPREAUTH cookie: '%s'\n"),
				     recvbuf);
	} while (len && (count++ < 10));

	if (len > 0) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Too many non-empty lines from TNCC after DSPREAUTH cookie\n"));
		goto respfail;
	}

	return 0;
}
#endif

static struct oc_auth_form *parse_roles_table_node(xmlNodePtr node)
{
	struct oc_auth_form *form;
	xmlNodePtr table_itr;
	xmlNodePtr row_itr;
	xmlNodePtr data_itr;
	struct oc_form_opt_select *opt;
	struct oc_choice *choice;

	form = calloc(1, sizeof(*form));
	if (!form)
		return NULL;

	form->auth_id = strdup("frmSelectRoles");
	if (!form->auth_id) {
		free(form);
		return NULL;
	};

	opt = calloc(1, sizeof(*opt));
	if (!opt) {
		free_auth_form(form);
		return NULL;
	}

	form->opts = &opt->form;
	opt->form.label = strdup("frmSelectRoles");
	opt->form.name = strdup("frmSelectRoles");
	opt->form.type = OC_FORM_OPT_SELECT;
	form->authgroup_opt = opt; /* XX: --authgroup also sets realm field (see parse_select_node in auth-html.c) */

	for (table_itr = node->children; table_itr; table_itr = table_itr->next) {
		if (!table_itr->name || strcasecmp((const char *)table_itr->name, "tr"))
			continue;
		for (row_itr = table_itr->children; row_itr; row_itr = row_itr->next) {
			if (!row_itr->name || strcasecmp((const char *)row_itr->name, "td"))
				continue;
			for (data_itr = row_itr->children; data_itr; data_itr = data_itr->next) {
				struct oc_choice **new_choices;
				char *role_link = NULL;
				char *role_name = NULL;

				if (!data_itr->name || strcasecmp((const char *)data_itr->name, "a"))
					continue;

				// Discovered <a> tag with role selection.
				role_link = (char *)xmlGetProp(data_itr, (unsigned char *)"href");
				if (!role_link)
					continue;

				role_name = (char *)xmlNodeGetContent(data_itr);
				if (!role_name) {
					// some weird case?
					free(role_link);
					continue;
				}

				choice = calloc(1, sizeof(*choice));
				if (!choice) {
					free(role_name);
					free(role_link);
					free_auth_form(form);
					return NULL;
				}

				choice->label = role_name;
				choice->name = role_link;
				new_choices = realloc(opt->choices, sizeof(opt->choices[0]) * (opt->nr_choices+1));
				if (!new_choices) {
					free(choice);
					free(role_name);
					free(role_link);
					free_auth_form(form);
					return NULL;
				}
				opt->choices = new_choices;
				opt->choices[opt->nr_choices++] = choice;
			}
		}
	}

	return form;
}

static struct oc_auth_form *parse_roles_form_node(xmlNodePtr node)
{
	struct oc_auth_form *form = NULL;
	xmlNodePtr child;

	// Set form->action here as a redirect url with keys and ids.
	for (child = htmlnode_dive(node, node); child && child != node;
	     child = htmlnode_dive(node, child)) {
		if (child->name && !strcasecmp((char *)child->name, "table")) {
			char *table_id = (char *)xmlGetProp(child, (unsigned char *)"id");

			if (table_id) {
				if (!strcmp(table_id, "TABLE_SelectRole_1"))
					form = parse_roles_table_node(child);

				free(table_id);

				if (form)
					break;
			}
		}
	}

	return form;
}

int oncp_obtain_cookie(struct openconnect_info *vpninfo)
{
	int ret;
	struct oc_text_buf *resp_buf = NULL;
	xmlDocPtr doc = NULL;
	xmlNodePtr node;
	struct oc_auth_form *form = NULL;
	char *form_name = NULL, *form_id = NULL;
	int try_tncc = !!vpninfo->csd_wrapper;

	resp_buf = buf_alloc();
	if (buf_error(resp_buf)) {
		ret = buf_error(resp_buf);
		goto out;
	}

	while (1) {
		char *form_buf = NULL;
		int role_select = 0;
	        char *url;

		if (resp_buf && resp_buf->pos)
			ret = do_https_request(vpninfo, "POST", "application/x-www-form-urlencoded", resp_buf,
					       &form_buf, NULL, HTTP_REDIRECT_TO_GET);
		else
			ret = do_https_request(vpninfo, "GET", NULL, NULL, &form_buf, NULL, HTTP_REDIRECT_TO_GET);

		/* After login, the server will redirect the "browser" to a landing page.
		 * https://kb.pulsesecure.net/articles/Pulse_Secure_Article/SA44784
		 * turned some of those landing pages into a 403 but we don't *care*
		 * about that as long as we have the cookie we wanted. So check for
		 * cookie success *before* checking 'ret'. */
		if (!check_cookie_success(vpninfo)) {
			free(form_buf);
			ret = 0;
			break;
		}

		if (ret < 0)
			break;

		url = internal_get_url(vpninfo);
		if (!url) {
			free(form_buf);
			ret = -ENOMEM;
			break;
		}

		doc = htmlReadMemory(form_buf, ret, url, NULL,
				     HTML_PARSE_RECOVER|HTML_PARSE_NOERROR|HTML_PARSE_NOWARNING|HTML_PARSE_NONET);
		free(url);
		free(form_buf);
		if (!doc) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to parse HTML document\n"));
			ret = -EINVAL;
			break;
		}

		buf_truncate(resp_buf);

		node = find_form_node(doc);
		if (!node) {
			if (try_tncc) {
				try_tncc = 0;
				ret = tncc_preauth(vpninfo);
				if (ret)
					return ret;
				goto tncc_done;
			}
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to find or parse web form in login page\n"));
			ret = -EINVAL;
			break;
		}
		free(form_name);
		free(form_id);
		form_name = (char *)xmlGetProp(node, (unsigned char *)"name");
		form_id = (char *)xmlGetProp(node, (unsigned char *)"id");
		if (!form_name && !form_id) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Encountered form with no 'name' or 'id'\n"));
			goto dump_form;
		} else if (form_name && !strcmp(form_name, "frmLogin")) {
			form = parse_form_node(vpninfo, node, "btnSubmit", oncp_can_gen_tokencode);
		} else if (form_id && !strcmp(form_id, "loginForm")) {
			form = parse_form_node(vpninfo, node, "submitButton", oncp_can_gen_tokencode);
		} else if ((form_name && !strcmp(form_name, "frmDefender")) ||
			   (form_name && !strcmp(form_name, "frmNextToken"))) {
			form = parse_form_node(vpninfo, node, "btnAction", oncp_can_gen_tokencode);
		} else if (form_name && !strcmp(form_name, "frmConfirmation")) {
			form = parse_form_node(vpninfo, node, "btnContinue", oncp_can_gen_tokencode);
			if (!form) {
				ret = -EINVAL;
				break;
			}
			/* XXX: Actually ask the user? */
			goto form_done;
		} else if (form_name && !strcmp(form_name, "frmSelectRoles")) {
			form = parse_roles_form_node(node);
			role_select = 1;
		} else if (form_name && !strcmp(form_name, "frmTotpToken")) {
			form = parse_form_node(vpninfo, node, "totpactionEnter", oncp_can_gen_tokencode);
		} else if ((form_name && !strcmp(form_name, "hiddenform")) ||
			   (form_id && !strcmp(form_id, "formSAMLSSO"))) {
			form = parse_form_node(vpninfo, node, "submit", oncp_can_gen_tokencode);
		} else {
			char *form_action = (char *)xmlGetProp(node, (unsigned char *)"action");
			if (form_action && strstr(form_action, "remediate.cgi")) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Form action (%s) likely indicates that TNCC/Host Checker failed.\n"),
					     form_action);
			}
			free(form_action);

			vpn_progress(vpninfo, PRG_ERR,
				     _("Unknown form (name '%s', id '%s')\n"),
				     form_name, form_id);
		dump_form:
			fprintf(stderr, _("Dumping unknown HTML form:\n"));
			htmlNodeDumpFileFormat(stderr, node->doc, node, NULL, 1);
			ret = -EINVAL;
			break;
		}

		if (!form) {
			ret = -EINVAL;
			break;
		}

		do {
			ret = process_auth_form(vpninfo, form);
		} while (ret == OC_FORM_RESULT_NEWGROUP);
		if (ret)
			goto out;

		ret = do_gen_tokencode(vpninfo, form);
		if (ret) {
			vpn_progress(vpninfo, PRG_ERR, _("Failed to generate OTP tokencode; disabling token\n"));
			vpninfo->token_bypassed = 1;
			goto out;
		}

		/* frmSelectRoles is special; it's actually *links*, not a form. So
		 * we need to process it differently... */
		if (role_select) {
			vpninfo->redirect_url = strdup(form->opts[0]._value);
			goto do_redirect;
		}
	form_done:
		append_form_opts(vpninfo, form, resp_buf);
		ret = buf_error(resp_buf);
		if (ret)
			break;

		if (form->action) {
			vpninfo->redirect_url = form->action;
			form->action = NULL;
		}
	do_redirect:
		free_auth_form(form);
		form = NULL;
		if (vpninfo->redirect_url)
			handle_redirect(vpninfo);

	tncc_done:
		xmlFreeDoc(doc);
		doc = NULL;
	}
 out:
	if (doc)
		xmlFreeDoc(doc);
	free(form_name);
	free(form_id);
	if (form)
		free_auth_form(form);
	buf_free(resp_buf);
	return ret;
}
