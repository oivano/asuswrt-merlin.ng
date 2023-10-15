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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef _WIN32
#include <process.h>
#define getpid _getpid
#else
#include <sys/wait.h>
#endif

#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int script_setenv(struct openconnect_info *vpninfo,
		  const char *opt, const char *val, int trunc, int append)
{
	struct oc_vpn_option *p;
	char *str;

	for (p = vpninfo->script_env; p; p = p->next) {
		if (!strcmp(opt, p->option)) {
			if (append) {
				if (asprintf(&str, "%s %s", p->value, val) == -1)
					return -ENOMEM;
			} else
				str = val ? strdup(val) : NULL;

			free (p->value);
			p->value = str;
			return 0;
		}
	}
	p = malloc(sizeof(*p));
	if (!p)
		return -ENOMEM;
	p->next = vpninfo->script_env;
	p->option = strdup(opt);
	p->value = val ? (trunc ? strndup(val, trunc) : strdup(val)) : NULL;
	vpninfo->script_env = p;
	return 0;
}

int script_setenv_int(struct openconnect_info *vpninfo, const char *opt, int value)
{
	char buf[16];
	sprintf(buf, "%d", value);
	return script_setenv(vpninfo, opt, buf, 0, 0);
}

static inline int cls(uint32_t word)
{
#if defined(HAVE_BUILTIN_CLZ) && UINT_MAX == UINT32_MAX
	word = ~word;
	if (!word)
		return 32;
	return __builtin_clz(word);
#else
	int masklen = 0;
	while (word & 0x80000000) {
		word <<= 1;
		masklen++;
	}
	return masklen;
#endif
}

static int netmasklen(struct in_addr addr)
{
	return cls(ntohl(addr.s_addr));
}

static int netmasklen6(struct in6_addr *addr)
{
	int masklen;
	uint32_t *p = (uint32_t *)(addr->s6_addr);

	for (masklen = 0; masklen < 128; p++, masklen += 32) {
		uint32_t v = ntohl(*p);
		if (~v == 0)
			continue;
		return masklen + cls(v);
	}
	return 128;
}

static uint32_t netmaskbits(int masklen)
{
	if (masklen)
		return htonl(0xffffffff << (32-masklen));
	else /* Shifting by 32 is invalid, so special-case it */
		return 0;
}

static int process_split_xxclude(struct openconnect_info *vpninfo,
				 int include, const char *route, int *v4_incs,
				 int *v6_incs)
{
	struct in_addr net_addr, mask_addr;
	const char *in_ex = include ? "IN" : "EX";
	char envname[80], uptoslash[20], abuf[INET_ADDRSTRLEN];
	const char *slash;
	char *endp;
	int masklen;

	slash = strchr(route, '/');
	envname[79] = uptoslash[19] = 0;

	if (strchr(route, ':')) {
		snprintf(envname, 79, "CISCO_IPV6_SPLIT_%sC_%d_ADDR", in_ex,
			 *v6_incs);
		script_setenv(vpninfo, envname, route, slash ? slash - route : 0, 0);

		/* Accept IPv6 netmask in several forms */
		snprintf(envname, 79, "CISCO_IPV6_SPLIT_%sC_%d_MASKLEN", in_ex,
			 *v6_incs);
		if (!slash) {
			/* no mask (same as /128) */
			script_setenv_int(vpninfo, envname, 128);
		} else if ((masklen = strtol(slash+1, &endp, 10))<=128 && (*endp=='\0' || isspace(*endp))) {
			/* mask is /N */
			script_setenv_int(vpninfo, envname, masklen);
		} else {
			/* mask is /dead:beef:: */
			struct in6_addr a;
			if (inet_pton(AF_INET6, slash+1, &a) <= 0)
				goto bad;
			masklen = netmasklen6(&a);
			/* something invalid like /ffff::1 */
			for (int ii = (masklen >> 3); ii < 16; ii++) {
				if (ii == (masklen >> 3) && (~a.s6_addr[ii] & 0xff) != (0xff >> (masklen & 0x07)))
					goto bad;
				else if (a.s6_addr[ii] != 0)
					goto bad;
			}
			script_setenv_int(vpninfo, envname, masklen);
		}
		(*v6_incs)++;
		return 0;
	}

	if (!slash)
		strncpy(uptoslash, route, sizeof(uptoslash)-1);
	else {
		int l = MIN(slash - route, sizeof(uptoslash)-1);
		strncpy(uptoslash, route, l);
		uptoslash[l] = 0;
	}

	/* Network address must be parseable */
	if (!inet_aton(uptoslash, &net_addr)) {
	bad:
		if (include)
			vpn_progress(vpninfo, PRG_ERR,
					 _("Discard bad split include: \"%s\"\n"),
					 route);
		else
			vpn_progress(vpninfo, PRG_ERR,
					 _("Discard bad split exclude: \"%s\"\n"),
					 route);
		return -EINVAL;
	}

	/* Accept netmask in several forms */
	if (!slash) {
		/* no mask (same as /32) */
		masklen = 32;
		mask_addr.s_addr = netmaskbits(32);
	} else if ((masklen = strtol(slash+1, &endp, 10))<=32 && *endp!='.') {
		/* mask is /N */
		mask_addr.s_addr = netmaskbits(masklen);
	} else if (inet_aton(slash+1, &mask_addr)) {
		/* mask is /A.B.C.D */
		masklen = netmasklen(mask_addr);
		/* something invalid like /255.0.0.1 */
		if (netmaskbits(masklen) != mask_addr.s_addr)
			goto bad;
	} else
		goto bad;

	/* Fix incorrectly-set host bits */
	if (net_addr.s_addr & ~mask_addr.s_addr) {
		net_addr.s_addr &= mask_addr.s_addr;
		inet_ntop(AF_INET, &net_addr, abuf, sizeof(abuf));
		if (include)
			vpn_progress(vpninfo, PRG_ERR,
				     _("WARNING: Split include \"%s\" has host bits set, replacing with \"%s/%d\".\n"),
				     route, abuf, masklen);
		else
			vpn_progress(vpninfo, PRG_ERR,
				     _("WARNING: Split exclude \"%s\" has host bits set, replacing with \"%s/%d\".\n"),
				     route, abuf, masklen);
	}

	snprintf(envname, 79, "CISCO_SPLIT_%sC_%d_ADDR", in_ex, *v4_incs);
	script_setenv(vpninfo, envname, inet_ntop(AF_INET, &net_addr, abuf, sizeof(abuf)), 0, 0);

	snprintf(envname, 79, "CISCO_SPLIT_%sC_%d_MASK", in_ex, *v4_incs);
	script_setenv(vpninfo, envname, inet_ntop(AF_INET, &mask_addr, abuf, sizeof(abuf)), 0, 0);

	snprintf(envname, 79, "CISCO_SPLIT_%sC_%d_MASKLEN", in_ex, *v4_incs);
	script_setenv_int(vpninfo, envname, masklen);

	(*v4_incs)++;
	return 0;
}

static void setenv_cstp_opts(struct openconnect_info *vpninfo)
{
	char *env_buf;
	int buflen = 0;
	int bufofs = 0;
	struct oc_vpn_option *opt;

	for (opt = vpninfo->cstp_options; opt; opt = opt->next)
		buflen += 2 + strlen(opt->option) + strlen(opt->value);

	env_buf = malloc(buflen + 1);
	if (!env_buf)
		return;

	env_buf[buflen] = 0;

	for (opt = vpninfo->cstp_options; opt; opt = opt->next)
		bufofs += snprintf(env_buf + bufofs, buflen - bufofs,
				   "%s=%s\n", opt->option, opt->value);

	script_setenv(vpninfo, "CISCO_CSTP_OPTIONS", env_buf, 0, 0);
	free(env_buf);
}

static unsigned char nybble(unsigned char n)
{
	if      (n >= '0' && n <= '9') return n - '0';
	else if (n >= 'A' && n <= 'F') return n - ('A' - 10);
	else if (n >= 'a' && n <= 'f') return n - ('a' - 10);
	return 0;
}

unsigned char unhex(const char *data)
{
	return (nybble(data[0]) << 4) | nybble(data[1]);
}

static void set_banner(struct openconnect_info *vpninfo)
{
	char *banner, *legacy_banner, *q;
	const char *p;

	if (!vpninfo->banner || !(banner = malloc(strlen(vpninfo->banner)+1))) {
		script_setenv(vpninfo, "CISCO_BANNER", NULL, 0, 0);
		return;
	}
	p = vpninfo->banner;
	q = banner;

	while (*p) {
		if (*p == '%' && isxdigit((int)(unsigned char)p[1]) &&
		    isxdigit((int)(unsigned char)p[2])) {
			*(q++) = unhex(p + 1);
			p += 3;
		} else
			*(q++) = *(p++);
	}
	*q = 0;
	legacy_banner = openconnect_utf8_to_legacy(vpninfo, banner);
	script_setenv(vpninfo, "CISCO_BANNER", legacy_banner, 0, 0);
	if (legacy_banner != banner)
		free(legacy_banner);

	free(banner);
}

void prepare_script_env(struct openconnect_info *vpninfo)
{
	if (vpninfo->ip_info.gateway_addr)
		script_setenv(vpninfo, "VPNGATEWAY", vpninfo->ip_info.gateway_addr, 0, 0);

	set_banner(vpninfo);
	script_setenv(vpninfo, "CISCO_SPLIT_INC", NULL, 0, 0);
	script_setenv(vpninfo, "CISCO_SPLIT_EXC", NULL, 0, 0);

	script_setenv_int(vpninfo, "INTERNAL_IP4_MTU", vpninfo->ip_info.mtu);
	script_setenv_int(vpninfo, "VPNPID", (int)getpid());
	script_setenv_int(vpninfo, "LOG_LEVEL", vpninfo->verbose);

	if (vpninfo->idle_timeout)
		script_setenv_int(vpninfo, "IDLE_TIMEOUT", vpninfo->idle_timeout);
	else
		script_setenv(vpninfo, "IDLE_TIMEOUT", NULL, 0, 0);

	if (vpninfo->ip_info.addr) {
		script_setenv(vpninfo, "INTERNAL_IP4_ADDRESS", vpninfo->ip_info.addr, 0, 0);
		if (vpninfo->ip_info.netmask) {
			struct in_addr addr;
			struct in_addr mask;

			if (!inet_aton(vpninfo->ip_info.addr, &addr))
				vpn_progress(vpninfo, PRG_ERR,
					     _("Ignoring legacy network because address \"%s\" is invalid.\n"),
					     vpninfo->ip_info.addr);
			else if (!inet_aton(vpninfo->ip_info.netmask, &mask))
			bad_netmask:
				vpn_progress(vpninfo, PRG_ERR,
					     _("Ignoring legacy network because netmask \"%s\" is invalid.\n"),
					     vpninfo->ip_info.netmask);
			else {
				char netaddr[INET_ADDRSTRLEN];
				int masklen = netmasklen(mask);

				if (netmaskbits(masklen) != mask.s_addr)
					goto bad_netmask;
				addr.s_addr &= mask.s_addr;
				inet_ntop(AF_INET, &addr, netaddr, sizeof(netaddr));

				script_setenv(vpninfo, "INTERNAL_IP4_NETADDR", netaddr, 0, 0);
				script_setenv(vpninfo, "INTERNAL_IP4_NETMASK", vpninfo->ip_info.netmask, 0, 0);
				script_setenv_int(vpninfo, "INTERNAL_IP4_NETMASKLEN", masklen);
			}
		}
	}

	if (vpninfo->ip_info.addr6)
		script_setenv(vpninfo, "INTERNAL_IP6_ADDRESS", vpninfo->ip_info.addr6, 0, 0);
	if (vpninfo->ip_info.netmask6)
		script_setenv(vpninfo, "INTERNAL_IP6_NETMASK", vpninfo->ip_info.netmask6, 0, 0);
	/* The 'netmask6' is actually the address *and* netmask. From which we
	 * obtain just the address on its own, if we don't have it separately */
	if (vpninfo->ip_info.netmask6 && !vpninfo->ip_info.addr6) {
		char *slash = strchr(vpninfo->ip_info.netmask6, '/');
		if (slash)
			script_setenv(vpninfo, "INTERNAL_IP6_ADDRESS", vpninfo->ip_info.netmask6,
				      slash - vpninfo->ip_info.netmask6, 0);
	}

	if (vpninfo->ip_info.dns[0])
		script_setenv(vpninfo, "INTERNAL_IP4_DNS", vpninfo->ip_info.dns[0], 0, 0);
	else
		script_setenv(vpninfo, "INTERNAL_IP4_DNS", NULL, 0, 0);
	if (vpninfo->ip_info.dns[1])
		script_setenv(vpninfo, "INTERNAL_IP4_DNS", vpninfo->ip_info.dns[1], 0, 1);
	if (vpninfo->ip_info.dns[2])
		script_setenv(vpninfo, "INTERNAL_IP4_DNS", vpninfo->ip_info.dns[2], 0, 1);

	/* poorly configured VPNs send non-sensical 0.0.0.0 NBNS server address */
	if (vpninfo->ip_info.nbns[0] && !strcmp(vpninfo->ip_info.nbns[0], "0.0.0.0"))
		script_setenv(vpninfo, "INTERNAL_IP4_NBNS", vpninfo->ip_info.nbns[0], 0, 0);
	else
		script_setenv(vpninfo, "INTERNAL_IP4_NBNS", NULL, 0, 0);
	if (vpninfo->ip_info.nbns[1] && !strcmp(vpninfo->ip_info.nbns[1], "0.0.0.0"))
		script_setenv(vpninfo, "INTERNAL_IP4_NBNS", vpninfo->ip_info.nbns[1], 0, 1);
	if (vpninfo->ip_info.nbns[2] && !strcmp(vpninfo->ip_info.nbns[2], "0.0.0.0"))
		script_setenv(vpninfo, "INTERNAL_IP4_NBNS", vpninfo->ip_info.nbns[2], 0, 1);

	if (vpninfo->ip_info.domain)
		script_setenv(vpninfo, "CISCO_DEF_DOMAIN", vpninfo->ip_info.domain, 0, 0);
	else
		script_setenv(vpninfo, "CISCO_DEF_DOMAIN", NULL, 0, 0);

	if (vpninfo->ip_info.proxy_pac)
		script_setenv(vpninfo, "CISCO_PROXY_PAC", vpninfo->ip_info.proxy_pac, 0, 0);

	if (vpninfo->ip_info.split_dns) {
		char *list;
		int len = 0;
		struct oc_split_include *dns = vpninfo->ip_info.split_dns;

		while (dns) {
			len += strlen(dns->route) + 1;
			dns = dns->next;
		}
		list = malloc(len);
		if (list) {
			char *p = list;

			dns = vpninfo->ip_info.split_dns;
			while (1) {
				strcpy(p, dns->route);
				p += strlen(p);
				dns = dns->next;
				if (!dns)
					break;
				*(p++) = ',';
			}
			script_setenv(vpninfo, "CISCO_SPLIT_DNS", list, 0, 0);
			free(list);
		}
	}

	if (vpninfo->ip_info.split_includes) {
		struct oc_split_include *this = vpninfo->ip_info.split_includes;
		int nr_split_includes = 0;
		int nr_v6_split_includes = 0;

		while (this) {
			process_split_xxclude(vpninfo, 1, this->route,
					      &nr_split_includes,
					      &nr_v6_split_includes);
			this = this->next;
		}
		if (nr_split_includes)
			script_setenv_int(vpninfo, "CISCO_SPLIT_INC", nr_split_includes);
		if (nr_v6_split_includes)
			script_setenv_int(vpninfo, "CISCO_IPV6_SPLIT_INC", nr_v6_split_includes);
	}

	if (vpninfo->ip_info.split_excludes) {
		struct oc_split_include *this = vpninfo->ip_info.split_excludes;
		int nr_split_excludes = 0;
		int nr_v6_split_excludes = 0;

		while (this) {
			process_split_xxclude(vpninfo, 0, this->route,
					      &nr_split_excludes,
					      &nr_v6_split_excludes);
			this = this->next;
		}
		if (nr_split_excludes)
			script_setenv_int(vpninfo, "CISCO_SPLIT_EXC", nr_split_excludes);
		if (nr_v6_split_excludes)
			script_setenv_int(vpninfo, "CISCO_IPV6_SPLIT_EXC", nr_v6_split_excludes);
	}
	setenv_cstp_opts(vpninfo);
}

void free_split_routes(struct oc_ip_info *ip_info)
{
	struct oc_split_include *inc;

	for (inc = ip_info->split_includes; inc; ) {
		struct oc_split_include *next = inc->next;
		free(inc);
		inc = next;
	}
	for (inc = ip_info->split_excludes; inc; ) {
		struct oc_split_include *next = inc->next;
		free(inc);
		inc = next;
	}
	for (inc = ip_info->split_dns; inc; ) {
		struct oc_split_include *next = inc->next;
		free(inc);
		inc = next;
	}
	ip_info->split_dns = ip_info->split_includes =
		ip_info->split_excludes = NULL;
}


#ifdef _WIN32
static wchar_t *create_script_env(struct openconnect_info *vpninfo)
{
	struct oc_vpn_option *opt;
	struct oc_text_buf *envbuf;
	wchar_t **oldenv, **p, *newenv = NULL;
	int nr_envs = 0, i;

	/* _wenviron is NULL until we call _wgetenv() */
	(void)_wgetenv(L"PATH");

	/* Take a copy of _wenviron (but not of its strings) */
	for (p = _wenviron; *p; p++)
		nr_envs++;

	oldenv = malloc(nr_envs * sizeof(*oldenv));
	if (!oldenv)
		return NULL;
	memcpy(oldenv, _wenviron, nr_envs * sizeof(*oldenv));

	envbuf = buf_alloc();

	/* Add the script environment variables, prodding out any members of
	   oldenv which are obsoleted by them. */
	for (opt = vpninfo->script_env; opt && !buf_error(envbuf); opt = opt->next) {
		struct oc_text_buf *buf;

		buf = buf_alloc();
		buf_append_utf16le(buf, opt->option);
		buf_append_utf16le(buf, "=");

		if (buf_error(buf)) {
			buf_free(buf);
			goto err;
		}

		/* See if we can find it in the existing environment */
		for (i = 0; i < nr_envs; i++) {
			if (oldenv[i] &&
			    !wcsncmp((wchar_t *)buf->data, oldenv[i], buf->pos / 2)) {
				oldenv[i] = NULL;
				break;
			}
		}

		if (opt->value) {
			buf_append_bytes(envbuf, buf->data, buf->pos);
			buf_append_utf16le(envbuf, opt->value);
			buf_append_bytes(envbuf, "\0\0", 2);
		}

		buf_free(buf);
	}

	for (i = 0; i < nr_envs && !buf_error(envbuf); i++) {
		if (oldenv[i])
			buf_append_bytes(envbuf, oldenv[i],
					 (wcslen(oldenv[i]) + 1) * sizeof(wchar_t));
	}

	buf_append_bytes(envbuf, "\0\0", 2);

	if (!buf_error(envbuf)) {
		newenv = (wchar_t *)envbuf->data;
		envbuf->data = NULL;
	}

 err:
	free(oldenv);
	buf_free(envbuf);
	return newenv;
}

int script_config_tun(struct openconnect_info *vpninfo, const char *reason)
{
	wchar_t *script_w;
	wchar_t *script_env;
	int nr_chars;
	int ret;
	char *cmd;
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	DWORD cpflags, exit_status;

	if (!vpninfo->vpnc_script || vpninfo->script_tun)
		return 0;

	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	/* probably superfluous */
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;

	script_setenv(vpninfo, "reason", reason, 0, 0);

	if (asprintf(&cmd, "cscript.exe \"%s\"", vpninfo->vpnc_script) == -1)
		return 0;

	nr_chars = MultiByteToWideChar(CP_UTF8, 0, cmd, -1, NULL, 0);
	script_w = malloc(nr_chars * sizeof(wchar_t));

	if (!script_w) {
		free(cmd);
		return -ENOMEM;
	}

	MultiByteToWideChar(CP_UTF8, 0, cmd, -1, script_w, nr_chars);

	free(cmd);

	script_env = create_script_env(vpninfo);

	cpflags = CREATE_UNICODE_ENVIRONMENT;
	/* If we're running from a console, let the script use it too. */
	if (!GetConsoleWindow())
		cpflags |= CREATE_NO_WINDOW;

	if (CreateProcessW(NULL, script_w, NULL, NULL, FALSE, cpflags,
			   script_env, NULL, &si, &pi)) {
		ret = WaitForSingleObject(pi.hProcess,10000);
		if (!GetExitCodeProcess(pi.hProcess, &exit_status)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to get script exit status: %s\n"),
				     openconnect__win32_strerror(GetLastError()));
			ret = -EIO;
		} else if (exit_status > 0 && exit_status != STILL_ACTIVE) {
			/* STILL_ACTIVE == 259. That means that a perfectly normal positive integer return value overlaps with
			 * an exceptional condition. Don't blame me. I didn't design this.
			 * https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodeprocess#remarks
			 */
			vpn_progress(vpninfo, PRG_ERR,
				     _("Script '%s' returned error %ld\n"),
				     vpninfo->vpnc_script, exit_status);
			ret = -EIO;
		}
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		if (ret == WAIT_TIMEOUT || exit_status == STILL_ACTIVE) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Script did not complete within 10 seconds.\n"));
			ret = -ETIMEDOUT;
		} else if (ret != -EIO)
			ret = 0;
	} else {
		ret = -EIO;
	}

	free(script_env);

	if (ret < 0) {
		char *errstr = openconnect__win32_strerror(GetLastError());
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to spawn script '%s' for %s: %s\n"),
			     vpninfo->vpnc_script, reason, errstr);
		free(errstr);
		goto cleanup;
	}

 cleanup:
	free(script_w);
	return ret;
}
#else
/* Must only be run after fork(). */
int apply_script_env(struct oc_vpn_option *envs)
{
	struct oc_vpn_option *p;

	for (p = envs; p; p = p->next) {
		if (p->value)
			setenv(p->option, p->value, 1);
		else
			unsetenv(p->option);
	}
	return 0;
}

int script_config_tun(struct openconnect_info *vpninfo, const char *reason)
{
	int ret;
	pid_t pid;

	if (!vpninfo->vpnc_script || vpninfo->script_tun)
		return 0;

	pid = fork();
	if (!pid) {
		/* Child */
		char *script = openconnect_utf8_to_legacy(vpninfo, vpninfo->vpnc_script);

		apply_script_env(vpninfo->script_env);

		setenv("reason", reason, 1);

		execl("/bin/sh", "/bin/sh", "-c", script, NULL);
		exit(127);
	}
	if (pid == -1 || waitpid(pid, &ret, 0) == -1) {
		int err = errno;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to spawn script '%s' for %s: %s\n"),
			     vpninfo->vpnc_script, reason, strerror(err));
		return -err;
	}

	if (!WIFEXITED(ret)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Script '%s' exited abnormally (%x)\n"),
			       vpninfo->vpnc_script, ret);
		return -EIO;
	}

	ret = WEXITSTATUS(ret);
	if (ret) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Script '%s' returned error %d\n"),
			     vpninfo->vpnc_script, ret);
		return -EIO;
	}
	return 0;
}
#endif
