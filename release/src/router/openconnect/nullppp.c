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
#include "ppp.h"

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

int nullppp_obtain_cookie(struct openconnect_info *vpninfo)
{
	if (!(vpninfo->cookie = strdup("")))
		return -ENOMEM;
	return 0;
}

int nullppp_connect(struct openconnect_info *vpninfo)
{
	int ret;
	int ipv4, ipv6, hdlc;

	/* XX: cookie hack. Use -C hdlc,noipv4,noipv6,term on the
	 * command line to set options. */
	hdlc = strstr(vpninfo->cookie, "hdlc") ? 1 : 0;
	ipv4 = strstr(vpninfo->cookie, "noipv4") ? 0 : 1;
	ipv6 = strstr(vpninfo->cookie, "noipv6") ? 0 : 1;

	/* Now establish the actual connection */
	ret = openconnect_open_https(vpninfo);
	if (ret)
		goto out;

	ret = openconnect_ppp_new(vpninfo,
				  hdlc ? PPP_ENCAP_RFC1662_HDLC : PPP_ENCAP_RFC1661,
				  ipv4, ipv6);
	if (!ret) {
		/* Trigger the first PPP negotiations and ensure the PPP state
		 * is PPPS_ESTABLISH so that ppp_tcp_mainloop() knows we've started. */
		ppp_start_tcp_mainloop(vpninfo);
	}
 out:
	if (ret)
		openconnect_close_https(vpninfo, 0);
	else {
		monitor_fd_new(vpninfo, ssl);
		monitor_read_fd(vpninfo, ssl);
		monitor_except_fd(vpninfo, ssl);
	}

	return ret;
}

int nullppp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	if (vpninfo->ppp->ppp_state >= PPPS_NETWORK &&
	    strstr(vpninfo->cookie, "term")) {
		vpninfo->got_cancel_cmd = 1;
		vpn_progress(vpninfo, PRG_ERR,
			     _("Terminating because nullppp has reached network state.\n"));
	}

	return ppp_tcp_mainloop(vpninfo, timeout, readable);
}
