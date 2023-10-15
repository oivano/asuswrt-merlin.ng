/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2021 David Woodhouse.
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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <errno.h>
#include <stdio.h>

static WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
static WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
static WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
static WINTUN_DELETE_DRIVER_FUNC *WintunDeleteDriver;
static WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
static WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
static WINTUN_START_SESSION_FUNC *WintunStartSession;
static WINTUN_END_SESSION_FUNC *WintunEndSession;
static WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
static WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
static WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

static struct openconnect_info *logger_vpninfo;

#define WINTUN_TUNNEL_TYPE L"OpenConnect"
#define WINTUN_RING_CAPACITY 0x400000 /* 4 MiB */

static void CALLBACK wintun_log_fn(WINTUN_LOGGER_LEVEL wlvl, DWORD64 wts, const WCHAR *wmsg)
{
	int lvl = (wlvl == WINTUN_LOG_INFO) ? PRG_INFO : PRG_ERR;

	/* Sadly, Wintun doesn't provide any context information in the callback */
	if (!logger_vpninfo)
		return;

	vpn_progress(logger_vpninfo, lvl, "%d: %S\n", wlvl, wmsg);
}

static int init_wintun(struct openconnect_info *vpninfo)
{
	if (!vpninfo->wintun) {
		vpninfo->wintun = LoadLibraryExW(L"wintun.dll", NULL,
						 LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
						 LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (!vpninfo->wintun) {
			vpn_progress(vpninfo, PRG_DEBUG, _("Could not load wintun.dll\n"));
			return -ENOENT;
		}

#define Resolve(Name) ((Name = (void *)GetProcAddress(vpninfo->wintun, #Name)) == NULL)
		if (Resolve(WintunCreateAdapter) || Resolve(WintunOpenAdapter) ||
		    Resolve(WintunCloseAdapter) || Resolve(WintunDeleteDriver) ||
		    Resolve(WintunGetAdapterLUID) || Resolve(WintunGetRunningDriverVersion) ||
		    Resolve(WintunSetLogger) || Resolve(WintunStartSession) ||
		    Resolve(WintunEndSession) || Resolve(WintunGetReadWaitEvent) ||
		    Resolve(WintunReceivePacket) || Resolve(WintunReleaseReceivePacket) ||
		    Resolve(WintunAllocateSendPacket) || Resolve(WintunSendPacket)) {
#undef Resolve
			vpn_progress(vpninfo, PRG_ERR, _("Could not resolve functions from wintun.dll\n"));
			FreeLibrary(vpninfo->wintun);
			vpninfo->wintun = NULL;
			return -EIO;
		}

		logger_vpninfo = vpninfo;
		WintunSetLogger(wintun_log_fn);
	}

	return 0;
}

int create_wintun(struct openconnect_info *vpninfo)
{
	int ret = init_wintun(vpninfo);
	if (ret < 0)
		return ret;

	vpninfo->wintun_adapter = WintunCreateAdapter(vpninfo->ifname_w,
						      WINTUN_TUNNEL_TYPE, NULL);
	if (vpninfo->wintun_adapter)
		return 0;

	ret = GetLastError();
	char *errstr = openconnect__win32_strerror(ret);
	vpn_progress(vpninfo, PRG_ERR, "Could not create Wintun adapter '%S': %s\n",
		     vpninfo->ifname_w, errstr);
	free(errstr);
	return (ret == ERROR_ACCESS_DENIED ? -EPERM : -EIO);
}

intptr_t open_wintun(struct openconnect_info *vpninfo, char *guid, wchar_t *wname)
{
	intptr_t ret;

	if (init_wintun(vpninfo))
		return 0;

	if (!vpninfo->wintun_adapter) {
		vpninfo->wintun_adapter = WintunOpenAdapter(wname);
		if (!vpninfo->wintun_adapter) {
			char *errstr = openconnect__win32_strerror(GetLastError());
			vpn_progress(vpninfo, PRG_ERR, "Could not open Wintun adapter '%S': %s\n",
				     wname, errstr);
			free(errstr);

			ret = OPEN_TUN_SOFTFAIL;
			goto out;
		}
	}

	DWORD ver = WintunGetRunningDriverVersion();
	vpn_progress(vpninfo, PRG_DEBUG, _("Loaded Wintun v%lu.%lu\n"),
		     (ver >> 16) & 0xff, ver & 0xff);

	vpninfo->wintun_session = WintunStartSession(vpninfo->wintun_adapter,
	                                             WINTUN_RING_CAPACITY);
	if (!vpninfo->wintun_session) {
		char *errstr = openconnect__win32_strerror(GetLastError());
		vpn_progress(vpninfo, PRG_ERR, _("Failed to create Wintun session: %s\n"),
			     errstr);
		free(errstr);

		ret = OPEN_TUN_HARDFAIL;
		goto out;
	}

	return 1;
 out:
	os_shutdown_wintun(vpninfo);
	return ret;
}

int os_read_wintun(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	DWORD tun_len;
	BYTE *tun_pkt = WintunReceivePacket(vpninfo->wintun_session,
					    &tun_len);
	if (!tun_pkt) {
		DWORD err = GetLastError();
		if (err != ERROR_NO_MORE_ITEMS) {
			char *errstr = openconnect__win32_strerror(err);
			vpn_progress(vpninfo, PRG_ERR, _("Could not retrieve packet from Wintun adapter '%S': %s\n"),
				     vpninfo->ifname_w, errstr);
			free(errstr);
		}
		return -1;
	}

	int ret = 0;
	if (tun_len <= pkt->len) {
		memcpy(pkt->data, tun_pkt, tun_len);
		pkt->len = tun_len;
	} else {
		vpn_progress(vpninfo, PRG_ERR, _("Drop oversized packet retrieved from Wintun adapter '%S' (%ld > %d)\n"),
			     vpninfo->ifname_w, tun_len, pkt->len);
		ret = -1;
	}
	WintunReleaseReceivePacket(vpninfo->wintun_session, tun_pkt);
	return ret;
}

int os_write_wintun(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	BYTE *tun_pkt = WintunAllocateSendPacket(vpninfo->wintun_session,
						 pkt->len);
	if (!tun_pkt) {
		DWORD err = GetLastError();
		char *errstr = openconnect__win32_strerror(err);
		vpn_progress(vpninfo, PRG_ERR, _("Could not send packet through Wintun adapter '%S': %s\n"),
			     vpninfo->ifname_w, errstr);
		free(errstr);
		return -1;
	}

	memcpy(tun_pkt, pkt->data, pkt->len);
	WintunSendPacket(vpninfo->wintun_session, tun_pkt);
	return 0;
}

void os_shutdown_wintun(struct openconnect_info *vpninfo)
{
	if (vpninfo->wintun_session) {
		WintunEndSession(vpninfo->wintun_session);
		vpninfo->wintun_session = NULL;
	}
	if (vpninfo->wintun_adapter) {
		WintunCloseAdapter(vpninfo->wintun_adapter);
		vpninfo->wintun_adapter = NULL;
	}
	logger_vpninfo = NULL;
	FreeLibrary(vpninfo->wintun);
	vpninfo->wintun = NULL;
}

int setup_wintun_fd(struct openconnect_info *vpninfo, intptr_t tun_fd)
{
	vpninfo->tun_rd_overlap.hEvent = WintunGetReadWaitEvent(vpninfo->wintun_session);
	monitor_read_fd(vpninfo, tun);
	vpninfo->tun_fh = (HANDLE)tun_fd;
	return 0;
}
