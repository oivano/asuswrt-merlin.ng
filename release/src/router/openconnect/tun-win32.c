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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>
/* must precede iphlpapi.h, per https://docs.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh */
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include <errno.h>
#include <stdio.h>

/*
 * TAP-Windows support inspired by http://i3.cs.berkeley.edu/ (v0.2) with
 * permission.
 */
#define _TAP_IOCTL(nr) CTL_CODE(FILE_DEVICE_UNKNOWN, nr, METHOD_BUFFERED, \
				FILE_ANY_ACCESS)

#define TAP_IOCTL_GET_MAC               _TAP_IOCTL(1)
#define TAP_IOCTL_GET_VERSION           _TAP_IOCTL(2)
#define TAP_IOCTL_GET_MTU               _TAP_IOCTL(3)
#define TAP_IOCTL_GET_INFO              _TAP_IOCTL(4)
#define TAP_IOCTL_CONFIG_POINT_TO_POINT _TAP_IOCTL(5)
#define TAP_IOCTL_SET_MEDIA_STATUS      _TAP_IOCTL(6)
#define TAP_IOCTL_CONFIG_DHCP_MASQ      _TAP_IOCTL(7)
#define TAP_IOCTL_GET_LOG_LINE          _TAP_IOCTL(8)
#define TAP_IOCTL_CONFIG_DHCP_SET_OPT   _TAP_IOCTL(9)
#define TAP_IOCTL_CONFIG_TUN            _TAP_IOCTL(10)

/* TAP driver 9.21.2 we download from the OpenVPN download page */
#define TAP_COMPONENT_ID "tap0901"
/* TAP driver bundled with OpenVPN */
#define TAP_OVPNCONNECT_COMPONENT_ID "tap_ovpnconnect"

#define DEVTEMPLATE "\\\\.\\Global\\%s.tap"

#define NETDEV_GUID "{4D36E972-E325-11CE-BFC1-08002BE10318}"
#define CONTROL_KEY "SYSTEM\\CurrentControlSet\\Control\\"

#define ADAPTERS_KEY CONTROL_KEY "Class\\" NETDEV_GUID
#define CONNECTIONS_KEY CONTROL_KEY "Network\\" NETDEV_GUID

#define ADAPTER_TUNTAP 0
#define ADAPTER_WINTUN 1

typedef intptr_t (tap_callback)(struct openconnect_info *vpninfo, int type, char *idx, wchar_t *name);

#define SEARCH_CONTINUE	0
#define SEARCH_DONE	1

static intptr_t search_taps(struct openconnect_info *vpninfo, tap_callback *cb)
{
	LONG status;
	HKEY adapters_key, hkey;
	DWORD len, type;
	int adapter_type;
	char buf[40];
	wchar_t name[40];
	char keyname[strlen(CONNECTIONS_KEY) + sizeof(buf) + 1 + strlen("\\Connection")];
	int i = 0;
	intptr_t ret = OPEN_TUN_SOFTFAIL;

	status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, ADAPTERS_KEY, 0,
			       KEY_READ, &adapters_key);
	if (status) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error accessing registry key for network adapters\n"));
		return -EIO;
	}
	while (ret == OPEN_TUN_SOFTFAIL) {
		len = sizeof(buf);
		status = RegEnumKeyExA(adapters_key, i++, buf, &len,
				       NULL, NULL, NULL, NULL);
		if (status) {
			if (status != ERROR_NO_MORE_ITEMS)
				ret = OPEN_TUN_HARDFAIL;
			break;
		}

		snprintf(keyname, sizeof(keyname), "%s\\%s",
			 ADAPTERS_KEY, buf);

		status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyname, 0,
				       KEY_QUERY_VALUE, &hkey);
		if (status)
			continue;

		len = sizeof(buf);
		status = RegQueryValueExA(hkey, "ComponentId", NULL, &type,
					  (unsigned char *)buf, &len);
		if (status || type != REG_SZ) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Cannot read %s\\%s or is not string\n"),
				     keyname, "ComponentId");
			RegCloseKey(hkey);
			continue;
		}
		if (!stricmp(buf, TAP_COMPONENT_ID) || !stricmp(buf, "root\\" TAP_COMPONENT_ID) ||
		    !stricmp(buf, TAP_OVPNCONNECT_COMPONENT_ID) ||
		    !stricmp(buf, "root\\" TAP_OVPNCONNECT_COMPONENT_ID))
			adapter_type = ADAPTER_TUNTAP;
		else if (!stricmp(buf, "Wintun"))
			adapter_type = ADAPTER_WINTUN;
		else {
			vpn_progress(vpninfo, PRG_TRACE, _("%s\\ComponentId is unknown '%s'\n"),
				     keyname, buf);
			RegCloseKey(hkey);
			continue;
		}

		vpn_progress(vpninfo, PRG_TRACE, _("Found %s at %s\n"),
			     buf, keyname);

		len = sizeof(buf);
		status = RegQueryValueExA(hkey, "NetCfgInstanceId", NULL,
					  &type, (unsigned char *)buf, &len);
		RegCloseKey(hkey);
		if (status || type != REG_SZ)
			continue;

		snprintf(keyname, sizeof(keyname), "%s\\%s\\Connection",
			 CONNECTIONS_KEY, buf);

		status = RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyname, 0,
				       KEY_QUERY_VALUE, &hkey);
		if (status) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Cannot open registry key %s\n"),
				     keyname);
			continue;
		}

		len = sizeof(name);
		status = RegQueryValueExW(hkey, L"Name", NULL, &type,
					 (unsigned char *)name, &len);
		RegCloseKey(hkey);
		if (status || type != REG_SZ) {
			vpn_progress(vpninfo, PRG_INFO,
				     _("Cannot read registry key %s\\%s or is not string\n"),
				     keyname, "Name");
			continue;
		}

		ret = cb(vpninfo, adapter_type, buf, name);
	}

	RegCloseKey(adapters_key);

	return ret;
}

#ifndef __LIST_TAPS__

static int get_adapter_index(struct openconnect_info *vpninfo, char *guid)
{
	struct oc_text_buf *buf = buf_alloc();
	IP_ADAPTER_INFO *adapter;
	void *adapters_buf;
	ULONG idx;
	DWORD status;
	int ret = -EINVAL;

	vpninfo->tun_idx = -1;

	buf_append_utf16le(buf, "\\device\\tcpip_");
	buf_append_utf16le(buf, guid);
	if (buf_error(buf)) {
		/* If we didn't manage to malloc for this, we're never
		 * going to manage for GetAdaptersInfo(). Give up. */
		return buf_free(buf);
	}
	status = GetAdapterIndex((void *)buf->data, &idx);
	buf_free(buf);
	if (status == NO_ERROR) {
		vpninfo->tun_idx = idx;
		return 0;
	} else {
		char *errstr = openconnect__win32_strerror(status);
		vpn_progress(vpninfo, PRG_INFO,
			     _("GetAdapterIndex() failed: %s\nFalling back to GetAdaptersInfo()\n"),
			     errstr);
		free(errstr);
	}
	idx = 0;
	status = GetAdaptersInfo(NULL, &idx);
	if (status != ERROR_BUFFER_OVERFLOW)
		return -EIO;
	adapters_buf = malloc(idx);
	if (!adapters_buf)
		return -ENOMEM;
	status = GetAdaptersInfo(adapters_buf, &idx);
	if (status != NO_ERROR) {
		char *errstr = openconnect__win32_strerror(status);
		vpn_progress(vpninfo, PRG_ERR, _("GetAdaptersInfo() failed: %s\n"), errstr);
		free(errstr);
		free(adapters_buf);
		return -EIO;
	}

	for (adapter = adapters_buf; adapter; adapter = adapter->Next) {
		if (!strcmp(adapter->AdapterName, guid)) {
			vpninfo->tun_idx = adapter->Index;
			ret = 0;
			break;
		}
	}
	free(adapters_buf);
	return ret;
}

static int check_address_conflicts(struct openconnect_info *vpninfo)
{
	ULONG bufSize = 15000;
	PIP_ADAPTER_ADDRESSES addresses = NULL;
	DWORD LastError;
	int ret = 0;

	struct in_addr our_ipv4_addr;
	struct in6_addr our_ipv6_addr;
	if (vpninfo->ip_info.addr && !inet_aton(vpninfo->ip_info.addr, &our_ipv4_addr))
		return -EINVAL;
	if (vpninfo->ip_info.addr6 && !inet_pton(AF_INET6, vpninfo->ip_info.addr6, &our_ipv6_addr))
		return -EINVAL;

	/* XX: repeat twice, because it may tell us we need a bigger buffer */
	for (int tries=0; tries<2; tries++) {
		free(addresses);
		addresses = malloc(bufSize);
		if (!addresses)
			return -ENOMEM;

		/* AF_UNSPEC means both Legacy IP and IPv6 */
		LastError = GetAdaptersAddresses(AF_UNSPEC,
						 GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
						 NULL, addresses, &bufSize);
		if (LastError != ERROR_BUFFER_OVERFLOW)
			break;
	}
	if (LastError != ERROR_SUCCESS) {
		char *errstr = openconnect__win32_strerror(LastError);
		vpn_progress(vpninfo, PRG_ERR, _("GetAdaptersAddresses() failed: %s\n"), errstr);
		ret = -EIO;
		goto out;
	}

	for (; addresses; addresses=addresses->Next) {
		/* XX: skip "our own" adapter */
		if (addresses->IfIndex == vpninfo->tun_idx)
			continue;

		for (PIP_ADAPTER_UNICAST_ADDRESS ua = addresses->FirstUnicastAddress;
		     ua; ua=ua->Next) {
			struct sockaddr *a = ua->Address.lpSockaddr;
			union {
				struct sockaddr_in s4;
				struct sockaddr_in6 s6;
			} *sa = (void *)a;
			int needs_reclaim = 0;

			if (a->sa_family == AF_INET) {
				if (vpninfo->ip_info.addr && our_ipv4_addr.s_addr == sa->s4.sin_addr.s_addr)
					needs_reclaim = 1;
			} else if (a->sa_family == AF_INET6) {
				if (vpninfo->ip_info.addr6 && !memcmp(&our_ipv6_addr, &sa->s6.sin6_addr, sizeof(sa->s6.sin6_addr)))
					needs_reclaim = 1;
			}

			if (needs_reclaim) {
				if (addresses->OperStatus == IfOperStatusUp) {
					/* XX: Interface is up. We shouldn't steal its address */
					vpn_progress(vpninfo, PRG_ERR,
						     _("Adapter \"%S\" / %ld is UP and using our IPv%d address. Cannot resolve.\n"),
						     addresses->FriendlyName, addresses->IfIndex, a->sa_family == AF_INET ? 4 : 6);
					ret = -ENOENT;
					goto out;
				} else {
					/* XX: Interface is down */
					vpn_progress(vpninfo, PRG_ERR,
						     _("Adapter \"%S\" / %ld is DOWN and using our IPv%d address. We will reclaim the address from it.\n"),
						     addresses->FriendlyName, addresses->IfIndex, a->sa_family == AF_INET ? 4 : 6);

					/* XX: In order to use DeleteUnicastIpAddressEntry(), we bizarrely have to iterate through a
					 * whole different table of IP addresses to find the right row. I previously tried
					 * faking/synthesizing the requisite MIB_UNICASTIPADDRESS_TABLE rows, and it did not
					 * work.
					 */
					int found = 0;
					PMIB_UNICASTIPADDRESS_TABLE pipTable = NULL;
					LastError = GetUnicastIpAddressTable(AF_UNSPEC, &pipTable);
					if (LastError != ERROR_SUCCESS) {
						char *errstr = openconnect__win32_strerror(LastError);
						vpn_progress(vpninfo, PRG_ERR, _("GetUnicastIpAddressTable() failed: %s\n"), errstr);
						ret = -EIO;
						goto out;
					}
					for (int i = 0; i < pipTable->NumEntries; i++) {
						if (pipTable->Table[i].Address.si_family == AF_INET && a->sa_family == AF_INET) {
							if (sa->s4.sin_addr.s_addr == pipTable->Table[i].Address.Ipv4.sin_addr.s_addr)
								found = 1;
						} else if (pipTable->Table[i].Address.si_family == AF_INET6 && a->sa_family == AF_INET6) {
							if (!memcmp(&sa->s6.sin6_addr, &pipTable->Table[i].Address.Ipv6, sizeof(sa->s6.sin6_addr)))
								found = 1;
						}
						if (found) {
							LastError = DeleteUnicastIpAddressEntry(&pipTable->Table[i]);
							break;
						}
					}
					FreeMibTable(pipTable);

					if (LastError != NO_ERROR) {
						char *errstr = openconnect__win32_strerror(LastError);
						vpn_progress(vpninfo, PRG_ERR, _("DeleteUnicastIpAddressEntry() failed: %s\n"), errstr);
						ret = -EIO;
						goto out;
					}

					if (!found) {
						vpn_progress(vpninfo, PRG_ERR,
							     _("GetUnicastIpAddressTable() did not find matching address to reclaim\n"));
						/* ret = -EIO;
						   goto out; */
					}

				}
			}
		}
	}

 out:
	free(addresses);
	return ret;
}

static intptr_t open_tuntap(struct openconnect_info *vpninfo, char *guid, wchar_t *wname)
{
	char devname[80];
	HANDLE tun_fh;
	ULONG data[3];
	DWORD len;

	snprintf(devname, sizeof(devname), DEVTEMPLATE, guid);
	tun_fh = CreateFileA(devname, GENERIC_WRITE|GENERIC_READ, 0, 0,
			     OPEN_EXISTING,
			     FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
			     0);
	if (tun_fh == INVALID_HANDLE_VALUE) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to open %s\n"),
			     devname);
		return OPEN_TUN_SOFTFAIL;

	}
	vpn_progress(vpninfo, PRG_DEBUG, _("Opened tun device %S\n"), wname);

	if (!DeviceIoControl(tun_fh, TAP_IOCTL_GET_VERSION,
			     data, sizeof(data), data, sizeof(data),
			     &len, NULL)) {
		char *errstr = openconnect__win32_strerror(GetLastError());

		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to obtain TAP driver version: %s\n"), errstr);
		free(errstr);
		return OPEN_TUN_HARDFAIL;
	}
	if (data[0] < 9 || (data[0] == 9 && data[1] < 9)) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Error: TAP-Windows driver v9.9 or greater is required (found %ld.%ld)\n"),
			     data[0], data[1]);
		return -1;
	}
	vpn_progress(vpninfo, PRG_DEBUG, "TAP-Windows driver v%ld.%ld (%ld)\n",
		     data[0], data[1], data[2]);

	data[0] = inet_addr(vpninfo->ip_info.addr);
	/* Set network and mask both to 0.0.0.0. It's not about routing;
	 * it just ensures that the TAP driver fakes ARP responses for
	 * *everything* we throw at it, and we can just configure them
	 * as on-link routes. */
	data[1] = 0;
	data[2] = 0;

	if (!DeviceIoControl(tun_fh, TAP_IOCTL_CONFIG_TUN,
			     data, sizeof(data), data, sizeof(data),
			     &len, NULL)) {
		char *errstr = openconnect__win32_strerror(GetLastError());

		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set TAP IP addresses: %s\n"), errstr);
		free(errstr);
		return OPEN_TUN_HARDFAIL;
	}

	data[0] = 1;
	if (!DeviceIoControl(tun_fh, TAP_IOCTL_SET_MEDIA_STATUS,
			     data, sizeof(data[0]), data, sizeof(data[0]),
			     &len, NULL)) {
		char *errstr = openconnect__win32_strerror(GetLastError());

		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to set TAP media status: %s\n"), errstr);
		free(errstr);
		return OPEN_TUN_HARDFAIL;
	}

	return (intptr_t)tun_fh;
}

static intptr_t open_tun(struct openconnect_info *vpninfo, int adapter_type, char *guid, wchar_t *wname)
{
	intptr_t ret = -1;

	if (vpninfo->ifname_w && wcscmp(wname, vpninfo->ifname_w)) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Ignoring non-matching interface \"%S\"\n"),
			     wname);
		return 0;
	}

	if (adapter_type == ADAPTER_TUNTAP)
		ret = open_tuntap(vpninfo, guid, wname);
	else
		ret = open_wintun(vpninfo, guid, wname);

	if (ret == OPEN_TUN_SOFTFAIL || ret == OPEN_TUN_HARDFAIL)
		return ret;

	/*
	 * We have found the adapter and opened it successfully. Now set
	 * vpninfo->ifname accordingly, if necessary, and find $TUNIDX
	 * for the script to use to configure it.
	 */
	if (!vpninfo->ifname) {
		struct oc_text_buf *namebuf = buf_alloc();

		buf_append_from_utf16le(namebuf, wname);
		if (buf_error(namebuf)) {
			vpn_progress(vpninfo, PRG_ERR, _("Could not convert interface name to UTF-8\n"));
			os_shutdown_tun(vpninfo);

			buf_free(namebuf);
			return OPEN_TUN_HARDFAIL;
		}
		vpninfo->ifname = namebuf->data;
		namebuf->data = NULL;
		buf_free(namebuf);
	}

	get_adapter_index(vpninfo, guid);

	vpn_progress(vpninfo, adapter_type ? PRG_ERR : PRG_INFO,
		     _("Using %s device '%s', index %d\n"),
		     adapter_type ? "Wintun" : "TAP-Windows",
		     vpninfo->ifname, vpninfo->tun_idx);
	if (adapter_type == ADAPTER_WINTUN)
		vpn_progress(vpninfo, PRG_ERR,
			     _("WARNING: Support for Wintun is experimental and may be unstable. If you\n"
			       "  encounter problems, install the TAP-Windows driver instead. See\n"
			       "  %s\n"),
			     "https://www.infradead.org/openconnect/building.html");

	return ret;
}

static intptr_t create_ifname_w(struct openconnect_info *vpninfo,
				const char *ifname)
{
	struct oc_text_buf *ifname_buf = buf_alloc();

	buf_append_utf16le(ifname_buf, ifname);

	if (buf_error(ifname_buf)) {
		vpn_progress(vpninfo, PRG_ERR, _("Could not construct interface name\n"));
		return buf_free(ifname_buf);
	}

	free(vpninfo->ifname_w);
	vpninfo->ifname_w = (wchar_t *)ifname_buf->data;
	ifname_buf->data = NULL;
	buf_free(ifname_buf);
	return 0;
}

intptr_t os_setup_tun(struct openconnect_info *vpninfo)
{
	intptr_t ret;

	if (vpninfo->ifname) {
		ret = create_ifname_w(vpninfo, vpninfo->ifname);
		if (ret)
			return ret;
	}

	ret = search_taps(vpninfo, open_tun);

	if (ret == OPEN_TUN_SOFTFAIL) {
		if (!vpninfo->ifname_w) {
			ret = create_ifname_w(vpninfo, vpninfo->hostname);
			if (ret)
				return ret;
		}

		/* Try creating a Wintun instead of TAP */
		int retw = create_wintun(vpninfo);
		if (!retw) {
			ret = search_taps(vpninfo, open_tun);

			if (ret == OPEN_TUN_SOFTFAIL)
				ret = OPEN_TUN_HARDFAIL;
			if (ret == OPEN_TUN_HARDFAIL)
				os_shutdown_wintun(vpninfo);
		} else if (retw == -EPERM) {
			ret = OPEN_TUN_HARDFAIL;
			vpn_progress(vpninfo, PRG_ERR,
				     _("Access denied creating Wintun adapter. Are you running with Administrator privileges?\n"));
		}
	}

	if (ret == OPEN_TUN_SOFTFAIL) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("Neither Windows-TAP nor Wintun adapters were found. Is the driver installed?\n"));
		ret = OPEN_TUN_HARDFAIL;
	}

	if (check_address_conflicts(vpninfo) < 0)
		ret = OPEN_TUN_HARDFAIL; /* already complained about it */

	return ret;
}

int os_read_tun(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	DWORD pkt_size;
	if (vpninfo->wintun)
		return os_read_wintun(vpninfo, pkt);

 reread:
	if (!vpninfo->tun_rd_pending &&
	    !ReadFile(vpninfo->tun_fh, pkt->data, pkt->len, &pkt_size,
		      &vpninfo->tun_rd_overlap)) {
		DWORD err = GetLastError();

		if (err == ERROR_IO_PENDING)
			vpninfo->tun_rd_pending = 1;
		else if (err == ERROR_OPERATION_ABORTED) {
			vpninfo->quit_reason = "TAP device aborted";
			vpn_progress(vpninfo, PRG_ERR,
				     _("TAP device aborted connectivity. Disconnecting.\n"));
			return -1;
		} else {
			char *errstr = openconnect__win32_strerror(err);
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to read from TAP device: %s\n"),
				     errstr);
			free(errstr);
		}
		return -1;
	} else if (!GetOverlappedResult(vpninfo->tun_fh,
					&vpninfo->tun_rd_overlap, &pkt_size,
					FALSE)) {
		DWORD err = GetLastError();

		if (err != ERROR_IO_INCOMPLETE) {
			char *errstr = openconnect__win32_strerror(err);
			vpninfo->tun_rd_pending = 0;
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to complete read from TAP device: %s\n"),
				     errstr);
			free(errstr);
			goto reread;
		}
		return -1;
	}

	/* Either a straight ReadFile() or a subsequent GetOverlappedResult()
	   succeeded... */
	vpninfo->tun_rd_pending = 0;
	pkt->len = pkt_size;
	return 0;
}

int os_write_tun(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	DWORD pkt_size = 0;
	DWORD err;
	char *errstr;

	if (vpninfo->wintun)
		return os_write_wintun(vpninfo, pkt);

	if (WriteFile(vpninfo->tun_fh, pkt->data, pkt->len, &pkt_size, &vpninfo->tun_wr_overlap)) {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Wrote %ld bytes to tun\n"), pkt_size);
		return 0;
	}

	err = GetLastError();
	if (err == ERROR_IO_PENDING) {
		/* Theoretically we should let the mainloop handle this blocking,
		   but that's non-trivial and it doesn't ever seem to happen in
		   practice anyway. */
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Waiting for tun write...\n"));
		if (GetOverlappedResult(vpninfo->tun_fh, &vpninfo->tun_wr_overlap, &pkt_size, TRUE)) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Wrote %ld bytes to tun after waiting\n"), pkt_size);
			return 0;
		}
		err = GetLastError();
	}
	errstr = openconnect__win32_strerror(err);
	vpn_progress(vpninfo, PRG_ERR,
		     _("Failed to write to TAP device: %s\n"), errstr);
	free(errstr);
	return -1;
}

void os_shutdown_tun(struct openconnect_info *vpninfo)
{
	script_config_tun(vpninfo, "disconnect");

	if (vpninfo->wintun) {
		os_shutdown_wintun(vpninfo);
		return;
	}

	CloseHandle(vpninfo->tun_fh);
	vpninfo->tun_fh = NULL;
	CloseHandle(vpninfo->tun_rd_overlap.hEvent);
	vpninfo->tun_rd_overlap.hEvent = NULL;
}

int openconnect_setup_tun_fd(struct openconnect_info *vpninfo, intptr_t tun_fd)
{
	ULONG data;
	DWORD len;

	if (vpninfo->wintun)
		return setup_wintun_fd(vpninfo, tun_fd);

	/* Toggle media status so that network location awareness picks up all the configuration
	   that occurred and properly assigns the network so the user can adjust firewall
	   settings. */
	for (data = 0; data <= 1; data++) {
		if (!DeviceIoControl((HANDLE)tun_fd, TAP_IOCTL_SET_MEDIA_STATUS,
					&data, sizeof(data), &data, sizeof(data), &len, NULL)) {
			char *errstr = openconnect__win32_strerror(GetLastError());

			vpn_progress(vpninfo, PRG_ERR,
					_("Failed to set TAP media status: %s\n"), errstr);
			free(errstr);
			return -1;
		}
	}

	vpninfo->tun_fh = (HANDLE)tun_fd;
	vpninfo->tun_rd_overlap.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	monitor_read_fd(vpninfo, tun);

	return 0;
}

int openconnect_setup_tun_script(struct openconnect_info *vpninfo,
				 const char *tun_script)
{
	vpn_progress(vpninfo, PRG_ERR,
		     _("Spawning tunnel scripts is not yet supported on Windows\n"));
	return -1;
}

#endif /* __LIST_TAPS__ */
