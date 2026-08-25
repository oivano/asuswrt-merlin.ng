/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2019 David Woodhouse
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

#include <stdint.h>
#include <stdio.h>

#define __OPENCONNECT_INTERNAL_H__

#define vpn_progress(v, d, ...) printf(__VA_ARGS__)
#define _(x) x

struct openconnect_info {
	char *ifname;
	wchar_t *ifname_w;
};

/* don't link linkopenconnect in this test, just for this function
 * it won't get loaded under wine when cross compiling anyway */
#define openconnect__win32_strerror(err) (strdup("(Actual error text not present in tests)"))

#define OPEN_TUN_SOFTFAIL 0
#define OPEN_TUN_HARDFAIL -1

#define __LIST_TAPS__

#include "../tun-win32.c"

static intptr_t print_tun(struct openconnect_info *vpninfo, int type, char *guid, wchar_t *wname)
{
	printf("Found %s device '%S' guid %s\n",
	       (type == ADAPTER_WINTUN) ? "Wintun" : "Tap", wname, guid);
	return 0;
}

int main(void)
{
	intptr_t ret;
	struct oc_adapter_info *list = NULL;
	struct openconnect_info empty_info = { NULL, NULL};

	list = get_adapter_list(NULL);

	if (!list)
		return 1;

	search_taps(&empty_info, list, print_tun);

	free_adapter_list(list);
	return 0;
}
