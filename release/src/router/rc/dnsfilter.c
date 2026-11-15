/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 *
 * Copyright 2014-2022 Eric Sauvageau.
 *
 */

#include <rc.h>
#include <net/ethernet.h>
#include <shared.h>
#ifdef RTCONFIG_DNSFILTER
#include "dnsfilter.h"

static int _get_table_size(const int server6)
{
	int i = 0;
	if(!server6)
	{
		while(server_table[i][0] != NULL)
			++i;
	}
#ifdef RTCONFIG_IPV6
	else
	{
		while(server6_table[i][0] != NULL)
			++i;
	}
#endif
	return i;
}

// Return 1 if selected mode supports DNS over TLS
int dnsfilter_support_dot(int mode)
{
	switch (mode){
		case DNSF_SRV_CUSTOM1:
		case DNSF_SRV_CUSTOM2:
		case DNSF_SRV_CUSTOM3:	// Custom 1, 2 and 3 - assume they might support it
		case DNSF_SRV_QUAD9:
		case DNSF_SRV_ROUTER:	// Router (in case end-user implements it locally)
		case DNSF_SRV_CLEANBROWSING_SECURITY:
		case DNSF_SRV_CLEANBROWSING_ADULT:
		case DNSF_SRV_CLEANBROWSING_FAMILY:
			return 1;
			break;
		default:
			return 0;
	}
}


int get_dns_filter(int proto, int mode, dnsf_srv_entry_t *dnsfsrv)
{
	int count = 0;

// Initialize
	if (mode >= _get_table_size(0)) mode = 0;

#ifdef RTCONFIG_IPV6
	if (proto == AF_INET6)
#ifdef HND_ROUTER
	{
		switch (mode) {
			case DNSF_SRV_CUSTOM1:
				strlcpy(dnsfsrv->server1, nvram_safe_get("dnsfilter_custom61"), 46);
				dnsfsrv->server2[0] = '\0';
				break;
			case DNSF_SRV_CUSTOM2:
				strlcpy(dnsfsrv->server1, nvram_safe_get("dnsfilter_custom62"), 46);
				dnsfsrv->server2[0] = '\0';
				break;
			case DNSF_SRV_CUSTOM3:
				strlcpy(dnsfsrv->server1, nvram_safe_get("dnsfilter_custom63"), 46);
				dnsfsrv->server2[0] = '\0';
				break;
#if defined(BCM4912)	// Causes kernel checksum errors on HND 5.02
			case DNSF_SRV_ROUTER:
				strlcpy(dnsfsrv->server1, nvram_safe_get("ipv6_rtr_addr"), 46);
				dnsfsrv->server2[0] = '\0';
				break;
#endif
			default:
				strlcpy(dnsfsrv->server1, server6_table[mode][0], 46);
				strlcpy(dnsfsrv->server2, server6_table[mode][1], 46);
		}
	} else
#else
	{
		strlcpy(dnsfsrv->server1, server6_table[mode][0], 46);
		strlcpy(dnsfsrv->server2, server6_table[mode][1], 46);
	} else
#endif
#endif	// RTCONFIG_IPV6
	{
		switch (mode) {
			case DNSF_SRV_CUSTOM1:
				strlcpy(dnsfsrv->server1, nvram_safe_get("dnsfilter_custom1"), 46);
				dnsfsrv->server2[0] = '\0';
				break;
			case DNSF_SRV_CUSTOM2:
				strlcpy(dnsfsrv->server1, nvram_safe_get("dnsfilter_custom2"), 46);
				dnsfsrv->server2[0] = '\0';
				break;
			case DNSF_SRV_CUSTOM3:
				strlcpy(dnsfsrv->server1, nvram_safe_get("dnsfilter_custom3"), 46);
				dnsfsrv->server2[0] = '\0';
				break;
			case DNSF_SRV_ROUTER:
				strlcpy(dnsfsrv->server1, nvram_safe_get("dhcp_dns1_x"), 46);
				if (!*dnsfsrv->server1)	// Empty, default to router's IP
					strlcpy(dnsfsrv->server1, nvram_safe_get("lan_ipaddr"), 46);
				dnsfsrv->server2[0] = '\0';
				break;
			default:
				strlcpy(dnsfsrv->server1, server_table[mode][0], 46);
				strlcpy(dnsfsrv->server2, server_table[mode][1], 46);
		}
	}

// Make sure it's valid
	if ( (*dnsfsrv->server1) &&
#ifdef RTCONFIG_IPV6
	     ( ((proto == AF_INET6) && !is_valid_ip6(dnsfsrv->server1)) ||
#endif
	       ((proto == AF_INET) && !is_valid_ip4(dnsfsrv->server1)))
	){
		logmessage("dnsdirector", "Invalid server1 for mode %d!", mode);
		dnsfsrv->server1[0] = '\0';
	}

        if ( (*dnsfsrv->server2) &&
#ifdef RTCONFIG_IPV6
             ( ((proto == AF_INET6) && !is_valid_ip6(dnsfsrv->server2)) ||
#endif
               ((proto == AF_INET) && !is_valid_ip4(dnsfsrv->server2)))
        ){
		logmessage("dnsdirector", "Invalid server2 for mode %d!", mode);
                dnsfsrv->server2[0] = '\0';
        }

// Report how many non-empty server we are returning
	if (*dnsfsrv->server1) count++;
	if (*dnsfsrv->server2) count++;
	return count;
}


void dnsfilter_settings(FILE *fp) {
	char *name, *mac, *mode;
	unsigned char ea[ETHER_ADDR_LEN];
	char *nv, *nvp, *rule;
	int dnsmode;
	dnsf_srv_entry_t dnsfsrv;

	if (nvram_get_int("dnsfilter_enable_x")) {
		/* Reroute all DNS requests from LAN */
		fprintf(fp, "-A PREROUTING -i br+ -p udp -m udp --dport 53 -j DNSFILTER\n"
			    "-A PREROUTING -i br+ -p tcp -m tcp --dport 53 -j DNSFILTER\n");

		/* Protection level per client */

#ifdef HND_ROUTER
		nv = nvp = malloc(255 * 6 + 1);
		if (nv) nvram_split_get("dnsfilter_rulelist", nv, 255 * 6 + 1, 5);
#else
		nv = nvp = strdup(nvram_safe_get("dnsfilter_rulelist"));
#endif
		while (nv && (rule = strsep(&nvp, "<")) != NULL) {
			if (vstrsep(rule, ">", &name, &mac, &mode) != 3)
				continue;
			if (!*mac || !*mode || !ether_atoe(mac, ea))
				continue;
			dnsmode = atoi(mode);
			if (dnsmode == DNSF_SRV_UNFILTERED) {
				fprintf(fp,
					"-A DNSFILTER -m mac --mac-source %s -j RETURN\n",
					mac);
			} else if (get_dns_filter(AF_INET, dnsmode, &dnsfsrv)) {
					fprintf(fp,"-A DNSFILTER -m mac --mac-source %s -j DNAT --to-destination %s\n",
						mac, dnsfsrv.server1);
			}
		}

		free(nv);

		/* Send other queries to the default server */
		dnsmode = nvram_get_int("dnsfilter_mode");
		if (dnsmode == DNSF_SRV_ROUTER) {
			fprintf(fp, "-A DNSFILTER -j REDIRECT\n");
		} else if ((dnsmode != DNSF_SRV_UNFILTERED) && get_dns_filter(AF_INET, dnsmode, &dnsfsrv)) {
			fprintf(fp, "-A DNSFILTER -j DNAT --to-destination %s\n", dnsfsrv.server1);
		}
	}
}

#ifdef RTCONFIG_IPV6

#ifdef HND_ROUTER
void dnsfilter6_settings_dnat(FILE *fp) {
	char *name, *mac, *mode;
	unsigned char ea[ETHER_ADDR_LEN];
	char *nv, *nvp, *rule;
	int dnsmode;
	dnsf_srv_entry_t dnsfsrv;

	if (nvram_get_int("dnsfilter_enable_x")) {
		/* Reroute all DNS requests from LAN */
		fprintf(fp, "-A PREROUTING -i br+ -p udp -m udp --dport 53 -j DNSFILTER\n"
			    "-A PREROUTING -i br+ -p tcp -m tcp --dport 53 -j DNSFILTER\n");

		/* Protection level per client */

		nv = nvp = malloc(255 * 6 + 1);
		if (nv) nvram_split_get("dnsfilter_rulelist", nv, 255 * 6 + 1, 5);

		while (nv && (rule = strsep(&nvp, "<")) != NULL) {
			if (vstrsep(rule, ">", &name, &mac, &mode) != 3)
				continue;
			if (!*mac || !*mode || !ether_atoe(mac, ea))
				continue;
			dnsmode = atoi(mode);
			if (dnsmode == DNSF_SRV_UNFILTERED) {
				fprintf(fp, "-A DNSFILTER -m mac --mac-source %s -j RETURN\n", mac);
			} else if (get_dns_filter(AF_INET6, dnsmode, &dnsfsrv)) {
					fprintf(fp,"-A DNSFILTER -m mac --mac-source %s -j DNAT --to-destination [%s]\n",
						mac, dnsfsrv.server1);
			}
		}

		free(nv);

		/* Default behaviour */
		dnsmode = nvram_get_int("dnsfilter_mode");
		if (dnsmode == DNSF_SRV_UNFILTERED) {
			return;
		} else if (get_dns_filter(AF_INET6, dnsmode, &dnsfsrv)) {	// Default server (if one exists)
			fprintf(fp, "-A DNSFILTER -j DNAT --to-destination [%s]\n", dnsfsrv.server1);
		}
	}
}
#endif

void dnsfilter6_settings_mangle(FILE *fp) {
	char *nv, *nvp, *rule;
	char *name, *mac, *mode;
	unsigned char ea[ETHER_ADDR_LEN];
	int dnsmode, count;
	dnsf_srv_entry_t dnsfsrv;

	fprintf(fp, "-A INPUT -i br+ -p udp -m udp --dport 53 -j DNSFILTERI\n"
		    "-A INPUT -i br+ -p tcp -m tcp --dport 53 -j DNSFILTERI\n"
		    "-A FORWARD -i br+ -p udp -m udp --dport 53 -j DNSFILTERF\n"
		    "-A FORWARD -i br+ -p tcp -m tcp --dport 53 -j DNSFILTERF\n");

#ifdef HND_ROUTER
	nv = nvp = malloc(255 * 6 + 1);
	if (nv) nvram_split_get("dnsfilter_rulelist", nv, 255 * 6 + 1, 5);
#else
	nv = nvp = strdup(nvram_safe_get("dnsfilter_rulelist"));
#endif
	while (nv && (rule = strsep(&nvp, "<")) != NULL) {
		if (vstrsep(rule, ">", &name, &mac, &mode) != 3)
			continue;
		dnsmode = atoi(mode);
		if (!*mac || !ether_atoe(mac, ea))
			continue;
		if (dnsmode == DNSF_SRV_UNFILTERED) {
			fprintf(fp, "-A DNSFILTERI -m mac --mac-source %s -j ACCEPT\n"
				    "-A DNSFILTERF -m mac --mac-source %s -j ACCEPT\n",
					mac, mac);
		} else {	// Filtered
			count = get_dns_filter(AF_INET6, dnsmode, &dnsfsrv);
			if (count) {
				fprintf(fp, "-A DNSFILTERF -m mac --mac-source %s -d %s -j ACCEPT\n", mac, dnsfsrv.server1);
			}
			if (count == 2) {
				fprintf(fp, "-A DNSFILTERF -m mac --mac-source %s -d %s -j ACCEPT\n", mac, dnsfsrv.server2);
			}
			// Reject other dnsfsrv for that client
			fprintf(fp, "-A DNSFILTERI -m mac --mac-source %s -j %s\n"
			            "-A DNSFILTERF -m mac --mac-source %s -j DROP\n",
			            mac, (dnsmode == DNSF_SRV_ROUTER ? "ACCEPT" : "DROP"), mac);
		}
	}
	free(nv);

	dnsmode = nvram_get_int("dnsfilter_mode");
	if (dnsmode != DNSF_SRV_UNFILTERED) {
		/* Allow other queries to the default server, and drop the rest */
		count = get_dns_filter(AF_INET6, dnsmode, &dnsfsrv);
		if (count) {
			fprintf(fp, "-A DNSFILTERI -d %s -j ACCEPT\n"
				    "-A DNSFILTERF -d %s -j ACCEPT\n",
				dnsfsrv.server1, dnsfsrv.server1);
		}
		if (count == 2) {
			fprintf(fp, "-A DNSFILTERI -d %s -j ACCEPT\n"
				    "-A DNSFILTERF -d %s -j ACCEPT\n",
				dnsfsrv.server2, dnsfsrv.server2);
		}
		fprintf(fp, "-A DNSFILTERI -j %s\n"
			    "-A DNSFILTERF -j DROP\n",
		            (dnsmode == DNSF_SRV_ROUTER ? "ACCEPT" : "DROP"));
	}
}

int dnsfilter_get_client_mode(const char *client_mac)
{
	unsigned char client_ea[ETHER_ADDR_LEN], rule_ea[ETHER_ADDR_LEN];
	char *name, *mac, *mode, *enable;
	char *nv, *nvp, *rule;
	int dnsmode, defmode, count;
#ifdef RTCONFIG_IPV6
	int count6;
#endif
	dnsf_srv_entry_t dnsfsrv;

	if (!nvram_get_int("dnsfilter_enable_x") || !client_mac || !ether_atoe(client_mac, client_ea))
		return -1;

#ifdef HND_ROUTER
	nv = nvp = malloc(255 * 6 + 1);
	if (nv) nvram_split_get("dnsfilter_rulelist", nv, 255 * 6 + 1, 5);
#else
	nv = nvp = strdup(nvram_safe_get("dnsfilter_rulelist"));
#endif
	if (!nv)
		return -1;

	defmode = nvram_get_int("dnsfilter_mode");
	dnsmode = -1;
	while ((rule = strsep(&nvp, "<")) != NULL) {
		name = mac = mode = enable = NULL;
		if (vstrsep(rule, ">", &name, &mac, &mode, &enable) < 3 || !mac || !mode ||
		    (enable && atoi(enable) == 0) || !*mode || strlen(mac) != 17 ||
		    strspn(mac, "0123456789abcdefABCDEF:") != 17 || !ether_atoe(mac, rule_ea) ||
		    memcmp(client_ea, rule_ea, ETHER_ADDR_LEN) != 0)
			continue;

		dnsmode = atoi(mode);
		if (dnsmode <= DNSF_SRV_UNFILTERED || dnsmode == defmode ||
		    dnsmode >= _get_table_size(0)) {
			dnsmode = -1;
			break;
		}
		count = get_dns_filter(AF_INET, dnsmode, &dnsfsrv);
#ifdef RTCONFIG_IPV6
		count6 = dnsmode < _get_table_size(1) ? get_dns_filter(AF_INET6, dnsmode, &dnsfsrv) : 0;
		if (count6 == 0 && dnsmode == DNSF_SRV_ROUTER)
			count6 = 1;
		if (count == 0 && count6 == 0)
#else
		if (count == 0)
#endif
			dnsmode = -1;
		break;
	}
	free(nv);
	return dnsmode;
}

int dnsfilter_static_lease_exists(const char *client_mac)
{
	char *nv, *nvp, *entry, *mac, *ip, *dns, *hostname;
	unsigned char client_ea[ETHER_ADDR_LEN], entry_ea[ETHER_ADDR_LEN];
	in_addr_t lan_ip, lan_mask, ip1;
	struct in_addr dns4;
#ifdef RTCONFIG_IPV6
	struct in6_addr dns6;
#endif
	int found = 0;

	if (!nvram_get_int("dhcp_static_x") || !client_mac || !ether_atoe(client_mac, client_ea))
		return 0;

	lan_ip = inet_network(nvram_safe_get("lan_ipaddr"));
	lan_mask = inet_network(nvram_safe_get("lan_netmask"));
	if (lan_ip == (in_addr_t)-1 || lan_mask == (in_addr_t)-1)
		return 0;

	nv = nvp = strdup(nvram_safe_get("dhcp_staticlist"));
	if (!nv)
		return 0;
	while ((entry = strsep(&nvp, "<")) != NULL) {
		mac = ip = dns = hostname = NULL;
		if (vstrsep(entry, ">", &mac, &ip, &dns, &hostname) < 2 || !mac || !ip ||
		    strlen(mac) != 17 || strspn(mac, "0123456789abcdefABCDEF:") != 17 ||
		    !ether_atoe(mac, entry_ea) || memcmp(client_ea, entry_ea, ETHER_ADDR_LEN) != 0)
			continue;

		if (dns && *dns &&
#ifdef RTCONFIG_IPV6
		    ((inet_pton(AF_INET6, dns, &dns6) > 0 && !IN6_IS_ADDR_UNSPECIFIED(&dns6) &&
		      !IN6_IS_ADDR_LOOPBACK(&dns6)) ||
#endif
		     (inet_pton(AF_INET, dns, &dns4) > 0 && dns4.s_addr != INADDR_ANY &&
		      dns4.s_addr != INADDR_LOOPBACK && dns4.s_addr != INADDR_BROADCAST)
#ifdef RTCONFIG_IPV6
		    )
#endif
		   ) {
			found = 1;
			break;
		}
		if (*ip && (ip1 = inet_network(ip)) != (in_addr_t)-1 &&
		    (ip1 & lan_mask) == (lan_ip & lan_mask)) {
			found = 1;
			break;
		}
	}
	free(nv);
	return found;
}

// Non-HND cannot DNAT to the configured server, so as a partial solution,
// we have dnsmasq provide it through dhcp instead.
void dnsfilter_setup_dnsmasq(FILE *fp) {

	unsigned char ea[ETHER_ADDR_LEN];
	char *name, *mac, *mode, *enable;
	char *nv, *nvp, *b;
	int count, dnsmode, defmode, table_size;
#ifdef RTCONFIG_IPV6
	int count6, table_size6;
#endif
	dnsf_srv_entry_t dnsfsrv;

	defmode = nvram_get_int("dnsfilter_mode");
	table_size = _get_table_size(0);
#ifdef RTCONFIG_IPV6
	table_size6 = _get_table_size(1);
#endif

	for (dnsmode = 1; dnsmode < table_size; dnsmode++) {
		if (dnsmode == defmode)
			continue;
		count = get_dns_filter(AF_INET, dnsmode, &dnsfsrv);
		if (count > 0) {
			fprintf(fp, "dhcp-option=tag:dnsf%u,6,%s", dnsmode, dnsfsrv.server1);
			if (count == 2)
				fprintf(fp, ",%s", dnsfsrv.server2);
			fprintf(fp, "\n");
		}

#ifdef RTCONFIG_IPV6
		count6 = dnsmode < table_size6 ? get_dns_filter(AF_INET6, dnsmode, &dnsfsrv) : 0;
		if (count6 == 0 && dnsmode == DNSF_SRV_ROUTER) {
			/* Workaround dynamic router address */
			strcpy(dnsfsrv.server1, "::");
			count6 = 1;
		}
		if (count6 > 0) {
			fprintf(fp, "dhcp-option=tag:dnsf%u,option6:23,[%s]", dnsmode, dnsfsrv.server1);
			if (count6 == 2)
				fprintf(fp, ",[%s]", dnsfsrv.server2);
			fprintf(fp, "\n");
		}
#endif
	}

	/* DNS server per client */
#ifdef HND_ROUTER
	nv = nvp = malloc(255 * 6 + 1);
	if (nv) nvram_split_get("dnsfilter_rulelist", nv, 255 * 6 + 1, 5);
#else
	nv = nvp = strdup(nvram_safe_get("dnsfilter_rulelist"));
#endif

	while (nv && (b = strsep(&nvp, "<")) != NULL) {
		if (vstrsep(b, ">", &name, &mac, &mode, &enable) < 3)
			continue;
		if (enable && atoi(enable) == 0)
			continue;
		if (!*mode || strlen(mac) != 17 || strspn(mac, "0123456789abcdefABCDEF:") != 17 ||
		    !ether_atoe(mac, ea))
			continue;
		dnsmode = atoi(mode);
		/* Skip unfiltered, default, and invalid levels */
		if (dnsmode <= DNSF_SRV_UNFILTERED || dnsmode == defmode || dnsmode >= table_size)
			continue;
#ifdef RTCONFIG_IPV6
		count6 = dnsmode < table_size6 ? get_dns_filter(AF_INET6, dnsmode, &dnsfsrv) : 0;
		if (count6 == 0 && dnsmode == DNSF_SRV_ROUTER)
			count6 = 1;
		if (get_dns_filter(AF_INET, dnsmode, &dnsfsrv) == 0 && count6 == 0)
			continue;
#else
		if (get_dns_filter(AF_INET, dnsmode, &dnsfsrv) == 0)
			continue;
#endif
		if (dnsfilter_static_lease_exists(mac))
			continue;
		fprintf(fp, "dhcp-host=%s,set:dnsf%u\n", mac, dnsmode);
	}
	free(nv);
}


// Block DOT if the configured server isn't known to support DOT, to prevent bypassing dnsfilter with DOT
void dnsfilter6_dot_rules(FILE *fp)
{
	char *name, *mac, *mode;
	unsigned char ea[ETHER_ADDR_LEN];
	char *nv, *nvp, *rule;
	int dnsmode;
	dnsf_srv_entry_t dnsfsrv;

	if (nvram_get_int("dnsfilter_enable_x") == 0) return;

	fprintf(fp, "-A FORWARD -i br+ -m tcp -p tcp --dport 853 -j DNSFILTER_DOT\n");

#ifdef HND_ROUTER
	nv = nvp = malloc(255 * 6 + 1);
	if (nv) nvram_split_get("dnsfilter_rulelist", nv, 255 * 6 + 1, 5);
#else
	nv = nvp = strdup(nvram_safe_get("dnsfilter_rulelist"));
#endif
	while (nv && (rule = strsep(&nvp, "<")) != NULL) {
		if (vstrsep(rule, ">", &name, &mac, &mode) != 3)
			continue;
		if (!*mac || !*mode || !ether_atoe(mac, ea))
			continue;
		dnsmode = atoi(mode);
		if (dnsmode == DNSF_SRV_UNFILTERED)
			fprintf(fp, "-A DNSFILTER_DOT -m mac --mac-source %s -j RETURN\n", mac);
		else if (dnsfilter_support_dot(dnsmode) && get_dns_filter(AF_INET6, dnsmode, &dnsfsrv) > 0 )	// Filter supports DOT
			fprintf(fp, "-A DNSFILTER_DOT -m mac --mac-source %s ! -d %s -j REJECT\n", mac, dnsfsrv.server1);
		else	// Reject DOT access
			fprintf(fp, "-A DNSFILTER_DOT -m mac --mac-source %s -j REJECT\n", mac);
	}
	free(nv);

	/* Global filtering */
	dnsmode = nvram_get_int("dnsfilter_mode");
	if (dnsmode != DNSF_SRV_UNFILTERED) {
		if (dnsfilter_support_dot(dnsmode) && get_dns_filter(AF_INET6, dnsmode, &dnsfsrv) > 0 )
			fprintf(fp, "-A DNSFILTER_DOT ! -d %s -j REJECT\n", dnsfsrv.server1);
		else
			fprintf(fp, "-A DNSFILTER_DOT -j REJECT\n");
	}
}
#endif	// RTCONFIG_IPV6


void dnsfilter_dot_rules(FILE *fp)
{
	char *name, *mac, *mode;
	unsigned char ea[ETHER_ADDR_LEN];
	char *nv, *nvp, *rule;
	int dnsmode;
	dnsf_srv_entry_t dnsfsrv;

	if (nvram_get_int("dnsfilter_enable_x") == 0) return;

	fprintf(fp, "-A FORWARD -i br+ -m tcp -p tcp --dport 853 -j DNSFILTER_DOT\n");

#ifdef HND_ROUTER
	nv = nvp = malloc(255 * 6 + 1);
	if (nv) nvram_split_get("dnsfilter_rulelist", nv, 255 * 6 + 1, 5);
#else
	nv = nvp = strdup(nvram_safe_get("dnsfilter_rulelist"));
#endif
	while (nv && (rule = strsep(&nvp, "<")) != NULL) {
		if (vstrsep(rule, ">", &name, &mac, &mode) != 3)
			continue;
		if (!*mac || !*mode || !ether_atoe(mac, ea))
			continue;
		dnsmode = atoi(mode);
		if (dnsmode == DNSF_SRV_UNFILTERED)
			fprintf(fp, "-A DNSFILTER_DOT -m mac --mac-source %s -j RETURN\n", mac);
		else if (dnsfilter_support_dot(dnsmode) && get_dns_filter(AF_INET, dnsmode, &dnsfsrv) > 0 )	// Filter supports DOT
			fprintf(fp, "-A DNSFILTER_DOT -m mac --mac-source %s ! -d %s -j REJECT\n", mac, dnsfsrv.server1);
		else	// Reject DOT access
			fprintf(fp, "-A DNSFILTER_DOT -m mac --mac-source %s -j REJECT\n", mac);
	}
	free(nv);

	/* Global filtering */
	dnsmode = nvram_get_int("dnsfilter_mode");
	if (dnsmode != DNSF_SRV_UNFILTERED) {
		if (dnsfilter_support_dot(dnsmode) && get_dns_filter(AF_INET, dnsmode, &dnsfsrv) > 0 )
			fprintf(fp, "-A DNSFILTER_DOT ! -d %s -j REJECT\n", dnsfsrv.server1);
		else
			fprintf(fp, "-A DNSFILTER_DOT -j REJECT\n");
	}
}

#endif	// RTCONFIG_DNSFILTER
