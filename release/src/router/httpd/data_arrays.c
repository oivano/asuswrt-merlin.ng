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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <httpd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <dirent.h>

#include <typedefs.h>
#include <bcmutils.h>
#include <shutils.h>
#include <bcmnvram.h>
#include <bcmnvram_f.h>
#include <common.h>
#include <shared.h>
#include <rtstate.h>
#ifdef HND_ROUTER
#include "bcmwifi_rates.h"
#include "wlioctl_defs.h"
#endif

#include <wlioctl.h>
#include <wlutils.h>
#include <sys/sysinfo.h>
#include <sys/statvfs.h>
#include <linux/version.h>

#include "data_arrays.h"
#include "httpd.h"
#include "iptraffic.h"

#include <net/route.h>
#ifdef RTCONFIG_STRONGSWAN
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/time.h>
#endif

#ifdef RTCONFIG_BWDPI
#define __USE_GNU
#include "bwdpi_common.h"
#include <search.h>
#endif

#include <json.h>

#ifdef RTCONFIG_FRR
#include "frr_web.h"
#endif

int
ej_get_leases_array(int eid, webs_t wp, int argc, char_t **argv)
{
	FILE *fp;
	struct in_addr addr4;
	struct in6_addr addr6;
	char line[256];
	char *hwaddr, *ipaddr, *name, *next;
	unsigned int expires;
	int ret=0;

	killall("dnsmasq", SIGUSR2);
	sleep(1);

	if (!(fp = fopen("/var/lib/misc/dnsmasq.leases", "r")))
		return websWrite(wp, "leasearray = [];\n");

	ret += websWrite(wp, "leasearray= [");

	while ((next = fgets(line, sizeof(line), fp)) != NULL) {
		/* line should start with a numeric value */
		if (sscanf(next, "%u ", &expires) != 1)
			continue;

		strsep(&next, " ");
		hwaddr = strsep(&next, " ") ? : "";
		ipaddr = strsep(&next, " ") ? : "";
		name = strsep(&next, " ") ? : "";

		if (strlen(name) > 32) {
			strcpy(name + 29, "...");
			name[32] = '\0';
		}

		if (inet_pton(AF_INET6, ipaddr, &addr6) != 0) {
			/* skip ipv6 leases, they have no hwaddr, but client id */
			// hwaddr = next ? : "";
			continue;

		} else if (inet_pton(AF_INET, ipaddr, &addr4) == 0)
			continue;

		ret += websWrite(wp, "[\"%d\", \"%s\", \"%s\", \"%s\"],\n", expires, hwaddr, ipaddr, name);
	}
	ret += websWrite(wp, "[]];\n");
	fclose(fp);

	return ret;
}


#ifdef RTCONFIG_IPV6
#ifdef RTCONFIG_IGD2
int
ej_ipv6_pinhole_array(int eid, webs_t wp, int argc, char_t **argv)
{
	FILE *fp;
	char *ipt_argv[] = {"ip6tables", "-nxL", "UPNP", NULL};
	char line[256], tmp[256];
	char target[16], proto[16];
	char src[45];
	char dst[45];
	char *sport, *dport, *ptr, *val;
	int ret = 0;

	ret += websWrite(wp, "var pinholes = ");

        if (!(ipv6_enabled() && is_routing_enabled())) {
                ret += websWrite(wp, "[];\n");
                return ret;
        }

	_eval(ipt_argv, ">/tmp/pinhole.log", 10, NULL);

	fp = fopen("/tmp/pinhole.log", "r");
	if (fp == NULL) {
		ret += websWrite(wp, "[];\n");
		return ret;
	}

	ret += websWrite(wp, "[");

	while (fgets(line, sizeof(line), fp) != NULL)
	{
		tmp[0] = '\0';
		if (sscanf(line,
		    "%15s%*[ \t]"		// target
		    "%15s%*[ \t]"		// prot
		    "%44[^/]/%*d%*[ \t]"	// source
		    "%44[^/]/%*d%*[ \t]"	// destination
		    "%255[^\n]",		// options
		    target, proto, src, dst, tmp) < 5) continue;

		if (strcmp(target, "ACCEPT")) continue;

		/* uppercase proto */
		for (ptr = proto; *ptr; ptr++)
			*ptr = toupper(*ptr);

		/* parse source */
		if (strcmp(src, "::") == 0)
			strcpy(src, "ALL");

		/* parse destination */
		if (strcmp(dst, "::") == 0)
			strcpy(dst, "ALL");

		/* parse options */
		sport = dport = "";
		ptr = tmp;
		while ((val = strsep(&ptr, " ")) != NULL) {
			if (strncmp(val, "dpt:", 4) == 0)
				dport = val + 4;
			if (strncmp(val, "spt:", 4) == 0)
				sport = val + 4;
			else if (strncmp(val, "dpts:", 5) == 0)
				dport = val + 5;
			else if (strncmp(val, "spts:", 5) == 0)
				sport = val + 5;
		}

		ret += websWrite(wp,
			"[\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"],\n",
			src, sport, dst, dport, proto);
	}
	ret += websWrite(wp, "[]];\n");

	fclose(fp);
	unlink("/tmp/pinhole.log");

	return ret;

}
#endif
#endif


int
ej_get_upnp_array(int eid, webs_t wp, int argc, char_t **argv)
{
	FILE *fp;
	char proto[4], eport[6], iaddr[sizeof("255.255.255.255")], iport[6], timestamp[15], desc[200], desc2[256];
	int ret=0;
	char line[256];

	killall("miniupnpd", SIGUSR2);
        sleep(1);

	ret += websWrite(wp, "var upnparray = [");

	fp = fopen("/tmp/upnp.leases", "r");
	if (fp == NULL) {
		ret += websWrite(wp, "[]];\n");
		return ret;
	}

	while (fgets(line, sizeof(line), fp) != NULL)
	{
		desc[0] = '\0';

		if (sscanf(line,
			"%3[^:]:"
			"%5[^:]:"
			"%15[^:]:"
			"%5[^:]:"
			"%14[^:]:"
			"%199[^\n]",
			proto, eport, iaddr, iport, timestamp, desc) < 5) continue;

		if (str_escape_quotes(desc2, desc, sizeof(desc2)) == 0)
			strlcpy(desc2, desc, sizeof(desc2));

		ret += websWrite(wp, "[\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"],\n",
			proto, eport, iaddr, iport, timestamp, desc2);
	}

	fclose(fp);

	ret += websWrite(wp, "[]];\n");
	return ret;

}

int
ej_get_vserver_array(int eid, webs_t wp, int argc, char_t **argv)
{
	FILE *fp;
	char *nat_argv[] = {"iptables", "-t", "nat", "-nxL", NULL};
	char line[256], tmp[256];
	char target[16], proto[16];
	char src[19];
	char dst[19];
	char *range, *host, *port, *ptr, *val;
	int ret = 0;
	char chain[16];

	/* dump nat table including VSERVER and VUPNP chains */
	_eval(nat_argv, ">/tmp/vserver.log", 10, NULL);

	ret += websWrite(wp, "var vserverarray = [");

	fp = fopen("/tmp/vserver.log", "r");

	if (fp == NULL) {
                ret += websWrite(wp, "[]];\n");
                return ret;
        }

	while (fgets(line, sizeof(line), fp) != NULL)
	{

		// If it's a chain definition then store it for following rules
		if (!strncmp(line, "Chain",  5)){
			if (sscanf(line, "%*s%*[ \t]%15s%*[ \t]%*s", chain) == 1)
				continue;
		}
		tmp[0] = '\0';
		if (sscanf(line,
		    "%15s%*[ \t]"		// target
		    "%15s%*[ \t]"		// prot
		    "%*s%*[ \t]"		// opt
		    "%18s%*[ \t]"		// source
		    "%15[^/]/%*d%*[ \t]"	// destination
		    "%255[^\n]",		// options
		    target, proto, src, dst, tmp) < 5) continue;

		/* TODO: add port trigger, portmap, etc support */
		if (strcmp(target, "DNAT") != 0)
			continue;

		/* Don't list DNS redirections  from DNSFilter or UPNP */
		if ((strcmp(chain, "DNSFILTER") == 0) || (strcmp(chain, "VUPNP") == 0) || (strcmp(chain, "PUPNP") == 0) || (strncmp(chain, "DNSVPN", 6) == 0))
			continue;

		/* uppercase proto */
		for (ptr = proto; *ptr; ptr++)
			*ptr = toupper(*ptr);
		/* parse source */
		if (strcmp(src, "0.0.0.0/0") == 0)
			strcpy(src, "ALL");
		/* parse destination */
		if (strcmp(dst, "0.0.0.0/0") == 0)
			strcpy(dst, "ALL");

		/* parse options */
		port = host = range = "";
		ptr = tmp;
		while ((val = strsep(&ptr, " ")) != NULL) {
			if (strncmp(val, "dpt:", 4) == 0)
				range = val + 4;
			else if (strncmp(val, "dpts:", 5) == 0)
				range = val + 5;
			else if (strncmp(val, "to:", 3) == 0) {
				port = host = val + 3;
				strsep(&port, ":");
			}
		}

		ret += websWrite(wp, "["
			"\"%s\", "
			"\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"],\n",
			src,
			dst, proto, range, host, port ? : range, chain);
	}
	fclose(fp);
	unlink("/tmp/vserver.log");

        ret += websWrite(wp, "[]];\n");
	return ret;
}



static int ipv4_route_table_array(webs_t wp)
{
	FILE *fp;
	char tmp[100], prefix[] = "wanXXXXXXXXXX_";
	char buf[256], *dev, *sflags, *str;
	struct in_addr dest, gateway, mask;
	int flags, ref, use, metric;
	int unit, ret = 0;

	fp = fopen("/proc/net/route", "r");
	if (fp == NULL) {
		ret += websWrite(wp, "[]];\n");
		return ret;
	}

	while ((str = fgets(buf, sizeof(buf), fp)) != NULL) {
		dev = strsep(&str, " \t");
		if (!str || dev == str)
			continue;
		if (sscanf(str, "%x%x%x%d%u%d%x", &dest.s_addr, &gateway.s_addr,
			&flags, &ref, &use, &metric, &mask.s_addr) != 7)
			continue;

		/* Parse flags, reuse buf */
		sflags = str;
		if (flags & RTF_UP)
			*str++ = 'U';
		if (flags & RTF_GATEWAY)
			*str++ = 'G';
		if (flags & RTF_HOST)
			*str++ = 'H';
		*str++ = '\0';

		/* Skip interfaces here */
		if (strcmp(dev, "lo") == 0)
			continue;

		/* Replace known interfaces with LAN/WAN/MAN */
		if (nvram_match("lan_ifname", dev)) /* br0, wl0, etc */
			dev = "LAN";
		else {
			/* Tricky, it's better to move wan_ifunit/wanx_ifunit to shared instead */
			for (unit = WAN_UNIT_FIRST; unit < WAN_UNIT_MAX; unit++) {
				snprintf(prefix, sizeof(prefix), "wan%d_", unit);
				if (nvram_match(strcat_r(prefix, "pppoe_ifname", tmp), dev)) {
					dev = "WAN";
					break;
				}
				if (nvram_match(strcat_r(prefix, "ifname", tmp), dev)) {
					char *wan_proto = nvram_safe_get(strcat_r(prefix, "proto", tmp));
					dev = (strcmp(wan_proto, "dhcp") == 0 ||
						strcmp(wan_proto, "static") == 0 ) ? "WAN" : "MAN";
					break;
				}
			}
		}

		ret += websWrite(wp, "[\"%s\",",  dest.s_addr == INADDR_ANY ? "default" : inet_ntoa(dest));
		ret += websWrite(wp, "\"%s\", ", gateway.s_addr == INADDR_ANY ? "*" : inet_ntoa(gateway));
		ret += websWrite(wp, "\"%s\", \"%s\", \"%d\", \"%d\", \"%d\", \"%s\"],\n",
                       inet_ntoa(mask), sflags, metric, ref, use, dev);

	}
	fclose(fp);

	return ret;
}


#ifndef RTF_PREFIX_RT
#define RTF_PREFIX_RT  0x00080000
#endif
#ifndef RTF_EXPIRES
#define RTF_EXPIRES    0x00400000
#endif
#ifndef RTF_ROUTEINFO
#define RTF_ROUTEINFO  0x00800000
#endif

const static struct {
       unsigned int flag;
       char name;
} route_flags[] = {
       { RTF_UP,        'U' },
       { RTF_GATEWAY,   'G' },
       { RTF_HOST,      'H' },
//     { RTF_DYNAMIC,   'N' },
//     { RTF_MODIFIED,  'M' },
       { RTF_REJECT,    'R' },
#ifdef RTCONFIG_IPV6
       { RTF_DEFAULT,   'D' },
       { RTF_ADDRCONF,  'A' },
       { RTF_PREFIX_RT, 'P' },
       { RTF_EXPIRES,   'E' },
       { RTF_ROUTEINFO, 'I' },
//     { RTF_CACHE,     'C' },
//     { RTF_LOCAL,     'L' },
#endif
};


#ifdef RTCONFIG_IPV6
static
int INET6_displayroutes_array(webs_t wp)
{
	FILE *fp;
	char buf[256], *str, *dev, *sflags;
	char sdest[INET6_ADDRSTRLEN], snexthop[INET6_ADDRSTRLEN], ifname[16];
	struct in6_addr dest, nexthop;
	int flags, ref, use, metric, prefix;
	int i, pass, maxlen, routing, ret = 0;

	fp = fopen("/proc/net/ipv6_route", "r");
	if (fp == NULL)
		return 0;

	pass = maxlen = 0;
	routing = is_routing_enabled();
again:
	while ((str = fgets(buf, sizeof(buf), fp)) != NULL) {
		if (sscanf(str, "%32s%x%*s%*x%32s%x%x%x%x%15s",
			   sdest, &prefix, snexthop,
			   &metric, &ref, &use, &flags, ifname) != 8)
			continue;

		/* Skip down and cache routes */
		if ((flags & (RTF_UP | RTF_CACHE)) != RTF_UP)
			continue;
		/* Skip interfaces here */
		if (strcmp(ifname, "lo") == 0)
			continue;

		/* Parse dst, reuse buf */
		if (inet_raddr6_pton(sdest, &dest, str) < 1)
			break;
		if (prefix || !IN6_IS_ADDR_UNSPECIFIED(&dest)) {
			inet_ntop(AF_INET6, &dest, sdest, sizeof(sdest));
			if (prefix != 128) {
				i = strlen(sdest);
				snprintf(sdest + i, sizeof(sdest) - i, "/%d", prefix);
			}
		} else
			snprintf(sdest, sizeof(sdest), "default");

		/* Parse nexthop, reuse buf */
		if (inet_raddr6_pton(snexthop, &nexthop, str) < 1)
			break;
		inet_ntop(AF_INET6, &nexthop, snexthop, sizeof(snexthop));

		/* Format addresses, reuse buf */
		i = snprintf(str, buf + sizeof(buf) - str, ((flags & RTF_NONEXTHOP) ||
			     IN6_IS_ADDR_UNSPECIFIED(&nexthop)) ? "%s" : "%s via %s",
			     sdest, snexthop);
		if (pass == 0) {
			if (maxlen < i)
				maxlen = i;
			continue;
		} else
			str += i + 1;

		/* Parse flags, reuse buf */
		sflags = str;
		for (i = 0; i < ARRAY_SIZE(route_flags); i++) {
			if (flags & route_flags[i].flag)
				*str++ = route_flags[i].name;
		}
		*str++ = '\0';

		/* Replace known interfaces with LAN/WAN/MAN */
		dev = NULL;
		if (nvram_match("lan_ifname", ifname)) /* br0, wl0, etc */
			dev = "LAN";
		else if (routing && strcmp(get_wan6face(), ifname) == 0)
			dev = "WAN";

		/* Print the info. */
		ret += websWrite(wp, "[\"%3s\", \"%s\", \"%s\", \"%d\", \"%d\", \"%d\", \"%s\", \"%s\"],\n",
		                      sdest, ((flags & RTF_NONEXTHOP) || IN6_IS_ADDR_UNSPECIFIED(&nexthop)) ? "" : snexthop,
                                      sflags, metric, ref, use, dev ? : "", ifname);

	}
	if (pass++ == 0) {
		if (maxlen > 0)
			rewind(fp);
		goto again;
	}
	fclose(fp);

	return ret;
}
#endif


#ifdef RTCONFIG_STRONGSWAN
static int route_status_wait(int fd, const struct timeval *started)
{
	struct timeval now, timeout;
	fd_set readers;
	long remaining;
	int result;

	do {
		gettimeofday(&now, NULL);
		remaining = 1000000 - (now.tv_sec - started->tv_sec) * 1000000
			- (now.tv_usec - started->tv_usec);
		if (remaining <= 0 || remaining > 1000000 || fd >= FD_SETSIZE)
			return 0;
		timeout.tv_sec = remaining / 1000000;
		timeout.tv_usec = remaining % 1000000;
		FD_ZERO(&readers);
		FD_SET(fd, &readers);
		result = select(fd + 1, &readers, NULL, NULL, &timeout);
	} while (result < 0 && errno == EINTR);
	return result > 0;
}

static int ipsec_client_child_installed(char *status)
{
	char key[40], profile[4096], *field, *cursor, *name, *enabled;
	char *line, *next, *child;
	int unit, index;

	for (unit = 1; unit <= 5; unit++) {
		snprintf(key, sizeof(key), "ipsec_profile_client_%d", unit);
		if (strlen(nvram_safe_get(key)) >= sizeof(profile))
			continue;
		strlcpy(profile, nvram_safe_get(key), sizeof(profile));
		cursor = profile;
		name = enabled = NULL;
		for (index = 0; (field = strsep(&cursor, ">")) != NULL; index++) {
			if (index == 1)
				name = field;
			if (index == 37)
				enabled = field;
		}
		if (!name || !*name || !enabled || strcmp(enabled, "1"))
			continue;
		for (line = status; *line; line = next) {
			next = strchr(line, '\n');
			if (!next)
				next = line + strlen(line);
			else
				next++;
			while (line < next && isspace((unsigned char)*line))
				line++;
			if (strncmp(line, name, strlen(name)))
				continue;
			child = line + strlen(name);
			if (*child != '{')
				continue;
			while (++child < next && isdigit((unsigned char)*child))
				;
			if (next - child >= 14 && !strncmp(child, "}:  INSTALLED,", 14))
				return 1;
		}
	}
	return 0;
}

static int ipsec_route_client_active(void)
{
	int pipes[2], nullfd, child_status, complete = 0;
	pid_t child;
	ssize_t count;
	size_t used = 0;
	char *status;
	struct timeval started;
	sigset_t blocked, previous;

	if (!nvram_match("ipsec_client_enable", "1") || !pids("charon"))
		return 0;
	status = malloc(65536);
	if (!status)
		return 0;
	if (pipe(pipes) < 0) {
		free(status);
		return 0;
	}
	gettimeofday(&started, NULL);
	sigemptyset(&blocked);
	sigaddset(&blocked, SIGCHLD);
	sigprocmask(SIG_BLOCK, &blocked, &previous);
	child = fork();
	if (child == 0) {
		sigprocmask(SIG_SETMASK, &previous, NULL);
		close(pipes[0]);
		dup2(pipes[1], STDOUT_FILENO);
		close(pipes[1]);
		nullfd = open("/dev/null", O_RDWR);
		if (nullfd >= 0) {
			dup2(nullfd, STDIN_FILENO);
			dup2(nullfd, STDERR_FILENO);
			if (nullfd > STDERR_FILENO)
				close(nullfd);
		}
		execl("/usr/lib/ipsec/stroke", "stroke", "status", (char *)NULL);
		_exit(127);
	}
	close(pipes[1]);
	if (child > 0) {
		while (used < 65535 && route_status_wait(pipes[0], &started)) {
			count = read(pipes[0], status + used, 65535 - used);
			if (count == 0) {
				complete = 1;
				break;
			}
			if (count < 0) {
				if (errno == EINTR)
					continue;
				break;
			}
			used += count;
		}
		if (waitpid(child, &child_status, WNOHANG) == 0) {
			kill(child, SIGKILL);
			waitpid(child, &child_status, WNOHANG);
		}
	}
	close(pipes[0]);
	sigprocmask(SIG_SETMASK, &previous, NULL);
	status[used] = '\0';
	complete = complete && ipsec_client_child_installed(status);
	free(status);
	return complete;
}

/* Same LAN/WAN/MAN labels as ipv4_route_table_array() and INET6_displayroutes_array() */
static const char *ipsec_route_dev_label(int family, const char *ifname)
{
	char tmp[100], prefix[] = "wanXXXXXXXXXX_";
	int unit;

	if (!*ifname)
		return "";
	if (nvram_match("lan_ifname", ifname))
		return "LAN";
	if (family == AF_INET) {
		for (unit = WAN_UNIT_FIRST; unit < WAN_UNIT_MAX; unit++) {
			snprintf(prefix, sizeof(prefix), "wan%d_", unit);
			if (nvram_match(strcat_r(prefix, "pppoe_ifname", tmp), ifname))
				return "WAN";
			if (nvram_match(strcat_r(prefix, "ifname", tmp), ifname)) {
				char *wan_proto = nvram_safe_get(strcat_r(prefix, "proto", tmp));
				return (!strcmp(wan_proto, "dhcp") || !strcmp(wan_proto, "static")) ? "WAN" : "MAN";
			}
		}
		return ifname;
	}
#ifdef RTCONFIG_IPV6
	if (is_routing_enabled() && !strcmp(get_wan6face(), ifname))
		return "WAN";
#endif
	return "";
}

static int ipsec_route_dump(int family, struct json_object *routes)
{
	struct {
		struct nlmsghdr header;
		struct rtmsg route;
	} request;
	struct sockaddr_nl address;
	struct timeval started;
	struct nlmsghdr *header;
	struct rtmsg *route;
	struct rtattr *attr;
	struct json_object *entry;
	union {
		struct nlmsghdr alignment;
		char data[16384];
	} buffer;
	char destination[INET6_ADDRSTRLEN], gateway[INET6_ADDRSTRLEN];
	char source[INET6_ADDRSTRLEN], prefix[INET6_ADDRSTRLEN + 8], iface[IFNAMSIZ];
	unsigned int table, metric, interface;
	int fd, length, attrlen, remaining, complete = 0, bytes = 0;
	int addrlen = family == AF_INET ? 4 : 16;

	fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (fd < 0)
		return 0;
	memset(&address, 0, sizeof(address));
	address.nl_family = AF_NETLINK;
	memset(&request, 0, sizeof(request));
	request.header.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	request.header.nlmsg_type = RTM_GETROUTE;
	request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.header.nlmsg_seq = 1;
	request.route.rtm_family = family;
	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0 ||
	    sendto(fd, &request, request.header.nlmsg_len, 0,
		(struct sockaddr *)&address, sizeof(address)) < 0)
		goto finished;
	gettimeofday(&started, NULL);
	while (route_status_wait(fd, &started)) {
		length = recv(fd, buffer.data, sizeof(buffer.data), MSG_TRUNC);
		if (length <= 0 || length > sizeof(buffer.data) || (bytes += length) > 524288)
			break;
		remaining = length;
		for (header = (struct nlmsghdr *)buffer.data; NLMSG_OK(header, remaining);
		     header = NLMSG_NEXT(header, remaining)) {
			if (header->nlmsg_seq != 1)
				continue;
			if (header->nlmsg_type == NLMSG_DONE) {
				complete = 1;
				goto finished;
			}
			if (header->nlmsg_type == NLMSG_ERROR)
				goto finished;
			if (header->nlmsg_type != RTM_NEWROUTE ||
			    header->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg)))
				continue;
			route = NLMSG_DATA(header);
			if (route->rtm_family != family || route->rtm_dst_len > addrlen * 8)
				continue;
			table = route->rtm_table;
			metric = interface = 0;
			strlcpy(destination, family == AF_INET ? "0.0.0.0" : "::", sizeof(destination));
			gateway[0] = source[0] = iface[0] = '\0';
			attrlen = RTM_PAYLOAD(header);
			for (attr = RTM_RTA(route); RTA_OK(attr, attrlen); attr = RTA_NEXT(attr, attrlen)) {
				if (RTA_PAYLOAD(attr) == sizeof(unsigned int)) {
					if (attr->rta_type == RTA_TABLE)
						memcpy(&table, RTA_DATA(attr), sizeof(table));
					if (attr->rta_type == RTA_PRIORITY)
						memcpy(&metric, RTA_DATA(attr), sizeof(metric));
					if (attr->rta_type == RTA_OIF)
						memcpy(&interface, RTA_DATA(attr), sizeof(interface));
				}
				if (RTA_PAYLOAD(attr) != addrlen)
					continue;
				if (attr->rta_type == RTA_DST)
					inet_ntop(family, RTA_DATA(attr), destination, sizeof(destination));
				if (attr->rta_type == RTA_GATEWAY)
					inet_ntop(family, RTA_DATA(attr), gateway, sizeof(gateway));
				if (attr->rta_type == RTA_PREFSRC)
					inet_ntop(family, RTA_DATA(attr), source, sizeof(source));
			}
			if (table != 220 || attrlen)
				continue;
			if (interface)
				if_indextoname(interface, iface);
			snprintf(prefix, sizeof(prefix), "%s/%u", destination, route->rtm_dst_len);
			entry = json_object_new_object();
			json_object_object_add(entry, "prefix", json_object_new_string(prefix));
			json_object_object_add(entry, "nexthop", json_object_new_string(gateway));
			json_object_object_add(entry, "iface", json_object_new_string(iface));
			json_object_object_add(entry, "dev", json_object_new_string(ipsec_route_dev_label(family, iface)));
			json_object_object_add(entry, "source", json_object_new_string(source));
			json_object_object_add(entry, "metric", json_object_new_int64(metric));
			json_object_object_add(entry, "type", json_object_new_int(route->rtm_type));
			json_object_object_add(entry, "protocol", json_object_new_int(route->rtm_protocol));
			json_object_object_add(entry, "onlink", json_object_new_boolean(route->rtm_flags & RTNH_F_ONLINK));
			json_object_array_add(routes, entry);
		}
	}
finished:
	close(fd);
	return complete;
}
#endif

int
ej_get_route_array(int eid, webs_t wp, int argc, char_t **argv)
{
	int ret = 0;

	ret += websWrite(wp, "var routearray = [");
	ret += ipv4_route_table_array(wp);
	ret += websWrite(wp, "[]];\n");

	ret += websWrite(wp, "var routev6array = [");
#ifdef RTCONFIG_IPV6
	if (get_ipv6_service() != IPV6_DISABLED) {
		INET6_displayroutes_array(wp);
	}
#endif

	ret += websWrite(wp, "[]];\n");
	ret += websWrite(wp, "var ipsec_route_active = false; var ipsec_route_v4 = []; var ipsec_route_v6 = [];\n");
	ret += websWrite(wp, "var frr_ipsec_overlay_enabled = 0; var frr_ipsec_route_v4 = {}; var frr_ipsec_route_v6 = {};\n");
#ifdef RTCONFIG_STRONGSWAN
	if (ipsec_route_client_active()) {
		struct json_object *routes4 = json_object_new_array();
		struct json_object *routes6 = json_object_new_array();
		int valid = ipsec_route_dump(AF_INET, routes4);
#ifdef RTCONFIG_IPV6
		if (get_ipv6_service() != IPV6_DISABLED)
			valid = ipsec_route_dump(AF_INET6, routes6) && valid;
#endif
		if (valid) {
			ret += websWrite(wp, "ipsec_route_active = true; ipsec_route_v4 = %s; ipsec_route_v6 = %s;\n",
				json_object_to_json_string(routes4), json_object_to_json_string(routes6));
#ifdef RTCONFIG_FRR
			if (nvram_match("frr_enable", "1"))
				ret += frr_write_ipsec_route_origin(wp);
#endif
		}
		json_object_put(routes4);
		json_object_put(routes6);
	}
#endif
	return ret;
}

#ifdef RTCONFIG_IPV6
int
ej_lan_ipv6_network_array(int eid, webs_t wp, int argc, char_t **argv)
{
	FILE *fp;
	char buf[64+32+8192+1];
	char *hostname, *macaddr, ipaddrs[8192+1];
	char ipv6_dns_str[1024];
	char *wan_type, *wan_dns, *p;
	int service, i, ret = 0;

	ret += websWrite(wp, "var ipv6cfgarray = [");

	if (!(ipv6_enabled() && is_routing_enabled())) {
		ret += websWrite(wp, "[]];\n");
		ret += websWrite(wp, "var ipv6clientarray = [");
		ret += websWrite(wp, "[]];\n");
		return ret;
	}

	service = get_ipv6_service();
	switch (service) {
	case IPV6_NATIVE_DHCP:
		wan_type = "Native with DHCP-PD"; break;
	case IPV6_6TO4:
		wan_type = "Tunnel 6to4"; break;
	case IPV6_6IN4:
		wan_type = "Tunnel 6in4"; break;
	case IPV6_6RD:
		wan_type = "Tunnel 6rd"; break;
	case IPV6_MANUAL:
		wan_type = "Static"; break;
	default:
		wan_type = "Disabled"; break;
	}

	ret += websWrite(wp, "[\"IPv6 Connection Type\",\"%s\"],", wan_type);

	ret += websWrite(wp, "[\"WAN IPv6 Address\",\"%s\"],",
			 getifaddr((char *) get_wan6face(), AF_INET6, GIF_PREFIXLEN) ? : nvram_safe_get("ipv6_rtr_addr"));


	ret += websWrite(wp, "[\"WAN IPv6 Gateway\",\"%s\"],",
			 ipv6_gateway_address() ? : "");

	ret += websWrite(wp, "[\"LAN IPv6 Address\",\"%s\"],",
			 getifaddr(nvram_safe_get("lan_ifname"), AF_INET6, GIF_PREFIXLEN) ? : "");

	ret += websWrite(wp, "[\"LAN IPv6 Link-Local Address\",\"%s\"],",
			 getifaddr(nvram_safe_get("lan_ifname"), AF_INET6, GIF_LINKLOCAL | GIF_PREFIXLEN) ? : "");

	if (service == IPV6_NATIVE_DHCP) {
		ret += websWrite(wp, "[\"DHCP-PD\",\"%s\"],",
			 nvram_get_int("ipv6_dhcp_pd") ? "Enabled" : "Disabled");
	}

	ret += websWrite(wp, "[\"LAN IPv6 Prefix\",\"%s/%d\"],",
			 nvram_safe_get("ipv6_prefix"), nvram_get_int("ipv6_prefix_length"));

	if (service == IPV6_NATIVE_DHCP &&
	    nvram_get_int("ipv6_dnsenable")) {
		wan_dns = nvram_safe_get("ipv6_get_dns");
	} else {
		char nvname[sizeof("ipv6_dnsXXX")];
		char *next = ipv6_dns_str;

		ipv6_dns_str[0] = '\0';
		for (i = 1; i <= 3; i++) {
			snprintf(nvname, sizeof(nvname), "ipv6_dns%d", i);
			wan_dns = nvram_safe_get(nvname);
			if (*wan_dns)
				next += sprintf(next, *ipv6_dns_str ? " %s" : "%s", wan_dns);
		}
		wan_dns = ipv6_dns_str;
	}

	ret += websWrite(wp, "[\"DNS Address\",\"%s\"],", wan_dns);
	ret += websWrite(wp, "[]];\n");

	ret += websWrite(wp, "var ipv6clientarray = [");

	/* Refresh lease file to get actual expire time */
	killall("dnsmasq", SIGUSR2);
	usleep(100 * 1000);

	get_ipv6_client_info();
	get_ipv6_client_list();

	if ((fp = fopen(IPV6_CLIENT_LIST, "r")) == NULL) {
		_dprintf("can't open %s: %s", IPV6_CLIENT_LIST, strerror(errno));
		return ret;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *ptr = buf;

		ptr = strsep(&ptr, "\n");
		hostname = strsep(&ptr, " ");
		macaddr = strsep(&ptr, " ");
		if (!macaddr || *macaddr == '\0' ||
		    !ptr || *ptr == '\0')
			continue;

		if (strlen(hostname) > 32)
			sprintf(hostname + 29, "...");

		ipaddrs[0] = '\0';
		p = ipaddrs;
		while (ptr && *ptr) {
			char *next = strsep(&ptr, ",\n");
			if (next && *next)
				p += snprintf(p, sizeof(ipaddrs) + ipaddrs - p, "%s%s", *ipaddrs ? ", " : "", next);
		}

		ret += websWrite(wp, "[\"%s\", \"%s\", \"%s\"],",
				 hostname, macaddr, ipaddrs);
	}
	fclose(fp);

	ret += websWrite(wp, "[]];\n");
	return ret;
}

int
ej_lan_ipv6_clients_array(int eid, webs_t wp, int argc, char_t **argv)
{
	FILE *fp;
	char buf[64+32+8192+1];
	char addrbuf[64];
	char *hostname, *macaddr;
	int ret = 0, len;

	ret += websWrite(wp, "var ipv6clientarray = {};\n");

	if (!(ipv6_enabled() && is_routing_enabled()))
		return ret;

	/* Refresh lease file to get actual expire time */
	killall("dnsmasq", SIGUSR2);
	usleep(100 * 1000);

	get_ipv6_client_info();
	get_ipv6_client_list();

	if ((fp = fopen(IPV6_CLIENT_LIST, "r")) == NULL) {
		_dprintf("can't open %s: %s", IPV6_CLIENT_LIST, strerror(errno));
		return ret;
	}

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		char *ptr = buf;

		ptr = strsep(&ptr, "\n");
		hostname = strsep(&ptr, " ");
		macaddr = strsep(&ptr, " ");
		if (!macaddr || *macaddr == '\0' ||
		    !ptr || *ptr == '\0' ||
		    !strcmp(hostname, "*") ||
		    !strcmp(hostname, "<unknown>"))
			continue;

		if (strlen(hostname) > 32)
			sprintf(hostname + 29, "...");

		while (ptr && *ptr) {
			char *next = strsep(&ptr, ",\n");
			if (next && *next) {
				/* Workaround - TrendMicro truncates last two bytes, and we pad them with "00" to generate a valid IP  */
				strlcpy(addrbuf, next, sizeof(addrbuf));
				len = strlen(addrbuf);
				if (len > 2) {
					addrbuf[len-1] = '0';
					addrbuf[len-2] = '0';
				}
				ret += websWrite(wp, "ipv6clientarray[\"%s\"] = \"%s\";\n", addrbuf, hostname);
			}
		}
	}
	fclose(fp);

	return ret;
}
#endif


#ifdef RTCONFIG_BWDPI
int parseTcFilter(webs_t wp, const char *interface) {
	char command[256];
	char buffer[1024];
	int foundmark=-1, foundflowid=-1, lastmark=-1;
	FILE *fp;
	int ret;
	char *mark = NULL;
	char *flowid = NULL;
	int value, value2;

	ret = websWrite(wp, "var tcdata_filter_array = [];\n");

	if (nvram_get_int("qos_type") != 1 || nvram_get_int("qos_enable") == 0)
		return ret;

	snprintf(command, sizeof(command), "tc filter show dev %s", interface);

	if ((fp = popen(command, "r")) == NULL)
		return ret;

	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		flowid = strstr(buffer, "flowid ");
		if (flowid) {
			sscanf(flowid, "flowid 1:%d", &foundflowid);
			if (foundflowid < 10 || foundflowid > 20)
				foundflowid = -1;
				continue;
		}

		mark = strstr(buffer, "mark ");
		if (mark) {
			if (sscanf(mark, "mark %x %x", &value, &value2) != 2 || value2 != 0xc03f0000) {
				foundflowid = -1;
				continue;
			}
			foundmark = (value & 0x3F0000)/0xFFFF;
			if (foundmark == lastmark) {
				foundmark += 50;
			}
		}

		if (foundflowid != -1 && foundmark != -1) {
			ret += websWrite(wp, "tcdata_filter_array[%d] = %d;\n", foundmark,foundflowid);
			lastmark = foundmark;
			foundflowid = -1;
			foundmark = -1;
		}
	}

	pclose(fp);
	return ret;
}


int ej_tcfilter_array(int eid, webs_t wp, int argc, char_t **argv) {

	return parseTcFilter(wp, "br0");
}
#endif

int ej_tcclass_dump_array(int eid, webs_t wp, int argc, char_t **argv) {
	FILE *fp;
	int ret = 0;
	char tmp[64];
	int qos_type;
	char wan_ifname[16];

	strlcpy(wan_ifname, nvram_safe_get("wan_ifname"), sizeof(wan_ifname));
	if (*wan_ifname == '\0')
		strlcpy(wan_ifname, "eth0", sizeof(wan_ifname));

	qos_type = nvram_get_int("qos_type");

	if (nvram_get_int("qos_enable") == 0) {
		ret += websWrite(wp, "var tcdata_lan_array = [[]];\nvar tcdata_wan_array = [[]];\n");
		return ret;
	}

	if (qos_type == 0 || qos_type == 1 || qos_type == 3) {	// Traditional, Adaptive or Geforce Now
		system("tc -s class show dev br0 > /tmp/tcclass.txt");
		system("tc -s class show dev imq0 >> /tmp/tcclass.txt");

		ret += websWrite(wp, "var tcdata_lan_array = [\n");

		fp = fopen("/tmp/tcclass.txt","r");
		if (fp) {
			ret += tcclass_dump(fp, wp);
			fclose(fp);
		} else {
			ret += websWrite(wp, "[]];\n");
		}
		unlink("/tmp/tcclass.txt");

	}

	if (qos_type != 2) {	// Must not be BW Limiter
		snprintf(tmp, sizeof(tmp), "tc -s class show dev %s > /tmp/tcclass.txt", wan_ifname);
		system(tmp);

	        ret += websWrite(wp, "var tcdata_wan_array = [\n");

	        fp = fopen("/tmp/tcclass.txt","r");
	        if (fp) {
	                ret += tcclass_dump(fp, wp);
			fclose(fp);
		} else {
			ret += websWrite(wp, "[]];\n");
	        }
		unlink("/tmp/tcclass.txt");
	}

	return ret;
}


int tcclass_dump(FILE *fp, webs_t wp) {
	char buf[256], ratebps[16], ratepps[16];
	int tcclass = 0;
	int stage = 0;
	unsigned long long traffic;
	int ret = 0;
	const char *class_template;
	int qos_type = nvram_get_int("qos_type");

	if (qos_type == 0 || qos_type == 3) {	//Traditional and geforce now, have both 1:* and 2:*
		class_template = "class htb %*c:%d %*s";
	} else {
		class_template = "class htb 1:%d %*s";
	}

	while (fgets(buf, sizeof(buf) , fp)) {
		switch (stage) {
			case 0:	// class
				if (sscanf(buf, class_template, &tcclass) == 1) {
					// Skip roots 1:1 and 1:2, and skip 1:60 in tQoS since it's BCM's download class
					if ( (tcclass < 10) || ((qos_type == 0) && (tcclass == 60))) {
						continue;
					}
					ret += websWrite(wp, "[\"%d\",", tcclass);
					stage = 1;
				}
				break;
			case 1: // Total data
				if (sscanf(buf, " Sent %llu bytes %*d pkt %*s)", &traffic) == 1) {
					ret += websWrite(wp, " \"%llu\",", traffic);
					stage = 2;
				}
				break;
			case 2: // Rates
				if (sscanf(buf, " rate %15s %15s backlog %*s", ratebps, ratepps) == 2) {
					ret += websWrite(wp, " \"%s\", \"%s\"],\n", ratebps, ratepps);
					stage = 0;
				}
				break;
			default:
				break;
		}
	}
	ret += websWrite(wp, "[]];\n");
	return ret;
}

#if 0
void wo_iptbackup(char *url, webs_t wp)
{
	static const char *ifn = "/var/lib/misc/cstats-history.gz";
	struct stat st;
	time_t t;
	int i;

	if (stat(ifn, &st) == 0) {
		t = st.st_mtime;
		sleep(1);
	}
	else {
		t = 0;
	}
	killall("cstats", SIGHUP);
	for (i = 20; i > 0; --i) { // may take a long time for gzip to complete
		if ((stat(ifn, &st) == 0) && (st.st_mtime != t)) break;
		sleep(1);
	}
	if (i == 0) {
//		send_error(500, NULL, NULL);
		return;
	}
//	send_header(200, NULL, mime_binary, 0);
	do_f((char *)ifn, wp);
}
#endif

#if !defined(HND_ROUTER)
int ej_iptmon(int eid, webs_t wp, int argc, char **argv) {

	char comma;
	char sa[256];
	FILE *a;
	char *exclude;
	char *include;

	char ip[INET6_ADDRSTRLEN];

	int64_t tx, rx;

	exclude = nvram_safe_get("cstats_exclude");
	include = nvram_safe_get("cstats_include");

	websWrite(wp, "\n\niptmon={");
	comma = ' ';

	char wholenetstatsline = 1;

	if ((a = fopen("/proc/net/ipt_account/lan", "r")) == NULL) return 0;

	if (!wholenetstatsline)
		fgets(sa, sizeof(sa), a); // network

	while (fgets(sa, sizeof(sa), a)) {
		if(sscanf(sa, 
			"ip = %s bytes_src = %llu %*u %*u %*u %*u packets_src = %*u %*u %*u %*u %*u bytes_dst = %llu %*u %*u %*u %*u packets_dst = %*u %*u %*u %*u %*u time = %*u",
			ip, &tx, &rx) != 3 ) continue;
		if (find_word(exclude, ip)) {
			wholenetstatsline = 0;
			continue;
		}

		if (((find_word(include, ip)) || (wholenetstatsline == 1)) || ((nvram_get_int("cstats_all")) && ((rx > 0) || (tx > 0)) )) {
//		if ((find_word(include, ip)) || (wholenetstatsline == 1)) {
//		if ((tx > 0) || (rx > 0) || (wholenetstatsline == 1)) {
//		if ((tx > 0) || (rx > 0)) {
			websWrite(wp,"%c'%s':{rx:0x%llx,tx:0x%llx}", comma, ip, rx, tx);
			comma = ',';
		}
		wholenetstatsline = 0;
	}
	fclose(a);
	websWrite(wp,"};\n");

	return 0;
}

int ej_ipt_bandwidth(int eid, webs_t wp, int argc, char **argv)
{
	char *name;
	int sig;

	if ((nvram_get_int("cstats_enable") == 1) && (argc == 1)) {
		if (strcmp(argv[0], "speed") == 0) {
			sig = SIGUSR1;
			name = "/var/spool/cstats-speed.js";
		}
		else {
			sig = SIGUSR2;
			name = "/var/spool/cstats-history.js";
		}
		unlink(name);
		killall("cstats", sig);
		f_wait_exists(name, 5);
		do_f(name, wp);
		unlink(name);
	}
	return 0;
}

int ej_iptraffic(int eid, webs_t wp, int argc, char **argv) {
	char comma;
	char sa[256];
	FILE *a;
	char ip[INET_ADDRSTRLEN];

	char *exclude;

	int64_t tx_bytes, rx_bytes;
	unsigned long tp_tcp, rp_tcp;
	unsigned long tp_udp, rp_udp;
	unsigned long tp_icmp, rp_icmp;
	unsigned int ct_tcp, ct_udp;

	exclude = nvram_safe_get("cstats_exclude");

	Node tmp;
	Node *ptr;

	iptraffic_conntrack_init();

	if ((a = fopen("/proc/net/ipt_account/lan", "r")) == NULL) return 0;

        websWrite(wp, "\n\niptraffic=[");
        comma = ' ';

	fgets(sa, sizeof(sa), a); // network
	while (fgets(sa, sizeof(sa), a)) {
		if(sscanf(sa, 
			"ip = %s bytes_src = %llu %*u %*u %*u %*u packets_src = %*u %lu %lu %lu %*u bytes_dst = %llu %*u %*u %*u %*u packets_dst = %*u %lu %lu %lu %*u time = %*u",
			ip, &tx_bytes, &tp_tcp, &tp_udp, &tp_icmp, &rx_bytes, &rp_tcp, &rp_udp, &rp_icmp) != 9 ) continue;
		if (find_word(exclude, ip)) continue ;
		if ((tx_bytes > 0) || (rx_bytes > 0)){
			strncpy(tmp.ipaddr, ip, INET_ADDRSTRLEN);
			ptr = TREE_FIND(&tree, _Node, linkage, &tmp);
			if (!ptr) {
				ct_tcp = 0;
				ct_udp = 0;
			} else {
				ct_tcp = ptr->tcp_conn;
				ct_udp = ptr->udp_conn;
			}
			websWrite(wp, "%c['%s', %llu, %llu, %lu, %lu, %lu, %lu, %lu, %lu, %u, %u]", 
						comma, ip, rx_bytes, tx_bytes, rp_tcp, tp_tcp, rp_udp, tp_udp, rp_icmp, tp_icmp, ct_tcp, ct_udp);
			comma = ',';
		}
	}
	fclose(a);
	websWrite(wp, "];\n");

	TREE_FORWARD_APPLY(&tree, _Node, linkage, Node_housekeeping, NULL);
	TREE_INIT(&tree, Node_compare);

	return 0;
}

void iptraffic_conntrack_init() {
	unsigned int a_time, a_proto;
	char a_src[INET_ADDRSTRLEN];
	char a_dst[INET_ADDRSTRLEN];
	char b_src[INET_ADDRSTRLEN];
	char b_dst[INET_ADDRSTRLEN];

	char sa[256];
	char sb[256];
	FILE *a;
	char *p;
	int x;

	Node tmp;
	Node *ptr;

	unsigned long rip;
	unsigned long lan;
	unsigned long mask;

	if (strcmp(nvram_safe_get("lan_ifname"), "") != 0) {
		rip = inet_addr(nvram_safe_get("lan_ipaddr"));
		mask = inet_addr(nvram_safe_get("lan_netmask"));
		lan = rip & mask;
//		_dprintf("rip[%d]=%lu\n", br, rip[br]);
//		_dprintf("mask[%d]=%lu\n", br, mask[br]);
//		_dprintf("lan[%d]=%lu\n", br, lan[br]);
	} else {
		mask = 0;
		rip = 0;
		lan = 0;
	}

	const char conntrack[] = "/proc/net/ip_conntrack";

	if ((a = fopen(conntrack, "r")) == NULL) return;

//	ctvbuf(a);	// if possible, read in one go

	while (fgets(sa, sizeof(sa), a)) {
		if (sscanf(sa, "%*s %u %u", &a_proto, &a_time) != 2) continue;

		if ((a_proto != 6) && (a_proto != 17)) continue;

		if ((p = strstr(sa, "src=")) == NULL) continue;
		if (sscanf(p, "src=%s dst=%s %n", a_src, a_dst, &x) != 2) continue;
		p += x;

		if ((p = strstr(p, "src=")) == NULL) continue;
		if (sscanf(p, "src=%s dst=%s", b_src, b_dst) != 2) continue;

		snprintf(sb, sizeof(sb), "%s %s %s %s", a_src, a_dst, b_src, b_dst);
		remove_dups(sb, sizeof(sb));

		char ipaddr[INET_ADDRSTRLEN], *next = NULL;

		foreach(ipaddr, sb, next) {
			if ((mask == 0) || ((inet_addr(ipaddr) & mask) != lan)) continue;

			strncpy(tmp.ipaddr, ipaddr, INET_ADDRSTRLEN);
			ptr = TREE_FIND(&tree, _Node, linkage, &tmp);

			if (!ptr) {
				_dprintf("%s: new ip: %s\n", __FUNCTION__, ipaddr);
				TREE_INSERT(&tree, _Node, linkage, Node_new(ipaddr));
				ptr = TREE_FIND(&tree, _Node, linkage, &tmp);
			}
			if (a_proto == 6) ++ptr->tcp_conn;
			if (a_proto == 17) ++ptr->udp_conn;
		}
	}
	fclose(a);
//	Tree_info();
}

void ctvbuf(FILE *f) {
	int n;
	struct sysinfo si;
//	meminfo_t mem;

#if 1
	const char *p;

	if ((p = nvram_get("ct_max")) != NULL) {
		n = atoi(p);
		if (n == 0) n = 2048;
		else if (n < 1024) n = 1024;
		else if (n > 10240) n = 10240;
	}
	else {
		n = 2048;
	}
#else
	char s[64];

	if (f_read_string("/proc/sys/net/ipv4/ip_conntrack_max", s, sizeof(s)) > 0) n = atoi(s);
		else n = 1024;
	if (n < 1024) n = 1024;
		else if (n > 10240) n = 10240;
#endif

	n *= 170;	// avg tested

//	get_memory(&mem);
//	if (mem.maxfreeram < (n + (64 * 1024))) n = mem.maxfreeram - (64 * 1024);

	sysinfo(&si);
	if (si.freeram < (n + (64 * 1024))) n = si.freeram - (64 * 1024);

//	cprintf("free: %dK, buffer: %dK\n", si.freeram / 1024, n / 1024);

	if (n > 4096) {
//		n =
		setvbuf(f, NULL, _IOFBF, n);
//		cprintf("setvbuf = %d\n", n);
	}
}

#endif


int ej_connlist_array(int eid, webs_t wp, int argc, char **argv) {
	FILE *fp;
	char line[100];
	int firstline = 1;
	char proto[6], address[16], dest[16], state[15], port1[6], port2[6];
	int ret = 0;

	ret += websWrite(wp, "var connarray = [");

	system("/usr/sbin/netstat-nat -r state -xn > /tmp/connect.log 2>&1");

	fp = fopen("/tmp/connect.log", "r");
	if (fp == NULL) {
		websWrite(wp, "[]];\n");
		return ret;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (firstline) {
			firstline = 0;
			continue;
		}
		if (!strncmp(line,"icmp",4)) {
			if (sscanf(line,
			    "%5s%*[ \t]"
			    "%15[0-9.]%*[ \t]"
			    "%15[0-9.]%*[ \t]",
			    proto, address, dest) != 3) continue;
			state[0] = '\0';
			port2[0] = '\0';
			port1[0] = '\0';
		} else {
			if (sscanf(line,
			    "%5s%*[ \t]"
			    "%15[0-9.]%*[:]"
			    "%5s%*[ \t]"
			    "%15[0-9.]%*[:]"
			    "%5s%*[ \t]"
			    "%14s%*[ \t]",
			    proto, address, port1, dest, port2, state) != 6) continue;
		}

		ret += websWrite(wp, "[\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"],\n",
		                      proto, address, port1, dest, port2, state);
	}
	fclose(fp);
	unlink("/tmp/connect.log");

	ret += websWrite(wp, "[]];\n");

	return ret;
}

#ifdef RTCONFIG_BWDPI
int ej_bwdpi_conntrack(int eid, webs_t wp, int argc, char **argv_) {
	char comma;
	char line[256];
	FILE *fp;
	static unsigned int count = 0;
	char src_ip[64], dst_ip[64], prot[4];
	int dport, sport;
	int ret;
	unsigned long mark;
	int id, cat;
	char desc[64], key[9];
	char ipversion;
	static struct hsearch_data *htab;
	ENTRY entry, *resultp;
	struct stat dbattrib;
	static unsigned long lastupd = 0;
	static char **alloctable;
	int allocptr = 0;

	if (stat(APPDB, &dbattrib))
		return websWrite(wp, "bwdpi_conntrack=[];");

	if ((lastupd) && (lastupd != dbattrib.st_ctime)) {
		// free all nodes (2 entries per item)
		while (allocptr < count * 2) {
			free(alloctable[allocptr++]);
		}
		hdestroy_r(htab);
		count = allocptr = lastupd = 0;
		free(alloctable);
	}

// Init hash table
	if (!lastupd) {
		lastupd = dbattrib.st_ctime;

		fp = fopen(APPDB, "r");
		if (!fp) return websWrite(wp, "bwdpi_conntrack=[];");

		while (fgets(line, sizeof(line), fp) != NULL) {
			count++;
		}

		alloctable = calloc(count * 2, sizeof(char *));
		htab = calloc(1, sizeof(struct hsearch_data));

		if ((!alloctable) || (!htab) || (!hcreate_r((unsigned int)count * 1.3, htab))) {
			fclose(fp);
			return websWrite(wp, "bwdpi_conntrack=[];");
		}

// Parse App database
		rewind(fp);
		while (fgets(line, sizeof(line), fp) != NULL) {
			if (sscanf(line,"%d,%d,%*d,%63[^\n]", &id, &cat, desc) == 3) {
				snprintf(key, sizeof(key), "%d-%d",id, cat);
				entry.key = strdup(key);
				entry.data = strdup(desc);
				if (entry.key && entry.data) {
					alloctable[allocptr++] = entry.key;
					alloctable[allocptr++] = entry.data;
					hsearch_r(entry, ENTER, &resultp, htab);
				}
			}
		}
		fclose(fp);
	}

// Parse tracked connections
	if ((fp = fopen("/proc/bw_cte_dump", "r")) == NULL)
		return websWrite(wp, "bwdpi_conntrack=[];");

	ret = websWrite(wp, "bwdpi_conntrack=[");
	comma = ' ';

	while (fgets(line, sizeof(line), fp)) {
		// ipv4 tcp src=192.168.10.156 dst=172.217.13.110 sport=8248 dport=443 index=8510 mark=3cd000f
		if (sscanf(line, "ipv%c %3s src=%63s dst=%63s sport=%d dport=%d index=%*d mark=%lx",
			          &ipversion, prot, src_ip, dst_ip, &sport, &dport, &mark) != 7 ) continue;

		id = (mark & 0x3F0000)/0xFFFF;
		cat = mark & 0xFFFF;

		if ((cat == 0) && (id == 0))
			strcpy(desc, "Untracked");
		else {

			snprintf(key, sizeof(key), "%d-%d", id, cat);
			entry.key = key;
			if (!hsearch_r(entry, FIND, &resultp, htab))
				sprintf(desc, "unknown (AppID=%d, Cat=%d)", id, cat);
			else
				strlcpy(desc, (char *)resultp->data, sizeof(desc));
		}

		if (ipversion == '6') {
			_fix_TM_ipv6(src_ip);
			_fix_TM_ipv6(dst_ip);
		}

		ret += websWrite(wp, "%c[\"%s\", \"%s\", \"%d\", \"%s\", \"%d\", \"%s\", \"%d\", \"%d\"]",
		                      comma, prot, src_ip, sport, dst_ip, dport, desc, cat, id);
		comma = ',';
	}
	fclose(fp);

	ret += websWrite(wp, "];\n");
	return ret;
}

// TM puts columns between every octet pairs
// Reformat that into quads rather than pairs
// Also TM is missing the last two octets, so pad
// with arbitrary "00" octets to get a valid IPv6
void _fix_TM_ipv6(char* str) {
	char *pr = str, *pw = str;
	int found=0;

	while (*pr) {
		*pw = *pr++;
		if (*pw == ':') {
			found++;
			if (found % 2)
				continue;
		}
		pw++;
	}
	*pw = '\0';

	if (strlen(str) == 37)
		strcat(str,"00");
}
#endif


int ej_get_custom_settings(int eid, webs_t wp, int argc, char **argv_) {

	struct json_object *settings_obj;
	int ret = 0;
	char line[3040];
	char name[30];
	char value[3000];
	FILE *fp;

	fp = fopen("/jffs/addons/custom_settings.txt", "r");
	if (fp == NULL) {
		ret += websWrite(wp," new Object()");
		return 0;
	}

	settings_obj = json_object_new_object();
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line,"%29s%*[ ]%2999s%*[ \n]",name, value) == 2) {
			json_object_object_add(settings_obj, name, json_object_new_string(value));
		}
	}
	fclose(fp);

	ret += websWrite(wp, "%s", json_object_to_json_string(settings_obj));

	json_object_put(settings_obj);
	return ret;
}


void write_custom_settings(char *jstring) {
	char line[3040];
	FILE *fp;
	struct json_object *settings_obj;

	settings_obj = json_tokener_parse(jstring);
	if (!settings_obj) return;

	fp = fopen("/jffs/addons/custom_settings.txt", "w");
	if (!fp) return;

	json_object_object_foreach(settings_obj, key, val) {
		snprintf(line, sizeof(line), "%s %s\n", key, json_object_get_string(val));
		fwrite(line, 1, strlen(line), fp);
	}
	fclose(fp);

	json_object_put(settings_obj);
}
