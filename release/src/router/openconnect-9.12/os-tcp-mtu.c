/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2022 Daniel Lenski <dlenski@gmail.com>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#if defined(__linux__)
/* For TCP_INFO */
# include <linux/tcp.h>
#endif

union sa_ip46 {
	struct sockaddr addr;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
};

static const char *ip46_ntop(union sa_ip46 *src, char *dst, socklen_t size) {
	return inet_ntop(src->addr.sa_family,
			 src->addr.sa_family == AF_INET6 ? (void *)&src->addr6.sin6_addr : (void *)&src->addr4.sin_addr,
			 dst, size);
}

int main(int argc, char **argv)
{
	int ret;
	socklen_t opt_size;
	char abuf[INET6_ADDRSTRLEN];

	union sa_ip46 asrc, adst;
	bzero(&asrc, sizeof(asrc));
	bzero(&adst, sizeof(adst));

	/* Parse parameters */
	if (argc < 3 || argc > 4) {
		fprintf(stderr,
			"usage: %s <destination> <port> [source_ip_addr]\n\n"
			"Creates a TCP connection to the specified hostname or IP address,\n"
			"and port, then introspects system information about path MTU and\n"
			"MSS.\n",
			argv[0]);
		exit(2);
	}
	const char *dst_ip = argv[1];
	int dst_port = atoi(argv[2]);
	const char *src_ip = argc > 3 ? argv[3] : NULL;

	/* Parse source address if specified, */
	if (src_ip) {
		if (inet_pton(AF_INET6, src_ip, &asrc.addr6.sin6_addr) > 0)
			asrc.addr.sa_family = AF_INET6;
		else if (inet_pton(AF_INET, src_ip, &asrc.addr4.sin_addr) > 0)
			asrc.addr.sa_family = AF_INET;
		else {
			fprintf(stderr, "Source is not a valid IPv6 or Legacy IP address: %s\n", src_ip);
			exit(2);
		}
	}

	/* Parse destination address or hostname */
	if (inet_pton(AF_INET, dst_ip, &adst.addr4.sin_addr) > 0)
		adst.addr.sa_family = AF_INET;
	else if (inet_pton(AF_INET6, dst_ip, &adst.addr6.sin6_addr) > 0)
		adst.addr.sa_family = AF_INET6;
	else {
		struct addrinfo *res, hints;
		bzero(&hints, sizeof(hints));
		hints.ai_family = asrc.addr.sa_family; /* will be zero ("any") if source address unknown */
		fprintf(stderr, "Resolving %s address for destination hostname %s ...\n",
			hints.ai_family == AF_INET6 ? "IPv6" : hints.ai_family == AF_INET ? "Legacy IP" : "IP",
			dst_ip);
		ret = getaddrinfo(dst_ip, "", &hints, &res);
		if (ret < 0) {
			fprintf(stderr, "Could not resolve %s address for %s\n",
				hints.ai_family == AF_INET6 ? "IPv6" : hints.ai_family == AF_INET ? "Legacy IP" : "IP",
				dst_ip);
			exit(2);
		}
		memcpy(&adst.addr, res->ai_addr, res->ai_addrlen);
		freeaddrinfo(res);

		ip46_ntop(&adst, abuf, sizeof(abuf));
		fprintf(stderr, "Resolved destination as %s address: %s\n",
			adst.addr.sa_family == AF_INET6 ? "IPv6" : "Legacy IP",
			abuf);
	}

	/* Sanity check matching address families */
	if (src_ip != 0 && asrc.addr.sa_family != adst.addr.sa_family) {
		fprintf(stderr, "Source and destination addresses must be same IP version.\n");
		exit(2);
	}
	int af = adst.addr.sa_family;
	const char *abufl = (af == AF_INET6 ? "[" : "");
	const char *abufr = (af == AF_INET6 ? "]" : "");
	int alen = (af == AF_INET6 ? sizeof(asrc.addr6) : sizeof(asrc.addr4));

	/* Create socket with DF ("do not fragment") bit on all packets */
	int sock = socket(af, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(1);
	}

#ifdef IP_PMTUDISC_DO
	int val = IP_PMTUDISC_DO;
	ret = setsockopt(sock, IPPROTO_TCP, IP_MTU_DISCOVER, &val, sizeof(val));
	if (ret < 0) {
		perror("setsockopt");
		exit(1);
	}
#endif

	/* Bind if source address was specified */
	if (src_ip) {
		ret = bind(sock, &asrc.addr, alen);
		if (ret < 0) {
			perror("bind");
			exit(1);
		}
		ip46_ntop(&asrc, abuf, sizeof(abuf));
		fprintf(stderr, "Bound to source address of %s%s%s\n",
			abufl, abuf, abufr);
	}

	/* Connect to destination address */
	adst.addr4.sin_port = htons(dst_port);
	ip46_ntop(&adst, abuf, sizeof(abuf));
	fprintf(stderr, "Trying to connect to %s%s%s:%d ...\n",
		abufl, abuf, abufr, ntohs(adst.addr4.sin_port));

	ret = connect(sock, (struct sockaddr *)&adst, alen);
	if (ret < 0) {
		perror("connect");
		exit(1);
	}

	/* Display resolved source info */
	socklen_t srclen = sizeof(asrc);
	ret = getsockname(sock, (struct sockaddr *)&asrc, &srclen);
	if (ret < 0) {
		perror("getsockname");
		exit(1);
	}
	ip46_ntop(&asrc, abuf, sizeof(abuf));
	fprintf(stderr, "Connected from source %s%s%s:%d\n",
		abufl, abuf, abufr, ntohs(asrc.addr4.sin_port));

	fprintf(stderr, "OS estimates of MTU/MSS for connected TCP socket:\n");

#if defined(__linux__)
	struct tcp_info ti;
	opt_size = sizeof(ti);
	ret = getsockopt(sock, IPPROTO_TCP, TCP_INFO, &ti, &opt_size);
	if (ret < 0) {
		perror("getsockopt TCP_INFO");
		exit(1);
	}

	fprintf(stderr,
		"  getsockopt TCP_INFO   -> rcv_mss %d, snd_mss %d, advmss %d, pmtu %d\n",
		ti.tcpi_rcv_mss, ti.tcpi_snd_mss, ti.tcpi_advmss, ti.tcpi_pmtu);

	int mtu;
	opt_size = sizeof(mtu);
	ret = getsockopt(sock, IPPROTO_IP, IP_MTU, &mtu, &opt_size);
	if (ret < 0)
		perror("getsockopt IP_MTU");
	else
		fprintf(stderr, "  getsockopt IP_MTU     -> mtu %d\n", mtu);
#endif

#ifdef TCP_MAXSEG
	int mss;
	opt_size = sizeof(mss);
	ret = getsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &mss, &opt_size);
	if (ret < 0)
		perror("getsockopt TCP_MAXSEG");
	else
		fprintf(stderr, "  getsockopt TCP_MAXSEG -> mss %d\n", mss);
#endif

#if !defined(__ANDROID__)
	/* XX: getifaddrs(3) exists in GNU/Linux, BSD, and macOS, but
	 * not natively in Android.
	 *
	 * TODO: use https://github.com/morristech/android-ifaddrs as
	 * as drop-in replacement.
	 */
	struct ifaddrs *ifaddr;
	ret = getifaddrs(&ifaddr);
	if (ret < 0) {
		perror("getifaddrs");
		exit(1);
	}

	/* ip46_ntop(&asrc, abuf, sizeof(abuf)); */
	/* fprintf(stderr, "src addr: %s, sa_family=%d\n", abuf, asrc.addr.sa_family); */
	struct ifreq ifr;
	bzero(&ifr, sizeof(ifr));
	for (struct ifaddrs *ii = ifaddr; ii; ii = ii->ifa_next) {
		if (ii->ifa_addr && ii->ifa_addr->sa_family == asrc.addr.sa_family) {
			/* ip46_ntop((void *)ii->ifa_addr, abuf, sizeof(abuf)); */
			/* fprintf(stderr, "ifa_addr: %s, ifa_addr->sa_family=%d\n", abuf, ii->ifa_addr->sa_family); */

			union sa_ip46 *a = (void *)ii->ifa_addr;
			if (asrc.addr.sa_family == AF_INET && a->addr4.sin_addr.s_addr == asrc.addr4.sin_addr.s_addr) {
				/* fprintf(stderr, "interface is %s\n", ii->ifa_name); */
				strncpy(ifr.ifr_name, ii->ifa_name, IFNAMSIZ - 1);
				break;
			} else if (asrc.addr.sa_family == AF_INET6 &&
				   !memcmp(&a->addr6.sin6_addr.s6_addr, &asrc.addr6.sin6_addr.s6_addr, 16)) {
				/* fprintf(stderr, "interface is %s\n", ii->ifa_name); */
				strncpy(ifr.ifr_name, ii->ifa_name, IFNAMSIZ - 1);
				break;
			}
		}
	}
	freeifaddrs(ifaddr);

	if (ifr.ifr_name[0]) {
		if (ioctl(sock, SIOCGIFMTU, &ifr) < 0)
			perror("ioctl");
		else
			fprintf(stderr, "  ioctl SIOCGIFMTU      -> ifr_mtu %d (for %.*s interface)\n",
				ifr.ifr_mtu, IFNAMSIZ, ifr.ifr_name);
	}
#endif

	ret = shutdown(sock, SHUT_RDWR);
	if (ret < 0) {
		perror("shutdown");
		exit(1);
	}

	return 0;
}
