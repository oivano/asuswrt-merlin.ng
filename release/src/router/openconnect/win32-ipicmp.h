/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Author: Daniel Lenski <dlenski@gmail.com>
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

#ifndef __OPENCONNECT_WIN32_IPICMP_H__
#define __OPENCONNECT_WIN32_IPICMP_H__

#include <ws2tcpip.h>
#include <stdint.h>

/* IPv4 header and flags used in gpst.c */

#define	IP_DF 0x4000			/* don't fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */

struct ip {
	u_char	ip_hl:4;		/* header length */
	u_char  ip_v:4;			/* version */
	u_char	ip_tos;			/* type of service */
	short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	short	ip_off;			/* fragment offset field */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

/* IPv6 header used in gpst.c */

struct ip6_hdr {
    union {
	struct ip6_hdrctl {
	    uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
					20 bits flow-ID */
	    uint16_t ip6_un1_plen;   /* payload length */
	    uint8_t  ip6_un1_nxt;    /* next header */
	    uint8_t  ip6_un1_hlim;   /* hop limit */
	} ip6_un1;
	uint8_t ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
    } ip6_ctlun;
    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
};


#define ip6_vfc   ip6_ctlun.ip6_un2_vfc
#define ip6_flow  ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt   ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim  ip6_ctlun.ip6_un1.ip6_un1_hlim
#define ip6_hops  ip6_ctlun.ip6_un1.ip6_un1_hlim

/* ICMP header and flags used in gpst.c */

#define IPPROTO_ICMP    1
#define	ICMP_MINLEN	8		/* abs minimum  */
#define ICMP_ECHO	8		/* Echo Request */
#define ICMP_ECHOREPLY	0		/* Echo Reply */

#define	icmp_pptr	icmp_hun.ih_pptr
#define	icmp_gwaddr	icmp_hun.ih_gwaddr
#define	icmp_id		icmp_hun.ih_idseq.icd_id
#define	icmp_seq	icmp_hun.ih_idseq.icd_seq
#define	icmp_void	icmp_hun.ih_void
#define	icmp_pmvoid	icmp_hun.ih_pmtu.ipm_void
#define	icmp_nextmtu	icmp_hun.ih_pmtu.ipm_nextmtu
#define	icmp_num_addrs	icmp_hun.ih_rtradv.irt_num_addrs
#define	icmp_wpa	icmp_hun.ih_rtradv.irt_wpa
#define	icmp_lifetime	icmp_hun.ih_rtradv.irt_lifetime

#define	icmp_otime	icmp_dun.id_ts.its_otime
#define	icmp_rtime	icmp_dun.id_ts.its_rtime
#define	icmp_ttime	icmp_dun.id_ts.its_ttime
#define	icmp_ip		icmp_dun.id_ip.idi_ip
#define	icmp_radv	icmp_dun.id_radv
#define	icmp_mask	icmp_dun.id_mask
#define	icmp_data	icmp_dun.id_data

struct icmp_ra_addr {
  uint32_t ira_addr;
  uint32_t ira_preference;
};

struct icmp {
  uint8_t  icmp_type;	/* type of message, see below */
  uint8_t  icmp_code;	/* type sub code */
  uint16_t icmp_cksum;	/* ones complement checksum of struct */
  union {
    u_char ih_pptr;		/* ICMP_PARAMPROB */
    struct in_addr ih_gwaddr;	/* gateway address */
    struct ih_idseq {		/* echo datagram */
      uint16_t icd_id;
      uint16_t icd_seq;
    } ih_idseq;
    uint32_t ih_void;

    /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
    struct ih_pmtu {
      uint16_t ipm_void;
      uint16_t ipm_nextmtu;
    } ih_pmtu;

    struct ih_rtradv {
      uint8_t irt_num_addrs;
      uint8_t irt_wpa;
      uint16_t irt_lifetime;
    } ih_rtradv;
  } icmp_hun;

  union {
    struct {
      uint32_t its_otime;
      uint32_t its_rtime;
      uint32_t its_ttime;
    } id_ts;
    struct {
      struct ip idi_ip;
      /* options and then 64 bits of data */
    } id_ip;
    struct icmp_ra_addr id_radv;
    uint32_t   id_mask;
    uint8_t    id_data[1];
  } icmp_dun;
};

/* ICMPv6 header and flags used in gpst.c */

#define IPPROTO_ICMPV6	58
#define ICMP6_ECHO_REQUEST	128
#define ICMP6_ECHO_REPLY	129

struct icmp6_hdr {
    uint8_t     icmp6_type;   /* type field */
    uint8_t     icmp6_code;   /* code field */
    uint16_t    icmp6_cksum;  /* checksum field */
    union {
	uint32_t  icmp6_un_data32[1]; /* type-specific field */
	uint16_t  icmp6_un_data16[2]; /* type-specific field */
	uint8_t   icmp6_un_data8[4];  /* type-specific field */
      } icmp6_dataun;
  };

#define icmp6_data32    icmp6_dataun.icmp6_un_data32
#define icmp6_data16    icmp6_dataun.icmp6_un_data16
#define icmp6_data8     icmp6_dataun.icmp6_un_data8
#define icmp6_pptr      icmp6_data32[0]  /* parameter prob */
#define icmp6_mtu       icmp6_data32[0]  /* packet too big */
#define icmp6_id        icmp6_data16[0]  /* echo request/reply */
#define icmp6_seq       icmp6_data16[1]  /* echo request/reply */
#define icmp6_maxdelay  icmp6_data16[0]  /* mcast group membership */

#endif /* __OPENCONNECT_WIN32_IPICMP_H__ */
