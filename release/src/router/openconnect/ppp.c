/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2020-2021 David Woodhouse, Daniel Lenski
 *
 * Authors: David Woodhouse <dwmw2@infradead.org>, Daniel Lenski <dlenski@gmail.com>
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

#include <errno.h>

static const uint16_t fcstab[256] = {
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

#define foldfcs(fcs, c) ( ( (fcs) >> 8 ) ^ fcstab[(fcs ^ (c)) & 0xff] )
#define NEED_ESCAPE(c, map) ( (((c) < 0x20) && (map && (1UL << (c)))) || ((c) == 0x7d) || ((c) == 0x7e) )
#define HDLC_OUT(outp, c, map) do {   \
	if (NEED_ESCAPE((c), map)) {  \
		*outp++ = 0x7d;       \
		*outp++ = (c) ^ 0x20; \
	} else                        \
		*outp++ = (c);        \
} while (0)

static struct pkt *hdlc_into_new_pkt(struct openconnect_info *vpninfo, struct pkt *old, int asyncmap)
{
	int len = old->len + old->ppp.hlen;
	const unsigned char *inp = old->data - old->ppp.hlen, *endp = inp + len;
	unsigned char *outp;
	uint16_t fcs = PPPINITFCS16;
	/* Every byte in payload and 2-byte FCS potentially expands to two bytes,
	 * plus 2 for flag (0x7e) at start and end. We know that we will output
	 * at least 4 bytes so we can stash those in the header. */
	struct pkt *p = alloc_pkt(vpninfo, len*2 + 2);
	if (!p)
		return NULL;

	outp = p->data - 4;
	*outp++ = 0x7e;

	for (; inp < endp; inp++) {
		fcs = foldfcs(fcs, *inp);
		HDLC_OUT(outp, *inp, asyncmap);
	}

	/* Append FCS, escaped, little-endian */
	fcs ^= 0xffff;
	HDLC_OUT(outp, fcs & 0xff, asyncmap);
	HDLC_OUT(outp, fcs >> 8, asyncmap);

	*outp++ = 0x7e;
	p->ppp.hlen = 4;
	p->len = outp - p->data;
	return p;
}

static int unhdlc_in_place(struct openconnect_info *vpninfo, unsigned char *bytes, int len, unsigned char **next)
{
	unsigned char *inp = bytes, *endp = bytes + len;
	unsigned char *outp = bytes;
	int escape = 0;
	uint16_t fcs = PPPINITFCS16;

	if (*inp == 0x7e)
		inp++;
	else
		vpn_progress(vpninfo, PRG_TRACE,
			     _("HDLC initial flag sequence (0x7e) is missing\n"));

	while (inp < endp) {
		unsigned char c = *inp++;
		if (c == 0x7e)
			goto done;
		else if (escape) {
			c ^= 0x20;
			escape = 0;
		} else if (c == 0x7d) {
			escape = 1;
			continue;
		}

		fcs = foldfcs(fcs, c);
		*outp++ = c;
	}
	vpn_progress(vpninfo, PRG_ERR,
		     _("HDLC buffer ended without FCS and flag sequence (0x7e)\n"));
	return -EINVAL;

 done:
	if (outp < bytes + 2) {
		vpn_progress(vpninfo, PRG_ERR,
			     _("HDLC frame too short (%d bytes)\n"),
			     (int)(outp - bytes));
		return -EINVAL;
	}

	outp -= 2; /* FCS */

	if (next)
		*next = inp; /* Pointing at the byte AFTER final 0x7e */

	if (fcs != PPPGOODFCS16) {
		vpn_progress(vpninfo, PRG_INFO,
			     _("Bad HDLC packet FCS %04x\n"), fcs);
		dump_buf_hex(vpninfo, PRG_INFO, '<', bytes, len);
		return -EINVAL;
	} else {
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Un-HDLC'ed packet (%ld bytes -> %ld), FCS=0x%04x\n"),
			     (long)(inp - bytes), (long)(outp - bytes), fcs);
		return outp - bytes;
	}
}

static const char * const ppps_names[] = {
	"DEAD",
	"ESTABLISH",
	"OPENED",
	"AUTHENTICATE",
	"NETWORK",
	"TERMINATE"
};

static const char * const encap_names[PPP_ENCAP_MAX+1] = {
	NULL,
	"RFC1661",
	"RFC1662 HDLC",
	"F5",
	"F5 HDLC",
	"FORTINET",
};

static const char * const lcp_names[] = {
	NULL,
	"Configure-Request",
	"Configure-Ack",
	"Configure-Nak",
	"Configure-Reject",
	"Terminate-Request",
	"Terminate-Ack",
	"Code-Reject",
	"Protocol-Reject",
	"Echo-Request",
	"Echo-Reply",
	"Discard-Request",
};

static inline const char *proto_names(uint16_t proto)
{
	static char unknown[21];

	switch (proto) {
	case PPP_LCP: return "LCP";
	case PPP_IPCP: return "IPCP";
	case PPP_IP6CP: return "IP6CP";
	case PPP_CCP: return "CCP";
	case PPP_IP: return "IPv4";
	case PPP_IP6: return "IPv6";

	default:
		snprintf(unknown, 21, "unknown proto 0x%04x", proto);
		return unknown;
	}
}

int openconnect_ppp_new(struct openconnect_info *vpninfo,
			int encap, int want_ipv4, int want_ipv6)
{
	free(vpninfo->ppp);

	struct oc_ppp *ppp = vpninfo->ppp = calloc(1, sizeof(*ppp));

	if (!ppp)
		return -ENOMEM;

	/* Delay tunnel setup during PPP negotiation */
	vpninfo->delay_tunnel_reason = "PPP negotiation";

	/* Outgoing IPv4 address and IPv6 interface identifier bits,
	 * if already configured via another mechanism */
	if (vpninfo->ip_info.addr)
		ppp->out_ipv4_addr.s_addr = inet_addr(vpninfo->ip_info.addr);
	if (vpninfo->ip_info.netmask6) {
		char *slash = strchr(vpninfo->ip_info.netmask6, '/');
		if (slash) *slash=0;
		inet_pton(AF_INET6, vpninfo->ip_info.netmask6, &ppp->out_ipv6_addr);
		if (slash) *slash='/';
	} else if (vpninfo->ip_info.addr6) {
		inet_pton(AF_INET6, vpninfo->ip_info.addr6, &ppp->out_ipv6_addr);
	}

	/* Nameservers to request from peer
	 * (see https://tools.ietf.org/html/rfc1877#section-1) */
	if (!vpninfo->ip_info.dns[0] && !vpninfo->ip_info.nbns[0])
		ppp->solicit_peerns = IPCP_DNS0|IPCP_DNS1|IPCP_NBNS0|IPCP_NBNS1;

	ppp->encap = encap;
	ppp->want_ipv4 = want_ipv4;
	ppp->want_ipv6 = want_ipv6 && !vpninfo->disable_ipv6;

	return ppp_reset(vpninfo);
}

int ppp_reset(struct openconnect_info *vpninfo)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	if (!ppp)
		return -EINVAL;

	memset(&ppp->lcp, 0, sizeof(ppp->lcp));
	memset(&ppp->ipcp, 0, sizeof(ppp->ipcp));
	memset(&ppp->ip6cp, 0, sizeof(ppp->ip6cp));

	ppp->ppp_state = PPPS_DEAD;
	ppp->out_asyncmap = 0;
	ppp->out_lcp_opts = BIT_MRU | BIT_MAGIC | BIT_PFCOMP | BIT_ACCOMP | BIT_MRU_COAX;
	ppp->check_http_response = 0;

	switch (ppp->encap) {
	case PPP_ENCAP_F5:
		ppp->encap_len = 4;
		break;

	case PPP_ENCAP_FORTINET:
		/* XX: Fortinet server rejects asyncmap and header compression. Don't blame me. */
		ppp->out_lcp_opts &= ~(BIT_PFCOMP | BIT_ACCOMP);
		ppp->encap_len = 6;
		break;

	case PPP_ENCAP_F5_HDLC:
	case PPP_ENCAP_RFC1662_HDLC:
		ppp->encap_len = 0;
		ppp->hdlc = 1;
		break;

	case PPP_ENCAP_RFC1661:
		ppp->encap_len = 0;
		break;

	default:
		free(ppp);
		return -EINVAL;
	}

	if (ppp->hdlc) ppp->out_lcp_opts |= BIT_ASYNCMAP;
	ppp->exp_ppp_hdr_size = 4; /* Address(1), Control(1), Proto(2) */

	return 0;
}

static void print_ppp_state(struct openconnect_info *vpninfo, int level)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	char buf4[20];
	char buf6[40];

	if (ppp->want_ipv4)
		inet_ntop(AF_INET, &ppp->in_ipv4_addr, buf4, sizeof(buf4));
	else
		snprintf(buf4, sizeof(buf4), "none");

	if (ppp->want_ipv6)
		inet_ntop(AF_INET6, &ppp->in_ipv6_addr, buf6, sizeof(buf6));
	else
		snprintf(buf6, sizeof(buf6), "none");

	vpn_progress(vpninfo, level, _("Current PPP state: %s (encap %s):\n"),
		     ppps_names[ppp->ppp_state], encap_names[ppp->encap]);
	vpn_progress(vpninfo, level, _("    in: asyncmap=0x%08x, lcp_opts=%d, lcp_magic=0x%08x, ipv4=%s, ipv6=%s\n"),
		     ppp->in_asyncmap, ppp->in_lcp_opts, (unsigned)ntohl(ppp->in_lcp_magic),
		     buf4, buf6);

	if (ppp->want_ipv4)
		inet_ntop(AF_INET, &ppp->out_ipv4_addr, buf4, sizeof(buf4));
	if (ppp->want_ipv6)
		inet_ntop(AF_INET6, &ppp->out_ipv6_addr, buf6, sizeof(buf6));
	vpn_progress(vpninfo, level, _("   out: asyncmap=0x%08x, lcp_opts=%d, lcp_magic=0x%08x, ipv4=%s, ipv6=%s, solicit_peerns=%d, got_peerns=%d\n"),
		     ppp->out_asyncmap, ppp->out_lcp_opts, (unsigned)ntohl(ppp->out_lcp_magic),
		     buf4, buf6, ppp->solicit_peerns, ppp->got_peerns);
}

static int buf_append_ppp_tlv(struct oc_text_buf *buf, int tag, int len, const void *data)
{
	unsigned char b[2];

	b[0] = tag;
	b[1] = len + 2;

	buf_append_bytes(buf, b, 2);
	if (len)
		buf_append_bytes(buf, data, len);

	return b[1];
}

static int buf_append_ppp_tlv_be16(struct oc_text_buf *buf, int tag, uint16_t value)
{
	uint16_t val_be;

	store_be16(&val_be, value);
	return buf_append_ppp_tlv(buf, tag, 2, &val_be);
}

static int buf_append_ppp_tlv_be32(struct oc_text_buf *buf, int tag, uint32_t value)
{
	uint32_t val_be;

	store_be32(&val_be, value);
	return buf_append_ppp_tlv(buf, tag, 4, &val_be);
}

static int queue_config_packet(struct openconnect_info *vpninfo, uint16_t proto,
			       int id, int code, int len, const void *payload)
{
	struct pkt *p = alloc_pkt(vpninfo, len + 4);

	if (!p)
		return -ENOMEM;

	p->ppp.proto = proto;
	p->data[0] = code;
	p->data[1] = id;
	p->len = 4 + len; /* payload length includes code, id, own 2 bytes */
	store_be16(p->data + 2, p->len);
	if (len)
		memcpy(p->data + 4, payload, len);

	queue_packet(&vpninfo->tcp_control_queue, p);
	return 0;
}

#define PROTO_TAG_LEN(p, t, l) ((((uint32_t)(p)) << 16) | ((t) << 8) | (l))

static int handle_config_request(struct openconnect_info *vpninfo,
				 int proto, int id, unsigned char *payload, int len)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	struct oc_text_buf *rejbuf = NULL, *nakbuf = NULL;
	int ret;
	struct oc_ncp *ncp;
	unsigned char *p;
	char abuf[MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];

	switch (proto) {
	case PPP_LCP: ncp = &ppp->lcp; break;
	case PPP_IPCP: ncp = &ppp->ipcp; break;
	case PPP_IP6CP: ncp = &ppp->ip6cp; break;
	default: return -EINVAL;
	}

	for (p = payload ; p+1 < payload+len && p+p[1] <= payload+len; p += p[1]) {
		unsigned char t = p[0], l = p[1];
		switch (PROTO_TAG_LEN(proto, t, l-2)) {
		case PROTO_TAG_LEN(PPP_LCP, LCP_MRU, 2): {
			int mru = load_be16(p + 2);
			if ((ppp->out_lcp_opts & BIT_MRU_COAX) && mru < vpninfo->ip_info.mtu) {
				/* XX: nak-offer our (larger) MTU to the server, but only try this once */
				store_be16(p + 2, vpninfo->ip_info.mtu);
				ppp->out_lcp_opts &= ~BIT_MRU_COAX;

				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Received MRU %d from server. Nak-offering larger MRU of %d (our MTU)\n"),
					     mru, vpninfo->ip_info.mtu);
				goto nak;
			} else {
				vpninfo->ip_info.mtu = mru;
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Received MRU %d from server. Setting our MTU to match.\n"),
					     mru);
			}
			break;
		}
		case PROTO_TAG_LEN(PPP_LCP, LCP_ASYNCMAP, 4):
			ppp->in_asyncmap = load_be32(p+2);
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received asyncmap of 0x%08x from server\n"),
				     ppp->in_asyncmap);
			break;
		case PROTO_TAG_LEN(PPP_LCP, LCP_MAGIC, 4):
			memcpy(&ppp->in_lcp_magic, p+2, 4);
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received magic number of 0x%08x from server\n"),
				     (unsigned)ntohl(ppp->in_lcp_magic));
			break;
		case PROTO_TAG_LEN(PPP_LCP, LCP_PFCOMP, 0):
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received protocol field compression from server\n"));
			ppp->in_lcp_opts |= BIT_PFCOMP;
			break;
		case PROTO_TAG_LEN(PPP_LCP, LCP_ACCOMP, 0):
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received address and control field compression from server\n"));
			ppp->in_lcp_opts |= BIT_ACCOMP;
			break;
		case PROTO_TAG_LEN(PPP_IPCP, IPCP_IPADDRS, 8):
			/* XX: Ancient and deprecated. We're supposed to ignore it if we receive it, unless
			 * we've been Nak'ed. https://tools.ietf.org/html/rfc1332#section-3.1 */
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received deprecated IP-Addresses from server, ignoring\n"));
			break;
		case PROTO_TAG_LEN(PPP_IPCP, IPCP_IPCOMP, 4):
			if (load_be16(p+2) == 0x002d) {
				/* Van Jacobson TCP/IP compression. Includes an
				 * additional 2 payload bytes (Max-Slot-Id, Comp-Slot-Id) */
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Received Van Jacobson TCP/IP compression from server\n"));
				/* No. Just no. */
				goto reject;
			}
			goto unknown;
		case PROTO_TAG_LEN(PPP_IPCP, IPCP_IPADDR, 4):
			memcpy(&ppp->in_ipv4_addr, p+2, 4);
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received peer IPv4 address %s from server\n"),
				     inet_ntop(AF_INET, &ppp->in_ipv4_addr, abuf, sizeof(abuf)));
			break;
		case PROTO_TAG_LEN(PPP_IP6CP, IP6CP_INT_ID, 8): {
			unsigned char ipv6_ll[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0};

			/* XX: The server has allegedly sent us its link-local IPv6 address.
			 * However, on the only server I have access to which supports IPv6,
			 * this is just a random/garbage value, and `ping6 -I $TUNDEV $THIS_LL_ADDRESS`
			 * returns an "unreachable" result from the server's actual LL address,
			 * which is not sent over PPP configuration. This is probably just an
			 * ignorable vestige of before the days of IPv6 address autoconfiguration.
			 */
			memcpy(ipv6_ll + 8, p+2, 8);
			memcpy(&ppp->in_ipv6_addr, ipv6_ll, 16);
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received peer IPv6 link-local address %s from server\n"),
				     inet_ntop(AF_INET6, &ppp->in_ipv6_addr, abuf, sizeof(abuf)));
			break;
		}
		default:
		unknown:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Received unknown %s TLV (tag %d, len %d+2) from server:\n"),
				     proto_names(proto), t, l-2);
			dump_buf_hex(vpninfo, PRG_DEBUG, '<', p, (int)p[1]);
		reject:
			if (!rejbuf)
				rejbuf = buf_alloc();
			if (!rejbuf) {
				ret = -ENOMEM;
				goto out;
			}
			buf_append_bytes(rejbuf, p, l);
			break;
		nak:
			if (!nakbuf)
				nakbuf = buf_alloc();
			if (!nakbuf) {
				ret = -ENOMEM;
				goto out;
			}
			buf_append_bytes(nakbuf, p, l);

		}
	}
	ncp->state |= NCP_CONF_REQ_RECEIVED;

	if (p != payload+len) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received %ld extra bytes at end of Config-Request:\n"), (long)(payload + len - p));
		dump_buf_hex(vpninfo, PRG_DEBUG, '<', p, payload + len - p);
	}

	if (rejbuf) {
		if ((ret = buf_error(rejbuf)))
			goto out;
		vpn_progress(vpninfo, PRG_DEBUG, _("Reject %s/id %d config from server\n"), proto_names(proto), id);
		if ((ret = queue_config_packet(vpninfo, proto, id, CONFREJ, rejbuf->pos, rejbuf->data)) >= 0) {
			ret = 0;
		}
	}
	if (nakbuf) {
		if ((ret = buf_error(nakbuf)))
			goto out;
		vpn_progress(vpninfo, PRG_DEBUG, _("Nak %s/id %d config from server\n"), proto_names(proto), id);
		if ((ret = queue_config_packet(vpninfo, proto, id, CONFNAK, nakbuf->pos, nakbuf->data)) >= 0) {
			ret = 0;
		}
	}
	if (!rejbuf && !nakbuf) {
		vpn_progress(vpninfo, PRG_DEBUG, _("Ack %s/id %d config from server\n"), proto_names(proto), id);
		if ((ret = queue_config_packet(vpninfo, proto, id, CONFACK, len, payload)) >= 0) {
			ncp->state |= NCP_CONF_ACK_SENT;
			ret = 0;
		}
	}

 out:
	buf_free(rejbuf);
	buf_free(nakbuf);
	return ret;
}

static int queue_config_request(struct openconnect_info *vpninfo, int proto)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	const uint32_t zero = 0;
	int ret, id, b;
	struct oc_ncp *ncp;
	struct oc_text_buf *buf;

	buf = buf_alloc();

	ret = buf_ensure_space(buf, 64);
	if (ret)
		goto out;

	switch (proto) {
	case PPP_LCP:
		ncp = &ppp->lcp;
		if (!vpninfo->ip_info.mtu) {
			int overhead = TLS_OVERHEAD + ppp->encap_len        /* TLS and encapsulation overhead */
				+ (ppp->hdlc ? 4 : 0)                       /* HDLC framing and FCS */
				+ (ppp->out_lcp_opts & BIT_ACCOMP ? 0 : 2)  /* PPP header AC fields */
				+ (ppp->out_lcp_opts & BIT_PFCOMP ? 1 : 2); /* PPP header protocol field */
			vpninfo->ip_info.mtu = calculate_mtu(vpninfo, 0 /* not UDP */, overhead, 0 /* no footer */, 1 /* no block padding */);
			/* XX: HDLC fudge factor (average overhead on random payload is 1/128, we'll use 4x that) */
			if (ppp->hdlc)
				vpninfo->ip_info.mtu -= vpninfo->ip_info.mtu >> 5;
			vpn_progress(vpninfo, PRG_INFO,
				     _("Requesting calculated MTU of %d\n"), vpninfo->ip_info.mtu);
		}

		if (ppp->out_lcp_opts & BIT_MRU)
			buf_append_ppp_tlv_be16(buf, LCP_MRU, vpninfo->ip_info.mtu);

		if (ppp->out_lcp_opts & BIT_ASYNCMAP)
			buf_append_ppp_tlv_be32(buf, LCP_ASYNCMAP, ppp->out_asyncmap);

		if (ppp->out_lcp_opts & BIT_MAGIC) {
			ret = openconnect_random(&ppp->out_lcp_magic, sizeof(ppp->out_lcp_magic));
			if (ret)
				goto out;
			buf_append_ppp_tlv(buf, LCP_MAGIC, 4, &ppp->out_lcp_magic);
		}

		if (ppp->out_lcp_opts & BIT_PFCOMP)
			buf_append_ppp_tlv(buf, LCP_PFCOMP, 0, NULL);

		if (ppp->out_lcp_opts & BIT_ACCOMP)
			buf_append_ppp_tlv(buf, LCP_ACCOMP, 0, NULL);
		break;

	case PPP_IPCP:
		ncp = &ppp->ipcp;

		/* XX: send zero for IPv4/DNS/NBNS to request via NAK */
		buf_append_ppp_tlv(buf, IPCP_IPADDR, 4, &ppp->out_ipv4_addr.s_addr);

		/* XX: See ppp.h for why bitfields work here */
		for (b=0; b<4; b++)
			if (ppp->solicit_peerns & (1<<b))
				buf_append_ppp_tlv(buf, IPCP_xNS_BASE + b, 4, &zero);
		break;

	case PPP_IP6CP:
		ncp = &ppp->ip6cp;

		/* Send zero here if we need a link-local IPv6 address, because
		 * we don't yet have a global IPv6 address. Otherwise, just send
		 * the interface bits of our global IPv6 address, to avoid getting
		 * a CONFREQ/CONFNAK/re-CONFREQ round trip */
		buf_append_ppp_tlv(buf, IP6CP_INT_ID, 8, ppp->out_ipv6_addr.s6_addr + 8);

		break;

	default:
		ret = -EINVAL;
		goto out;
	}

	if ((ret = buf_error(buf)) != 0)
		goto out;

	id = ++ncp->id;
	vpn_progress(vpninfo, PRG_DEBUG, _("Sending our %s/id %d config request to server\n"),
		     proto_names(proto), id);
	if ((ret = queue_config_packet(vpninfo, proto, id, CONFREQ, buf->pos, buf->data)) >= 0) {
		ncp->state |= NCP_CONF_REQ_SENT;
		ret = 0;
	}

out:
        buf_free(buf);
	return ret;
}

static int handle_config_rejnak(struct openconnect_info *vpninfo,
				int proto, int id, int code, unsigned char *payload, int len)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	struct oc_ncp *ncp;
	unsigned char *p;
	char abuf[MAX(INET_ADDRSTRLEN, INET6_ADDRSTRLEN)];

	switch (proto) {
	case PPP_LCP: ncp = &ppp->lcp; break;
	case PPP_IPCP: ncp = &ppp->ipcp; break;
	case PPP_IP6CP: ncp = &ppp->ip6cp; break;
	default: return -EINVAL;
	}

	/* If it isn't a response to our latest ConfReq, we don't care */
	if (id != ncp->id)
		return 0;

	for (p = payload ; p+1 < payload+len && p+p[1] <= payload+len; p += p[1]) {
		unsigned char t = p[0], l = p[1];
		switch (PROTO_TAG_LEN(proto, t, l-2)) {
		case PROTO_TAG_LEN(PPP_LCP, LCP_MRU, 2):
			/* XX: If this happens, should we try a smaller MRU? */
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Server rejected/nak'ed LCP MRU option\n"));
			ppp->out_lcp_opts &= ~BIT_MRU;
			break;
		case PROTO_TAG_LEN(PPP_LCP, LCP_ASYNCMAP, 4):
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Server rejected/nak'ed LCP asyncmap option\n"));
			ppp->out_asyncmap = ASYNCMAP_LCP;
			ppp->out_lcp_opts &= ~BIT_ASYNCMAP;
			break;
		case PROTO_TAG_LEN(PPP_LCP, LCP_MAGIC, 4):
			if (code == CONFNAK) {
				/* XX: If this happens, we are will select a new magic number in
				 * our next CONFREQ, in case it's 1984 and our RS-232 nullmodem is
				 * looped back. (https://tools.ietf.org/html/rfc1661#section-6.4) */
			} else {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Server rejected LCP magic option\n"));
				ppp->out_lcp_opts &= ~BIT_MAGIC;
			}
			break;
		case PROTO_TAG_LEN(PPP_LCP, LCP_PFCOMP, 0):
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Server rejected/nak'ed LCP PFCOMP option\n"));
			ppp->out_lcp_opts &= ~BIT_PFCOMP;
			break;
		case PROTO_TAG_LEN(PPP_LCP, LCP_ACCOMP, 0):
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Server rejected/nak'ed LCP ACCOMP option\n"));
			ppp->out_lcp_opts &= ~BIT_ACCOMP;
			break;
		case PROTO_TAG_LEN(PPP_IPCP, IPCP_IPADDR, 4): {
			struct in_addr *a = (void *)(p + 2);
			inet_ntop(AF_INET, a, abuf, sizeof(abuf));
			if (code == CONFNAK && a->s_addr) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Server nak-offered IPv4 address: %s\n"), abuf);
				ppp->out_ipv4_addr = *a;
				if (vpninfo->ip_info.addr) {
					vpn_progress(vpninfo, PRG_ERR,
						     _("Server rejected Legacy IP address %s\n"),
						       vpninfo->ip_info.addr);
					ppp->want_ipv4 = 0;
				}
			} else {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Server rejected/nak'ed our IPv4 address or request: %s\n"), abuf);
				return -EINVAL;
			}
			break;
		}
		case PROTO_TAG_LEN(PPP_IPCP, IPCP_xNS_BASE + 0, 4):
		case PROTO_TAG_LEN(PPP_IPCP, IPCP_xNS_BASE + 1, 4):
		case PROTO_TAG_LEN(PPP_IPCP, IPCP_xNS_BASE + 2, 4):
		case PROTO_TAG_LEN(PPP_IPCP, IPCP_xNS_BASE + 3, 4): {
			struct in_addr *a = (void *)(p + 2);
			/* XX: see ppp.h for why bitfields work here */
			int is_dns = t&1;
			int entry = (t&2)>>1;
			inet_ntop(AF_INET, a, abuf, sizeof(abuf));
			if (code == CONFNAK && a->s_addr) {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Server nak-offered IPCP request for %s[%d] server: %s\n"),
					     is_dns ? "DNS" : "NBNS", entry, abuf);
				ppp->nameservers[t & 3] = *a;
				ppp->got_peerns |= (1<<(t-IPCP_xNS_BASE));
			} else {
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Server rejected/nak'ed IPCP request for %s[%d] server\n"),
					     is_dns ? "DNS" : "NBNS", entry);
			}
			/* Stop soliciting */
			ppp->solicit_peerns &= ~(1<<(t-IPCP_xNS_BASE));
			break;
		}
		case PROTO_TAG_LEN(PPP_IP6CP, IP6CP_INT_ID, 8): {
			uint64_t *val = (void *)(p + 2);
			if (code == CONFNAK && *val != 0) {
				unsigned char ipv6_ll[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0};
				memcpy(ipv6_ll + 8, val, 8);
				inet_ntop(AF_INET6, ipv6_ll, abuf, sizeof(abuf));

				vpn_progress(vpninfo, PRG_DEBUG,
					     _("Server nak-offered IPv6 link-local address %s\n"), abuf);
				/* If we don't already have a valid global IPv6 address, then we are
				 * supposed to use this one to create a valid link-local IPv6
				 * address to allow autoconfiguration (https://tools.ietf.org/html/rfc5072)
				 */
				memcpy(&ppp->out_ipv6_addr, ipv6_ll, 16);
			} else {
				vpn_progress(vpninfo, PRG_INFO,
					     _("Server rejected/nak'ed our IPv6 interface identifier\n"));
				ppp->want_ipv6 = 0;
				return 0;
			}
			break;
		}
		default:
			vpn_progress(vpninfo, PRG_DEBUG,
				     _("Server rejected/nak'ed %s TLV (tag %d, len %d+2)\n"),
				     proto_names(proto), t, l-2);
			dump_buf_hex(vpninfo, PRG_DEBUG, '<', p, (int)p[1]);
			/* XX: Should abort negotiation */
			return -EINVAL;
		}
	}
	if (p != payload+len) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Received %ld extra bytes at end of Config-Reject:\n"), (long)(payload + len - p));
		dump_buf_hex(vpninfo, PRG_DEBUG, '<', p, payload + len - p);
	}

	return queue_config_request(vpninfo, proto);
}

static int handle_config_packet(struct openconnect_info *vpninfo,
				uint16_t proto, unsigned char *p, int len)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	int code = p[0], id = p[1];
	int ret = 0, add_state = 0;

	/* XX: The NCP header consist of 4 bytes: u8 code, u8 id, u16 length (length includes this header) */
	if (load_be16(p + 2) > len) {
		vpn_progress(vpninfo, PRG_ERR, "PPP config packet too short (header says %d bytes, received %d)\n", load_be16(p+2), len);
		dump_buf_hex(vpninfo, PRG_ERR, '<', p, len);
		return -EINVAL;
	} else if (load_be16(p + 2) < len) {
		vpn_progress(vpninfo, PRG_DEBUG, "PPP config packet has junk at end (header says %d bytes, received %d)\n", load_be16(p+2), len);
		len = load_be16(p + 2);
	}

        if (code > 0 && code <= 11)
		vpn_progress(vpninfo, PRG_TRACE, _("Received %s/id %d %s from server\n"), proto_names(proto), id, lcp_names[code]);
	switch (code) {
	case CONFREQ:
		ret = handle_config_request(vpninfo, proto, id, p + 4, len - 4);
		break;

	case CONFACK:
		/* XX: we could verify that the ack/reply bytes match the request bytes,
		 * and the ID is the expected one, but it isn't 1992, so let's not.
		 */
		add_state = NCP_CONF_ACK_RECEIVED;
		break;

	case ECHOREQ:
		if (ppp->ppp_state >= PPPS_OPENED)
			ret = queue_config_packet(vpninfo, proto, id, ECHOREP, 4, &ppp->out_lcp_magic);
		break;

	case TERMREQ:
		add_state = NCP_TERM_REQ_RECEIVED;
		ret = queue_config_packet(vpninfo, proto, id, TERMACK, 0, NULL);
		if (ret >= 0)
			add_state = NCP_TERM_ACK_SENT;
		goto set_quit_reason;

	case TERMACK:
		add_state = NCP_TERM_ACK_RECEIVED;
	set_quit_reason:
		if (!vpninfo->quit_reason && len > 4) {
			vpninfo->quit_reason = strndup((char *)(p + 4), len - 4);
			vpn_progress(vpninfo, PRG_ERR,
				     _("Server terminates with reason: %s\n"),
				     vpninfo->quit_reason);
		}
		ppp->ppp_state = PPPS_TERMINATE;
		vpninfo->delay_close = NO_DELAY_CLOSE;
		break;

	case ECHOREP:
	case DISCREQ:
		break;

	case CONFREJ:
	case CONFNAK:
		ret = handle_config_rejnak(vpninfo, proto, id, code, p + 4, len - 4);
		break;

	case PROTREJ:
		/* Only handle rejection of IPCP or IP6CP */
		if (proto != PPP_LCP || len < 6)
			goto unknown;

		proto = load_be16(p + 4);
		if (proto == PPP_IPCP) ppp->want_ipv4 = 0;
		else if (proto == PPP_IP6CP) ppp->want_ipv6 = 0;
		else goto unknown;

		vpn_progress(vpninfo, PRG_DEBUG,
			     _("Server rejected our request to configure IPv%d\n"),
			     proto == PPP_IP6CP ? 6 : 4);
		break;

	case CODEREJ:
	default:
	unknown:
		ret = -EINVAL;
	}

	switch (proto) {
	case PPP_LCP: ppp->lcp.state |= add_state; break;
	case PPP_IPCP: ppp->ipcp.state |= add_state; break;
	case PPP_IP6CP: ppp->ip6cp.state |= add_state; break;
	default: return -EINVAL;
	}
	return ret;
}

static int handle_state_transition(struct openconnect_info *vpninfo, int dtls,
				   struct keepalive_info *kai, int *timeout)
{
	struct oc_ppp *ppp = vpninfo->ppp;
	time_t now = time(NULL);
	int last_state = ppp->ppp_state, network, ret = 0;

	switch (ppp->ppp_state) {
	case PPPS_DEAD:
		/* Prevent race conditions after recovering dead peer connection */
		kai->last_rx = kai->last_tx = now;

		/* Drop any failed outgoing packet from previous connection;
		 * we need to reconfigure before we can send data packets. */
		free_pkt(vpninfo, vpninfo->current_ssl_pkt);
		vpninfo->current_ssl_pkt = NULL;
		vpninfo->partial_rec_size = 0;
		ppp->ppp_state = PPPS_ESTABLISH;
		/* fall through */

	case PPPS_ESTABLISH:
		if ((ppp->lcp.state & NCP_CONF_ACK_RECEIVED) && (ppp->lcp.state & NCP_CONF_ACK_SENT))
			ppp->ppp_state = PPPS_OPENED;
		else {
			if (ka_check_deadline(timeout, now, ppp->lcp.last_req + 3)) {
				ppp->lcp.last_req = now;
				if ((ret = queue_config_request(vpninfo, PPP_LCP)) < 0)
					goto out;
			}
			break;
		}
		/* fall through */

	case PPPS_OPENED:
		network = 1;
		if (!ppp->want_ipv4 && !ppp->want_ipv6) {
			vpninfo->quit_reason = "No network protocols configured";
			return -EINVAL;
		}

		if (ppp->want_ipv4) {
			if (!(ppp->ipcp.state & NCP_CONF_ACK_SENT) || !(ppp->ipcp.state & NCP_CONF_ACK_RECEIVED)) {
				network = 0;
				if (ka_check_deadline(timeout, now, ppp->ipcp.last_req + 3)) {
					ppp->ipcp.last_req = now;
					if ((ret = queue_config_request(vpninfo, PPP_IPCP)) < 0)
						goto out;
				}
			}
		}

		if (ppp->want_ipv6) {
			if (!(ppp->ip6cp.state & NCP_CONF_ACK_SENT) || !(ppp->ip6cp.state & NCP_CONF_ACK_RECEIVED)) {
				network = 0;
				if (ka_check_deadline(timeout, now, ppp->ip6cp.last_req + 3)) {
					ppp->ip6cp.last_req = now;
					if ((ret = queue_config_request(vpninfo, PPP_IP6CP)) < 0)
						goto out;
				}
			}
		}

		if (!network)
			break;

		ppp->ppp_state = PPPS_NETWORK;

		/* Ensure that we use the addresses we configured on PPP */
		if (ppp->want_ipv4 && !vpninfo->ip_info.addr) {
			vpninfo->ip_info.addr = add_option_ipaddr(&vpninfo->cstp_options, "ppp_ipv4",
								  AF_INET, &ppp->out_ipv4_addr);
		}

		/* Ensure that we use the addresses we configured on PPP */
		if (ppp->want_ipv6 && !vpninfo->ip_info.addr6 && !vpninfo->ip_info.netmask6) {
			vpninfo->ip_info.addr6 = add_option_ipaddr(&vpninfo->cstp_options, "ppp_ipv6",
								   AF_INET6, &ppp->out_ipv6_addr);
		}

		if (ppp->got_peerns & IPCP_NBNS0)
			vpninfo->ip_info.nbns[0] = add_option_ipaddr(&vpninfo->cstp_options, "ppp_nbns0",
								     AF_INET, &ppp->nameservers[0]);
		if (ppp->got_peerns & IPCP_DNS0)
			vpninfo->ip_info.dns[0] = add_option_ipaddr(&vpninfo->cstp_options, "ppp_dns0",
								    AF_INET, &ppp->nameservers[1]);
		if (ppp->got_peerns & IPCP_NBNS1)
			vpninfo->ip_info.nbns[1] = add_option_ipaddr(&vpninfo->cstp_options, "ppp_nbns1",
								     AF_INET, &ppp->nameservers[2]);
		if (ppp->got_peerns & IPCP_DNS1)
			vpninfo->ip_info.dns[1] = add_option_ipaddr(&vpninfo->cstp_options, "ppp_dns1",
								    AF_INET, &ppp->nameservers[3]);

		/* on close, we will need to send TERMREQ, then receive TERMACK */
		vpninfo->delay_close = DELAY_CLOSE_IMMEDIATE_CALLBACK;
		break;

	case PPPS_NETWORK:
		/* XX: When we pause and reconnect, we expect the auth cookie/session (external to the
		 * PPP layer) to remain valid, and to negotiate the same IP addresses on reconnection.
		 *
		 * However, most servers cancel our session or cancel our IP address allocation if we
		 * TERMINATE at the PPP layer, so we shouldn't do it when pausing.
		 */
		if (vpninfo->got_cancel_cmd ||
		    (vpninfo->got_pause_cmd && ppp->terminate_on_pause))
			ppp->ppp_state = PPPS_TERMINATE;
		else
			break;
		/* fall through */

	case PPPS_TERMINATE:
		/* XX: If server terminated,  we already ACK'ed it */
		if (ppp->lcp.state & NCP_TERM_REQ_RECEIVED)
			return -EPIPE;
		else if (!(ppp->lcp.state & NCP_TERM_ACK_RECEIVED)) {
			/* We need to send a TERMREQ and wait for a TERMACK, but not keep
			 * retrying for ever if it fails. For TLS, which ought to be
			 * lossless, we send TERMREQ just once, wait for a second, and
			 * give up. For DTLS we try three times (with a second between
			 * them and give up if none of them elicit a TERMACK. */
			if (!(ppp->lcp.state & NCP_TERM_REQ_SENT)) {
				ppp->lcp.state |= NCP_TERM_REQ_SENT;
				ppp->lcp.termreqs_sent = 1;
				ppp->lcp.last_req = now;
				(void) queue_config_packet(vpninfo, PPP_LCP, ++ppp->lcp.id, TERMREQ, 0, NULL);
				vpninfo->delay_close = DELAY_CLOSE_WAIT; /* Wait 1s for TERMACK */

			} else if (!ka_check_deadline(timeout, now, ppp->lcp.last_req + 1)) {
				vpninfo->delay_close = DELAY_CLOSE_WAIT; /* Still waiting */

			} else if (!dtls || ppp->lcp.termreqs_sent >= 3) {
				ppp->ppp_state = PPPS_TERMINATE;

			} else {
				ppp->lcp.termreqs_sent++;
				ppp->lcp.last_req = now;
				(void) queue_config_packet(vpninfo, PPP_LCP, ++ppp->lcp.id, TERMREQ, 0, NULL);
				vpninfo->delay_close = DELAY_CLOSE_WAIT; /* Wait 1s more */
			}
		}
		break;
	case PPPS_AUTHENTICATE: /* XX: should never */
	default:
		vpninfo->quit_reason = "Unexpected state";
		return -EINVAL;
	}

	/* Delay tunnel setup until after PPP negotiation */
	vpninfo->delay_tunnel_reason = (ppp->ppp_state < PPPS_NETWORK) ? "PPP negotiation" : NULL;

	if (last_state != ppp->ppp_state) {
		vpn_progress(vpninfo, PRG_DEBUG,
			     _("PPP state transition from %s to %s on %s channel\n"),
			     ppps_names[last_state], ppps_names[ppp->ppp_state],
			     dtls ? "DTLS" : "TLS");
		print_ppp_state(vpninfo, PRG_TRACE);
		return 1;
	}
 out:
	return ret;
}

static inline void add_ppp_header(struct pkt *p, struct oc_ppp *ppp, int proto)
{
	unsigned char *ph = p->data;
	/* XX: store PPP header, in reverse */
	*--ph = proto & 0xff;
	if (proto > 0xff || !(ppp->out_lcp_opts & BIT_PFCOMP))
		*--ph = proto >> 8;
	if (proto == PPP_LCP || !(ppp->out_lcp_opts & BIT_ACCOMP)) {
		*--ph = 0x03; /* Control */
		*--ph = 0xff; /* Address */
	}
	p->ppp.hlen = p->data - ph;
}

int check_http_status(const char *buf, int len)
{
	if (len >= 5 && !memcmp(buf, "HTTP/", 5)) {
		const char *eol = memchr(buf, '\r', len) ?: memchr(buf, '\n', len);
		const char *sp1 = memchr(buf, ' ', len);
		const char *sp2 = sp1 ? memchr(sp1+1, ' ', len - (sp1-buf) + 1) : NULL;
		return (sp1 && sp2 && (!eol || sp2<eol)) ? atoi(sp1+1) : 500;
	}
	return -EINVAL;
}

static int ppp_mainloop(struct openconnect_info *vpninfo, int dtls,
			struct keepalive_info *kai, int *timeout, int readable)
{
	int ret, magic, rsv_hdr_size;
	int work_done = 0;
	struct pkt *this;
	struct oc_ppp *ppp = vpninfo->ppp;
	int proto;

	if ((dtls ? vpninfo->dtls_fd : vpninfo->ssl_fd) == -1)
		goto do_reconnect;

	handle_state_transition(vpninfo, dtls, kai, timeout);

	/* FIXME: The poll() handling here is fairly simplistic. Actually,
	   if the SSL connection stalls it could return a WANT_WRITE error
	   on _either_ of the SSL_read() or SSL_write() calls. In that case,
	   we should probably remove POLLIN from the events we're looking for,
	   and add POLLOUT. As it is, though, it'll just chew CPU time in that
	   fairly unlikely situation, until the write backlog clears. */
	while (readable) {
		/* Some servers send us packets that are larger than
		   negotiated MTU. We reserve some extra space to
		   handle that */
		unsigned char *eh, *ph, *pp, *next;
		int receive_mtu = MAX(16384, vpninfo->ip_info.mtu);
		int len, payload_len, next_len;

		if (!vpninfo->cstp_pkt) {
			vpninfo->cstp_pkt = alloc_pkt(vpninfo, receive_mtu);
			if (!vpninfo->cstp_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				break;
			}
		}
		this = vpninfo->cstp_pkt;

		/* XX: PPP header is of variable length. We attempt to
		 * anticipate the actual length received, so we don't have to memmove
		 * the payload later. */
		rsv_hdr_size = ppp->encap_len + ppp->exp_ppp_hdr_size;

		/* This should never happen here as we should complain about it
		 * before setting ->partial_rec_size in the first place, but be
		 * paranoid. This would mean we just read zero (or negative!) */
		if (vpninfo->partial_rec_size >= receive_mtu + rsv_hdr_size) {
			vpninfo->quit_reason = "Payload exceeds MTU";
			vpn_progress(vpninfo, PRG_ERR,
				     _("PPP payload exceeds receive buffer\n"));
			return -EINVAL;
		}

		/* Load the encap header to end up with the payload where we expect it. Also,
		 * if our previous (D)TLS read contained an incomplete PPP packet, we need
		 * to append to it. */
		eh = this->data - rsv_hdr_size;
		len = ssl_nonblock_read(vpninfo, dtls, eh + vpninfo->partial_rec_size,
					receive_mtu + rsv_hdr_size - vpninfo->partial_rec_size);
		if (!len)
			break;
		if (len < 0)
			goto do_reconnect;
		len += vpninfo->partial_rec_size;
		vpninfo->partial_rec_size = 0;

		/* XX: Some protocols require us to check for an HTTP response in place
		 * of the first packet
		 */
		if (ppp->check_http_response) {
			int status = check_http_status((const char *)eh, len);
			ppp->check_http_response = 0;
		        if (status >= 0) {
				vpn_progress(vpninfo, PRG_ERR,_("Got unexpected HTTP response: %.*s\n"),
					     len, (const char *)eh);
				vpninfo->quit_reason = "Received HTTP response (not a PPP packet)";
				return (status >= 400 && status <= 499) ? -EPERM : -EINVAL;
			}
		}

	next_pkt:
		/* At this point:
		 *   eh: pointer to start of bytes-from-the-wire
		 *   len: number of bytes-from-the-wire
		 */

		if (len < (ppp->encap_len ? : 8)) {
		short_pkt:
			vpn_progress(vpninfo, PRG_DEBUG, _("Short packet received (%d bytes). Waiting for more.\n"), len);
			vpninfo->partial_rec_size = len;
			continue;
		}

		if (vpninfo->dump_http_traffic)
			dump_buf_hex(vpninfo, PRG_DEBUG, '<', eh, len);

		/* Deencapsulate from pre-PPP header */
		switch (ppp->encap) {
		case PPP_ENCAP_F5:
			magic = load_be16(eh);
			payload_len = load_be16(eh + 2);
			next = eh + 4 + payload_len;

			if (magic != 0xf500) {
			bad_encap_header:
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unexpected pre-PPP packet header for encap %d.\n"),
					     ppp->encap);
				dump_buf_hex(vpninfo, PRG_ERR, '<', eh, len);
				continue;
			}

			if (len < 4 + payload_len) {
			incomplete_pkt:
				/* We've read a partial PPP packet. Save the offset for our next read. */
				vpninfo->partial_rec_size = len;
				if (vpninfo->partial_rec_size >= receive_mtu + rsv_hdr_size) {
					vpninfo->quit_reason = "Payload exceeds MTU";
					vpn_progress(vpninfo, PRG_ERR,
						     _("PPP payload len %d exceeds receive buffer %d\n"),
						     payload_len, receive_mtu + rsv_hdr_size);
					dump_buf_hex(vpninfo, PRG_ERR, '<', eh, len);
					return -EINVAL;
				}
				vpn_progress(vpninfo, PRG_DEBUG,
					     _("PPP packet is incomplete. Received %d bytes on wire (includes %d encap) but header payload_len is %d. Waiting for more.\n"),
					     len, ppp->encap_len, payload_len);
				continue;
			}
			break;

		case PPP_ENCAP_FORTINET:
			payload_len = load_be16(eh + 4);
			magic = load_be16(eh + 2);
			next = eh + 6 + payload_len;

			if (magic != 0x5050 || (load_be16(eh) != payload_len + 6))
				goto bad_encap_header;
			if (len < 6 + payload_len)
				goto incomplete_pkt;
			break;

		case PPP_ENCAP_F5_HDLC:
		case PPP_ENCAP_RFC1662_HDLC:
			payload_len = unhdlc_in_place(vpninfo, eh + ppp->encap_len, len - ppp->encap_len, &next);
			if (payload_len < 0)
				continue; /* unhdlc_in_place already logged */
			if (vpninfo->dump_http_traffic)
				dump_buf_hex(vpninfo, PRG_TRACE, '<', eh + ppp->encap_len, payload_len);
			break;

		case PPP_ENCAP_RFC1661:
			payload_len = len;
			next = eh + payload_len;
			break;

		default:
			vpn_progress(vpninfo, PRG_ERR, _("Invalid PPP encapsulation\n"));
			vpninfo->quit_reason = "Invalid encapsulation";
			return -EINVAL;
		}

		ph = eh + ppp->encap_len;
		next_len = eh + len - next;
		if (next_len)
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Packet contains %d bytes after payload. Assuming concatenated packet.\n"),
				     next_len);

		/* At this point:
		 *   ph: pointer to start of PPP header
		 *   payload_len: number of bytes in PPP packet
		 *
		 *   Packet has been un-HDLC'ed, if necessary, and checked for incompleteness
		 *
		 *   next: pointer to next concatenated packet
		 *   next_len: its length
		 */

		/* check PPP header and extract protocol */
		pp = ph;
		if (pp[0] == 0xff && pp[1] == 0x03)
			/* XX: Neither byte is a possible proto value (https://tools.ietf.org/html/rfc1661#section-2) */
			pp += 2;
		proto = *pp++;
		if (!(proto & 1)) {
			proto <<= 8;
			proto += *pp++;
		}
		payload_len -= pp - ph;

		/* At this point:
		 *   pp: pointer to start of PPP payload
		 *   payload_len: number of bytes in PPP *payload*
		 */

		kai->last_rx = time(NULL);

		switch (proto) {
		case PPP_LCP:
		case PPP_IPCP:
		case PPP_IP6CP:
			if ((proto == PPP_IPCP && !ppp->want_ipv4) || (proto == PPP_IP6CP && !ppp->want_ipv6))
				goto reject;
			if (payload_len < 4)
				goto short_pkt;
			if ((ret = handle_config_packet(vpninfo, proto, pp, payload_len)) < 0)
				return ret;
			else if ((ret = handle_state_transition(vpninfo, dtls, kai, timeout)) < 0)
				return ret;
			break;

		case PPP_IP:
		case PPP_IP6:
			if (ppp->ppp_state != PPPS_NETWORK) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Unexpected IPv%d packet in PPP state %s.\n"),
					     (proto == PPP_IP6 ? 6 : 4), ppps_names[ppp->ppp_state]);
				dump_buf_hex(vpninfo, PRG_ERR, '<', pp, payload_len);
			} else {
				vpn_progress(vpninfo, PRG_TRACE,
					     _("Received IPv%d data packet of %d bytes over %s\n"),
					     proto == PPP_IP6 ? 6 : 4, payload_len,
					     dtls ? "DTLS" : "TLS");

				if (pp != this->data) {
					vpn_progress(vpninfo, PRG_TRACE,
						     _("Expected %d PPP header bytes but got %ld, shifting payload.\n"),
						     ppp->exp_ppp_hdr_size, (long)(pp - ph));
					/* Save it for next time */
					ppp->exp_ppp_hdr_size = pp - ph;
					/* XX: If PPP header was SMALLER than expected, we could
					 * be moving a huge packet past the allocated buffer. */
					memmove(this->data, pp, payload_len + next_len);
					next -= (pp - this->data);
				}

				this->len = payload_len;
				queue_packet(&vpninfo->incoming_queue, this);
				/* XX: keep reference in this to build next packet */
				if (this == vpninfo->cstp_pkt)
					vpninfo->cstp_pkt = NULL;
				work_done = 1;
			}
			break;

		default:
		reject:
			vpn_progress(vpninfo, PRG_ERR,
				     _("Sending Protocol-Reject for %s. Payload:\n"),
				     proto_names(proto));
			dump_buf_hex(vpninfo, PRG_ERR, '>', pp, payload_len);

			/* The rejected protocol MUST occupy 2 bytes prior to the rejected packet contents.
			 * (https://tools.ietf.org/html/rfc1661#section-5.7). We can clobber these bytes
			 * because we are throwing out this packet anyway.
			 *
			 * The rejected packet body is fully included, unless it must be truncated to the
			 * peer's MRU (taking into account the preceding 4 bytes for PPP header, 4 for LCP
			 * config header, and 2 for rejected proto.
			 */
			store_be16(pp - 2, proto);
			if ((ret = queue_config_packet(vpninfo, PPP_LCP, ++ppp->lcp.id, PROTREJ,
						       MIN(payload_len + 2, (vpninfo->ip_info.mtu ?: 256) - 10),
						       pp - 2)) < 0)
				return ret;
		}

		if (next_len) {
			/* Need to copy to a new struct pkt, not just move pointers, because data
			 * packets will get stolen for incoming queue and free()'d. Allocate a
			 * full sized packet so it can remain in vpninfo->cstp_pkt and be reused
			 * for receiving the next packet, if it's something other than data and
			 * doesn't get queued and freed. */
			this = vpninfo->cstp_pkt = alloc_pkt(vpninfo, receive_mtu);
			if (!this)
				return -ENOMEM;
			eh = this->data - rsv_hdr_size;
			memcpy(eh, next, next_len);
			len = next_len;
			goto next_pkt;
		}
	}

	/* If SSL_write() fails we are expected to try again. With exactly
	   the same data, at exactly the same location. So we keep the
	   packet we had before.... */
	if ((this = vpninfo->current_ssl_pkt)) {
	handle_outgoing:
		kai->last_tx = time(NULL);
		if (dtls)
			unmonitor_write_fd(vpninfo, dtls);
		else
			unmonitor_write_fd(vpninfo, ssl);

		ret = ssl_nonblock_write(vpninfo, dtls, this->data - this->ppp.hlen, this->len + this->ppp.hlen);
		if (ret < 0)
			goto do_reconnect;
		else if (!ret) {
			/* -EAGAIN: ssl_nonblock_write() will have added the SSL
			   fd to ->select_wfds if appropriate, so we can just
			   return and wait. Unless it's been stalled for so long
			   that DPD kicks in and we kill the connection. */
			switch (ka_stalled_action(kai, timeout)) {
			case KA_DPD_DEAD:
				goto peer_dead;
			case KA_REKEY:
				goto do_reconnect;
			case KA_NONE:
				return work_done;
			default:
				/* This can never happen because ka_stalled_action()
				 * always returns one of the above. */
				break;
			}
		}

		if (ret != this->len + this->ppp.hlen) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSL wrote too few bytes! Asked for %d, sent %d\n"),
				     this->len + this->ppp.hlen, ret);
			vpninfo->quit_reason = "Internal error";
			return 1;
		}

		free_pkt(vpninfo, this);
		vpninfo->current_ssl_pkt = NULL;
	}

	switch (keepalive_action(kai, timeout)) {
	case KA_DPD_DEAD:
	peer_dead:
		vpn_progress(vpninfo, PRG_ERR,
			     _("Detected dead peer!\n"));
		/* fall through */
	case KA_REKEY:
	do_reconnect:
		if (dtls) {
			/* This leaves it in state DTLS_SLEEPING, and will allow
			 * the protocol to handle any magic required to reopen it. */
			dtls_close(vpninfo);
		} else {
			if (ppp->ppp_state == PPPS_ESTABLISH) {
				vpn_progress(vpninfo, PRG_ERR, _("Failed to establish PPP\n"));
				vpninfo->quit_reason = "Failed to establish PPP";
				return -EPERM;
			}
			ret = ssl_reconnect(vpninfo);
			if (ret) {
				vpn_progress(vpninfo, PRG_ERR, _("Reconnect failed\n"));
				vpninfo->quit_reason = "PPP reconnect failed";
				return ret;
			}
		}
		return 1;

	case KA_KEEPALIVE:
		/* No need to send an explicit keepalive
		   if we have real data to send */
		if (vpninfo->tcp_control_queue.head ||
		    (ppp->ppp_state == PPPS_NETWORK && vpninfo->outgoing_queue.head))
			break;
		vpn_progress(vpninfo, PRG_DEBUG, _("Send PPP discard request as keepalive\n"));
		queue_config_packet(vpninfo, PPP_LCP, ++ppp->lcp.id, DISCREQ, 0, NULL);
		break;
	case KA_DPD:
		vpn_progress(vpninfo, PRG_DEBUG, _("Send PPP echo request as DPD\n"));
		queue_config_packet(vpninfo, PPP_LCP, ++ppp->lcp.id, ECHOREQ, 4, &ppp->out_lcp_magic);
	}

	/* Service control queue; also, outgoing packet queue, if no DTLS  */
	if ((this = vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->tcp_control_queue))) {
		/* XX: We pre-stash the PPP protocol field in the header for control packets */
		proto = this->ppp.proto;
		handle_state_transition(vpninfo, dtls, kai, timeout);
	} else if (ppp->ppp_state == PPPS_NETWORK &&
		   (this = vpninfo->current_ssl_pkt = dequeue_packet(&vpninfo->outgoing_queue))) {
		/* XX: Set protocol for IP packets */
		proto = (this->len && (this->data[0] & 0xf0) == 0x60) ? PPP_IP6 : PPP_IP;
	}

	/* XX: Need 'this = vpninfo->current_ssl_pkt' here, otherwise sanitizer complains about
	 * handle_state_transition() potentially freeing vpninfo->current_ssl_pkt.
	 *
	 * That only occurs in the PPPS_DEAD branch, which is unreachable after the first
	 * invocation, but how to convince it of that?
	 */
	if ((this = vpninfo->current_ssl_pkt)) {
		unsigned char *eh;
		const char *lcp = NULL;
		int id;

		switch (proto) {
		case PPP_LCP:
		case PPP_IPCP:
		case PPP_IP6CP:
			lcp = lcp_names[this->data[0]];
			id = this->data[1];
		}

		/* Add PPP header */
		add_ppp_header(this, ppp, proto);

		/* XX: Copy the whole packet into new HDLC'ed packet if needed */
		if (ppp->hdlc) {
			/* XX: use worst-case escaping for LCP */
			this = hdlc_into_new_pkt(vpninfo, this,
						 proto == PPP_LCP ? ASYNCMAP_LCP : ppp->out_asyncmap);
			if (!this)
				return 1; /* XX */
			free_pkt(vpninfo, vpninfo->current_ssl_pkt);
			vpninfo->current_ssl_pkt = this;
		}

		/* Encapsulate into pre-PPP header */
		eh = this->data - this->ppp.hlen - ppp->encap_len;
		switch (ppp->encap) {
		case PPP_ENCAP_F5:
			store_be16(eh, 0xf500);
			store_be16(eh + 2, this->len + this->ppp.hlen);
			break;
		case PPP_ENCAP_FORTINET:
			/* XX: header contains both TOTAL bytes-on-wire, and (bytes-on-wire excluding this header)  */
			store_be16(eh, this->len + this->ppp.hlen + 6);
			store_be16(eh + 2, 0x5050);
			store_be16(eh + 4, this->len + this->ppp.hlen);
			break;
		}
		this->ppp.hlen += ppp->encap_len;

		if (lcp)
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Sending PPP %s %s packet over %s (id %d, %d bytes total)\n"),
				     proto_names(proto), lcp,
				     dtls ? "DTLS" : "TLS",
				     id, this->len + this->ppp.hlen);
		else
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Sending PPP %s packet over %s (%d bytes total)\n"),
				     proto_names(proto),
				     dtls ? "DTLS" : "TLS",
				     this->len + this->ppp.hlen);

		if (vpninfo->dump_http_traffic)
			dump_buf_hex(vpninfo, PRG_TRACE, '>', this->data - this->ppp.hlen, this->len + this->ppp.hlen);

		vpninfo->current_ssl_pkt = this;
		goto handle_outgoing;
	}

	/* Work is not done if we just got rid of packets off the queue */
	return work_done;
}

/* This function in designed to be called from a PPP protocol's
 * ->tcp_connect() function, to allow it to determine whether it
 * should establish the PPP connection immediately or wait for
 * DTLS to have a turn. */
int ppp_tcp_should_connect(struct openconnect_info *vpninfo)
{
	switch (vpninfo->dtls_state) {
	case DTLS_DISABLED:
	case DTLS_NOSECRET:
		/* No DTLS here. Connect PPP immediately over TCP */
		return 1;

	case DTLS_SECRET:
		/* When openconnect_make_cstp_connection() is first called,
		 * before openconnect_setup_dtls() is called, the state is
		 * DTLS_SECRET. In that case, defer the connection to allow
		 * DTLS to have a turn. */
		return 0;

	case DTLS_SLEEPING:
		/* On a DTLS connection timeout, the TCP mainloop calls
		 * dtls_close() before calling this function to reconnect,
		 * so establish the PPP immediately over PPP.
		 *
		 * (After a connection pause, DTLS_SLEEPING is also seen but
		 * the UDP mainloop runs first and the state gets changed
		 * to DTLS_CONNECTING before the TCP mainloop runs, so that
		 * variant of DTLS_SLEEPING is never seen here.) */
		return 1;

	case DTLS_CONNECTING:
		/* After pause/SIGUSR2, the UDP mainloop will run first and
		 * shifts from DTLS_SLEEPING to DTLS_CONNECTING state, before
		 * the TCP mainloop invokes this function. So defer the
		 * connection to allow DTLS to connect. */
		return 0;

	default:
	case DTLS_CONNECTED:
	case DTLS_ESTABLISHED:
		/* These should never be seen. */
		vpn_progress(vpninfo, PRG_ERR,
			     _("PPP connect called with invalid DTLS state %d\n"),
			     vpninfo->dtls_state);
		return -EIO;
	}
}

int ppp_start_tcp_mainloop(struct openconnect_info *vpninfo)
{
	int timeout = 0;

	return ppp_mainloop(vpninfo, 0, &vpninfo->ssl_times, &timeout, 1);
}

int ppp_tcp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	/* If we're still attempting DTLS, do nothing yet. */
	switch (vpninfo->dtls_state) {
	case DTLS_ESTABLISHED:
		if (vpninfo->ssl_fd != -1) {
			openconnect_close_https(vpninfo, 0); /* don't keep stale HTTPS socket */
			vpn_progress(vpninfo, PRG_INFO,
				     _("DTLS tunnel connected; exiting HTTPS mainloop.\n"));
		}

		/* Now that we are connected, let's ensure timeout is less than
		 * or equal to DTLS DPD/keepalive else we might over sleep, e.g.
		 * if timeout is set to DTLS attempt period from DTLS mainloop,
		 * and falsely detect dead peer. */
		if (vpninfo->dtls_times.dpd)
			if (*timeout > vpninfo->dtls_times.dpd * 1000)
				*timeout = vpninfo->dtls_times.dpd * 1000;

		return 0;

	case DTLS_CONNECTED:
	case DTLS_CONNECTING:
	case DTLS_SECRET:
		if (vpninfo->ppp->ppp_state == PPPS_DEAD) {
			/* Allow 5 seconds after configuration for DTLS to start */
			if (!ka_check_deadline(timeout, time(NULL), vpninfo->new_dtls_started + 5)) {
				vpninfo->delay_tunnel_reason = "awaiting PPP DTLS connection";
				return 0;
			}
			/* It'll try again in a while, but we want it to be in DTLS_SLEEPING
			 * so that the tcp_connect() function actually establishes the PPP
			 * over TCP. */
			dtls_close(vpninfo);
		}

		/* Fall through */
	case DTLS_SLEEPING:
		/* Should only be seen by the mainloop if DTLS actually *failed*
		 * (which includes timing out). */
		if (vpninfo->ppp->ppp_state == PPPS_DEAD) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to connect DTLS tunnel; using HTTPS instead (state %d).\n"),
				     vpninfo->dtls_state);
		}
		/* Fall through */
	case DTLS_NOSECRET:
	case DTLS_DISABLED:
		/* The state is PPPS_DEAD until the first time ppp_tcp_mainloop()
		 * gets invoked. When f5_connect() actually establishes the tunnel,
		 * it does so to start the PPP state machine for the TCP connection.
		 */
		if (vpninfo->ssl_fd != -1 && vpninfo->ppp->ppp_state != PPPS_DEAD)
			return ppp_mainloop(vpninfo, 0, &vpninfo->ssl_times, timeout, readable);

		/* This will call *back* into the protocol's ->tcp_connect()
		 * but this time DTLS is disabled so it'll actually establish
		 * the connection there. We want to make use of the retry
		 * handling logic in ssl_reconnect() in the cases where it
		 * doesn't succeed immediately.
		 *
		 * If the connection is already open, try using it directly
		 * first, before falling back to a full ssl_reconnect().
		 */
		if (vpninfo->ssl_fd == -1 || vpninfo->proto->tcp_connect(vpninfo)) {
			int ret = ssl_reconnect(vpninfo);
			if (ret) {
				vpn_progress(vpninfo, PRG_ERR, _("Establishing PPP tunnel over TLS failed\n"));
				vpninfo->quit_reason = "PPP TLS connect failed";
				return ret;
			}
			vpninfo->delay_tunnel_reason = "DTLS connection pending";
			return 1;
		}
		vpninfo->delay_tunnel_reason = "DTLS connection pending";
		return 1;
	}

	vpn_progress(vpninfo, PRG_ERR, _("Invalid DTLS state %d\n"), vpninfo->dtls_state);
	vpninfo->quit_reason = "Invalid DTLS state";
	return 1;
}

int ppp_udp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable)
{
	int work_done = 0;
	time_t now = time(NULL);

	switch(vpninfo->dtls_state) {
	case DTLS_CONNECTING:
		if (vpninfo->ppp->ppp_state == PPPS_DEAD)
			vpninfo->delay_tunnel_reason = "DTLS connecting";

		dtls_try_handshake(vpninfo, timeout);
		if (vpninfo->dtls_state == DTLS_CONNECTED)
			goto newly_connected;
		return 0;

	case DTLS_CONNECTED:
		/* First, see if there's a response for us. */
		while(readable) {
			int receive_mtu = MAX(16384, vpninfo->ip_info.mtu);
			int len;

			/* cstp_pkt is used by PPP over either transport, and TCP
			 * may be in active use while we attempt to connect DTLS.
			 * So use vpninfo->dtls_pkt for this. */
			if (!vpninfo->dtls_pkt)
				vpninfo->dtls_pkt = alloc_pkt(vpninfo, receive_mtu);
			if (!vpninfo->dtls_pkt) {
				vpn_progress(vpninfo, PRG_ERR, _("Allocation failed\n"));
				dtls_close(vpninfo);
				vpninfo->dtls_state = DTLS_DISABLED;
				return 1;
			}

			struct pkt *this =  vpninfo->dtls_pkt;
			len = ssl_nonblock_read(vpninfo, 1, this->data, receive_mtu);
			if (!len)
				break;
			if (len < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to receive authentication response from DTLS\n"));
				dtls_close(vpninfo);
				return 1;
			}

			this->len = len;

			if (vpninfo->dump_http_traffic)
				dump_buf_hex(vpninfo, PRG_DEBUG, '<', this->data, len);

			int ret = vpninfo->proto->udp_catch_probe(vpninfo, this);
			if (ret < 0) {
				dtls_close(vpninfo);
				return 1;
			} else if (ret > 0) {
				vpninfo->dtls_state = DTLS_ESTABLISHED;
				vpninfo->dtls_pkt = NULL;
				free_pkt(vpninfo, this);

				/* We are going to take over the PPP now; reset the TCP one */
				ret = ppp_reset(vpninfo);
				if (ret) {
					/* This should never happen */
					vpn_progress(vpninfo, PRG_ERR, _("Reset PPP failed\n"));
					vpninfo->quit_reason = "PPP DTLS connect failed";
					return ret;
				}
				goto established;
			}
			/* This is the ret==0 case, where the packet was recognised
			 * neither as a success nor failure. In that case it could
			 * be a PPP frame which has been received out of order and
			 * made it to us before the OK response. Drop it and keep
			 * waiting. */
		}

		/* On first connection, the TCP mainloop will give us five seconds
		 * to do the whole exchange and reach DTLS_ESTABLISHED before it
		 * gives up and connects over TCP instead. But for opportunistic
		 * attempts to "upgrade" to DTLS later, it won't get involved.
		 * We still want to time out and give up on this DTLS connection
		 * if we failed to authenticate though. So do it here too. */
		if (ka_check_deadline(timeout, now, vpninfo->dtls_times.last_rekey + 5)) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("Failed to authenticate DTLS session\n"));
			dtls_close(vpninfo);
			return 1;
		}

		/* Resend the connect request every second */
		if (ka_check_deadline(timeout, now, vpninfo->dtls_times.last_tx + 1)) {
		newly_connected:
			if (buf_error(vpninfo->ppp_dtls_connect_req)) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Error creating connect request for DTLS session\n"));
				dtls_close(vpninfo);
				vpninfo->dtls_state = DTLS_DISABLED;
				return 1;
			}

			if (vpninfo->dump_http_traffic)
				dump_buf_hex(vpninfo, PRG_DEBUG, '>',
					     (void *)vpninfo->ppp_dtls_connect_req->data,
					     vpninfo->ppp_dtls_connect_req->pos);

			int ret = ssl_nonblock_write(vpninfo, 1,
						     vpninfo->ppp_dtls_connect_req->data,
						     vpninfo->ppp_dtls_connect_req->pos);
			if (ret < 0) {
				vpn_progress(vpninfo, PRG_ERR,
					     _("Failed to write connect request to DTLS session\n"));
				dtls_close(vpninfo);
				vpninfo->dtls_state = DTLS_DISABLED;
				return 1;
			}
			vpninfo->dtls_times.last_tx = now;
		}

		if (vpninfo->ppp->ppp_state == PPPS_DEAD)
			vpninfo->delay_tunnel_reason = "DTLS establishing";

		return 0;

	case DTLS_ESTABLISHED:
	established:
		work_done = ppp_mainloop(vpninfo, 1, &vpninfo->dtls_times, timeout, readable);
		if (vpninfo->dtls_state != DTLS_SLEEPING)
			break;

		/* Fall through */
	case DTLS_SLEEPING:
		/* If the SSL connection isn't open, that must mean we've been paused
		 * and resumed. So reconnect immediately regardless of whether we'd
		 * just done so, *and* reset the PPP state so that the TCP mainloop
		 * doesn't get confused. */
		if (vpninfo->ssl_fd == -1) {
			ppp_reset(vpninfo);
			if (now < vpninfo->new_dtls_started + vpninfo->dtls_attempt_period)
				now = vpninfo->new_dtls_started + vpninfo->dtls_attempt_period;
		}

		if (ka_check_deadline(timeout, now, vpninfo->new_dtls_started + vpninfo->dtls_attempt_period)) {
			vpn_progress(vpninfo, PRG_DEBUG, _("Attempt new DTLS connection\n"));
			dtls_reconnect(vpninfo, timeout);
			work_done = 1;
		}
	}

	return work_done;
}
