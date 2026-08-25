#ifndef _NETFILTER_NF_NAT_H
#define _NETFILTER_NF_NAT_H

#include <linux/netfilter.h>
#include <linux/netfilter/nf_conntrack_tuple_common.h>

#define NF_NAT_RANGE_MAP_IPS            1
#define NF_NAT_RANGE_PROTO_SPECIFIED    2
#define NF_NAT_RANGE_PROTO_RANDOM       4
#define NF_NAT_RANGE_PERSISTENT         8
#define IP_NAT_RANGE_MAP_IPS            NF_NAT_RANGE_MAP_IPS
#define IP_NAT_RANGE_PROTO_SPECIFIED    NF_NAT_RANGE_PROTO_SPECIFIED
#define IP_NAT_RANGE_PROTO_RANDOM       NF_NAT_RANGE_PROTO_RANDOM
#define IP_NAT_RANGE_PERSISTENT         NF_NAT_RANGE_PERSISTENT
#define IP_NAT_RANGE_PROTO_PSID         (1 << 7)

struct nf_nat_ipv4_range {
	unsigned int                    flags;
	__be32                          min_ip;
	__be32                          max_ip;
	union nf_conntrack_man_proto    min;
	union nf_conntrack_man_proto    max;
};

struct nf_nat_ipv4_multi_range_compat {
	unsigned int                    rangesize;
	struct nf_nat_ipv4_range        range[1];
};

#define nf_nat_multi_range nf_nat_ipv4_multi_range_compat

struct nf_nat_range {
	unsigned int                    flags;
	union nf_inet_addr              min_addr;
	union nf_inet_addr              max_addr;
	union nf_conntrack_man_proto    min_proto;
	union nf_conntrack_man_proto    max_proto;
};

#endif /* _NETFILTER_NF_NAT_H */