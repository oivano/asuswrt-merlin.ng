#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/cryptohash.h>
#include <linux/module.h>
#include <linux/cache.h>
#include <linux/random.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>
#include <linux/string.h>

static u32 net_secret[MD5_MESSAGE_BYTES / 4] ____cacheline_aligned;

static int __init net_secret_init(void)
{
	get_random_bytes(net_secret, sizeof(net_secret));
	return 0;
}
late_initcall(net_secret_init);

static u32 seq_scale(u32 seq)
{
	return seq + (ktime_to_ns(ktime_get_real()) >> 6);
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
__u32 secure_tcpv6_sequence_number(__be32 *saddr, __be32 *daddr,
				   __be16 sport, __be16 dport)
{
	u32 secret[MD5_MESSAGE_BYTES / 4];
	u32 hash[MD5_DIGEST_WORDS];
	u32 i;

	memcpy(hash, saddr, 16);
	for (i = 0; i < 4; i++)
		secret[i] = net_secret[i] + daddr[i];
	secret[4] = net_secret[4] +
		(((__force u16)sport << 16) + (__force u16)dport);
	for (i = 5; i < MD5_MESSAGE_BYTES / 4; i++)
		secret[i] = net_secret[i];

	md5_transform(hash, secret);
	return seq_scale(hash[0]);
}
EXPORT_SYMBOL(secure_tcpv6_sequence_number);
#endif

#ifdef CONFIG_INET
__u32 secure_tcp_sequence_number(__be32 saddr, __be32 daddr,
				 __be16 sport, __be16 dport)
{
	u32 hash[MD5_DIGEST_WORDS];

	hash[0] = (__force u32)saddr;
	hash[1] = (__force u32)daddr;
	hash[2] = ((__force u16)sport << 16) + (__force u16)dport;
	hash[3] = net_secret[15];

	md5_transform(hash, net_secret);
	return seq_scale(hash[0]);
}
#endif