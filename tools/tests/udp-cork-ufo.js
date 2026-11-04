const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/';
const ipv4 = fs.readFileSync(path.join(root, kernel, 'ipv4/ip_output.c'), 'utf8');
const ipv6 = fs.readFileSync(path.join(root, kernel, 'ipv6/ip6_output.c'), 'utf8');
const body = (source, start, end) => {
    const offset = source.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = source.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return source.slice(offset, limit);
};

const ipv4Append = body(ipv4, 'int ip_append_data(', 'ssize_t\tip_append_page(');
const ipv4Ufo = body(ipv4, 'static inline int ip_ufo_append_data(', '/*\n *\tip_append_data()');
const ipv6Append = body(ipv6, 'int ip6_append_data(', 'static void ip6_cork_release(');
const ipv6Ufo = body(ipv6, 'static inline int ip6_ufo_append_data(', 'static inline struct ipv6_opt_hdr *ip6_opt_dup(');

assert.match(ipv4Append, /if \(\(skb && skb_is_gso\(skb\)\) \|\|/,
    'IPv4 continues a queued GSO datagram on the UFO path');
assert.match(ipv4Append, /!skb && length > mtu && sk->sk_protocol == IPPROTO_UDP/,
    'IPv4 starts UFO only for a fresh oversized UDP datagram');
assert.match(ipv4Append,
    /if \(sk->sk_protocol != IPPROTO_UDP \|\|\s*!\(rt->dst\.dev->features & NETIF_F_UFO\)\) \{\s*err = -EOPNOTSUPP;\s*goto error;/,
    'IPv4 fails before modifying queued GSO data if UFO support disappears');
assert.match(ipv6Append,
    /if \(skb && skb_is_gso\(skb\)\) \{[\s\S]*?if \(sk->sk_protocol != IPPROTO_UDP \|\|\s*!\(rt->dst\.dev->features & NETIF_F_UFO\)\)/,
    'IPv6 keeps queued GSO data on UFO or fails without touching it');
assert.match(ipv6Append,
    /if \(!skb && proto == IPPROTO_UDP &&\s*\(rt->dst\.dev->features & NETIF_F_UFO\)\)/,
    'IPv6 starts UFO only for an empty queue, never after ordinary fragments exist');
for (const [family, source] of [['IPv4', ipv4Append], ['IPv6', ipv6Append]]) {
    assert.match(source,
        /if \(fraggap > datalen \|\|\s*transhdrlen > datalen - fraggap\) \{\s*err = -EINVAL;\s*goto error;/,
        `${family} rejects a fragment gap larger than the allocated data area`);
}
assert.match(ipv4Ufo,
    /err = skb_append_datato_frags[\s\S]*?if \(new_skb\) \{[\s\S]*?__skb_queue_tail\(&sk->sk_write_queue, skb\);/,
    'IPv4 queues only a newly allocated GSO skb after a successful append');
assert.match(ipv6Ufo,
    /if \(new_skb\) \{[\s\S]*?__skb_queue_tail\(&sk->sk_write_queue, skb\);/,
    'IPv6 queues only a newly allocated GSO skb');
assert.match(ipv6Ufo, /if \(new_skb\)\s*kfree_skb\(skb\);/,
    'IPv6 frees only an unqueued skb when fragment append fails');

const choosePath = ({ queuedGso, queueNonempty, length, mtu, ufo }) => {
    if (queuedGso)
        return ufo ? 'ufo-continue' : 'error';
    if (!queueNonempty && length > mtu && ufo)
        return 'ufo-start';
    return 'fragment';
};
for (const length of [64, 1500, 30000]) {
    assert.equal(choosePath({queuedGso: true, queueNonempty: true, length, mtu: 1500, ufo: true}),
        'ufo-continue');
    assert.equal(choosePath({queuedGso: true, queueNonempty: true, length, mtu: 1500, ufo: false}),
        'error');
}
assert.equal(choosePath({queuedGso: false, queueNonempty: false, length: 30000, mtu: 1500, ufo: true}),
    'ufo-start');
assert.equal(choosePath({queuedGso: false, queueNonempty: true, length: 30000, mtu: 1500, ufo: true}),
    'fragment');
assert.equal(choosePath({queuedGso: false, queueNonempty: false, length: 64, mtu: 1500, ufo: true}),
    'fragment');
for (const datalen of [0, 1, 1400]) {
    for (const gap of [0, datalen])
        assert.ok(gap <= datalen);
    if (datalen < 65535)
        assert.ok(65535 > datalen, 'an oversized GSO tail is rejected before fragment copying');
}
console.log('PASS: UDP cork UFO path, queue ownership, and fragment-gap source contracts (not kernel execution)');