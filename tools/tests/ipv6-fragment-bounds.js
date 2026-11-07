const assert = require('assert');
const fs = require('fs');

const root = `${__dirname}/../..`;
const read = (path) => fs.readFileSync(`${root}/${path}`, 'utf8');
const output = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/ip6_output.c');
const udp = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/udp.c');
const inet6 = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/af_inet6.c');
const xfrmTransport = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/xfrm6_mode_transport.c');
const xfrmRo = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/xfrm6_mode_ro.c');

const parser = output.match(/int ip6_find_1stfragopt\([\s\S]*?\n}\n/);
assert(parser, 'fragment-option parser exists');
assert.match(parser[0], /unsigned int offset/);
assert.match(parser[0], /offset \+ sizeof\(struct ipv6_opt_hdr\) > packet_len/);
assert.match(parser[0], /len >= IPV6_MAXPLEN - offset/);
assert.match(parser[0], /return -EINVAL;/);

const fragmenter = output.match(/static int ip6_fragment\([^;]+\)\n\{[\s\S]*?\n}\n/);
assert(fragmenter, 'IPv6 fragmenter exists');
assert.match(fragmenter[0], /if \(hlen < 0\)[\s\S]*?err = hlen;[\s\S]*?goto fail;/);
assert.match(fragmenter[0], /hlen >= skb->len[\s\S]*?mtu -= hlen \+ sizeof\(struct frag_hdr\);/);
assert.match(fragmenter[0], /hlen >= mtu - sizeof\(struct frag_hdr\)/);
assert.match(fragmenter[0], /mtu < 8 && skb->len - hlen > mtu[\s\S]*?goto fail;/);

assert.match(udp, /int unfrag_ip6hlen;[\s\S]*?unfrag_ip6hlen = ip6_find_1stfragopt\(skb, &prevhdr\);[\s\S]*?if \(unfrag_ip6hlen < 0\)[\s\S]*?ERR_PTR\(unfrag_ip6hlen\)/);
assert.match(inet6, /int unfrag_ip6hlen;[\s\S]*?unfrag_ip6hlen = ip6_find_1stfragopt\(skb, &prevhdr\);[\s\S]*?if \(unfrag_ip6hlen < 0\)[\s\S]*?return ERR_PTR\(unfrag_ip6hlen\);/);
assert.match(xfrmTransport, /hdr_len = x->type->hdr_offset\(x, skb, &prevhdr\);[\s\S]*?if \(hdr_len < 0\)[\s\S]*?return hdr_len;/);
assert.match(xfrmRo, /hdr_len = x->type->hdr_offset\(x, skb, &prevhdr\);[\s\S]*?if \(hdr_len < 0\)[\s\S]*?return hdr_len;/);

console.log('IPv6 fragment bounds source contracts passed');