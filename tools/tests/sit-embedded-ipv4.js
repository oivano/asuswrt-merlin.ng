const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/sit.c'), 'utf8');

const mapStart = source.indexOf('static inline int ipip6_addr_to_4(');
const mapEnd = source.indexOf('\nstatic inline int ipip6_tunnel_rcv_check', mapStart);
assert.notEqual(mapStart, -1);
assert.notEqual(mapEnd, -1);
const mapper = source.slice(mapStart, mapEnd);
assert.match(mapper, /ipv6_prefix_equal\(v6dst, &tunnel->ip6rd\.prefix/);
assert.match(mapper, /v6dst->s6_addr16\[0\] != htons\(0x2002\)/);
assert.match(mapper, /\*dst = tunnel->ip6rd\.relay_prefix \| htonl\(d\)/);
assert.match(mapper, /memcpy\(dst, &v6dst->s6_addr16\[1\], 4\)/);
assert.match(mapper, /return 1;/);

const checkStart = mapEnd + 1;
const checkEnd = source.indexOf('\nstatic int ipip6_rcv(', checkStart);
assert.notEqual(checkEnd, -1);
const receiveCheck = source.slice(checkStart, checkEnd);
assert.match(receiveCheck, /IFF_POINTOPOINT/);
assert.match(receiveCheck, /IFF_ISATAP/);
assert.match(receiveCheck,
    /ipip6_addr_to_4\(&ipv6h->saddr, tunnel, &embedded\)[\s\S]*?embedded != iph->saddr/);
assert.match(receiveCheck,
    /ipip6_addr_to_4\(&ipv6h->daddr, tunnel, &embedded\)[\s\S]*?embedded != iph->daddr/);

const receiveStart = source.indexOf('static int ipip6_rcv(');
const receiveEnd = source.indexOf('\n/*\n * Returns the embedded IPv4 address', receiveStart);
assert.notEqual(receiveStart, -1);
assert.notEqual(receiveEnd, -1);
const receive = source.slice(receiveStart, receiveEnd);
assert.match(receive,
    /if \(!ipip6_tunnel_rcv_check\(skb, iph, tunnel\)\) \{\s*tunnel->dev->stats\.rx_errors\+\+;[\s\S]*?kfree_skb\(skb\);[\s\S]*?return 0;\s*\}[\s\S]*?skb_tunnel_rx/);

function receiveAllowed({ pointToPoint = false, isatap = false, source, destination,
    outerSource, outerDestination }) {
    if (pointToPoint || isatap)
        return true;
    if (source.mapped && source.ipv4 !== outerSource)
        return false;
    if (destination.mapped && destination.ipv4 !== outerDestination)
        return false;
    return true;
}

const mapped = (ipv4) => ({ mapped: true, ipv4 });
const native = { mapped: false, ipv4: null };
assert.equal(receiveAllowed({
    source: mapped('198.51.100.10'), destination: native,
    outerSource: '198.51.100.10', outerDestination: '192.0.2.1'
}), true,
    'matching embedded source is accepted');
assert.equal(receiveAllowed({
    source: mapped('198.51.100.11'), destination: native,
    outerSource: '198.51.100.10', outerDestination: '192.0.2.1'
}), false,
    'spoofed embedded source is rejected');
assert.equal(receiveAllowed({
    source: native, destination: mapped('198.51.100.12'),
    outerSource: '198.51.100.10', outerDestination: '192.0.2.1'
}), false,
    'mismatched embedded destination is rejected');
assert.equal(receiveAllowed({
    source: mapped('0.0.0.0'), destination: native,
    outerSource: '198.51.100.10', outerDestination: '192.0.2.1'
}), false,
    'a zero-valued embedded IPv4 address remains a mapped address');
assert.equal(receiveAllowed({
    source: native, destination: native,
    outerSource: '198.51.100.10', outerDestination: '192.0.2.1'
}), true,
    'non-6rd/6to4 addresses are unchanged');
assert.equal(receiveAllowed({
    pointToPoint: true, source: mapped('198.51.100.11'),
    destination: mapped('198.51.100.12'), outerSource: '198.51.100.10',
    outerDestination: '192.0.2.1'
}), true, 'fixed-peer 6in4 is unchanged');
assert.equal(receiveAllowed({
    isatap: true, source: mapped('198.51.100.11'),
    destination: native, outerSource: '198.51.100.10', outerDestination: '192.0.2.1'
}),
    true, 'ISATAP keeps its existing validation path');

console.log('PASS: SIT embedded-IPv4 receive-check source/model cases; not compiled-kernel execution');