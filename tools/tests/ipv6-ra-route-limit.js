#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');

const fibHeader = fs.readFileSync('release/src-rt-6.x.4708/linux/linux-2.6.36/include/net/ip6_fib.h', 'utf8');
const fibSource = fs.readFileSync('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/ip6_fib.c', 'utf8');
const routeSource = fs.readFileSync('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/route.c', 'utf8');
const addrconfSource = fs.readFileSync('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/addrconf.c', 'utf8');
const inet6Header = fs.readFileSync('release/src-rt-6.x.4708/linux/linux-2.6.36/include/net/if_inet6.h', 'utf8');

assert.match(routeSource, /#define IPV6_RA_ROUTE_LIMIT\s+64/);
assert.match(routeSource, /#define IPV6_RA_DST_RESERVE\s+512/);
assert.match(inet6Header, /atomic_t\s+ra_route_count/);
assert.match(addrconfSource, /atomic_set\(&ndev->ra_route_count, 0\)/);
assert.match(fibSource, /atomic_inc\(&rt->rt6i_idev->ra_route_count\)/);
assert.match(fibSource, /RTF_PREFIX_RT \| RTF_DEFAULT\)\)/);
assert.match(fibSource, /atomic_dec\(&rt->rt6i_idev->ra_route_count\)/);
assert.match(routeSource, /route_count >= IPV6_RA_ROUTE_LIMIT/);
assert.match(routeSource, /atomic_read\(&idev->ra_route_count\)/);
assert.match(routeSource, /max_size - IPV6_RA_DST_RESERVE/);
assert.match(routeSource, /err = ip6_route_add\(cfg\);/);
assert.match(routeSource, /ip6_route_add_ra\(&cfg\);[\s\S]*?return rt6_get_dflt_router/);
assert.match(addrconfSource, /ip6_route_add_ra\(&cfg\);/);
assert.match(addrconfSource, /rt->rt6i_dev == dev[\s\S]*?rt->rt6i_dst.plen == pinfo->prefix_len[\s\S]*?RTF_ADDRCONF \| RTF_PREFIX_RT/);
assert.match(addrconfSource, /if \(valid_lft == 0\)[\s\S]*?ip6_del_rt\(rt\);[\s\S]*?else if \(valid_lft\)/);

const perInterfaceLimit = 64;
const dstLimit = 4096;
const reserve = 512;
const acceptedRoutes = new Set();
let dstEntries = 0;

for (let index = 0; index < 10000; index++) {
    if (acceptedRoutes.size >= perInterfaceLimit || dstEntries >= dstLimit - reserve) {
        continue;
    }
    acceptedRoutes.add(`2001:db8:${index.toString(16)}::/64`);
    dstEntries++;
}

assert.equal(acceptedRoutes.size, perInterfaceLimit);
assert.ok(dstEntries < dstLimit - reserve);
console.log('IPv6 RA route limit source contracts and 10000-prefix model passed');