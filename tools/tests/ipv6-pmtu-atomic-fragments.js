const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const routePath = path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/route.c');
const source = fs.readFileSync(routePath, 'utf8');

function functionSource(start, end) {
    const startIndex = source.indexOf(start);
    assert.notEqual(startIndex, -1, `missing function: ${start}`);
    const endIndex = source.indexOf(end, startIndex);
    assert.notEqual(endIndex, -1, `missing function end: ${end}`);
    return source.slice(startIndex, endIndex);
}

const updatePmtu = functionSource(
    'static void ip6_rt_update_pmtu(',
    'static int ipv6_get_mtu(');
const pmtuDiscovery = functionSource(
    'static void rt6_do_pmtu_disc(',
    'void rt6_pmtu_discovery(');

for (const [name, body] of [['update_pmtu', updatePmtu], ['PTB discovery', pmtuDiscovery]]) {
    assert.match(body, /mtu\s*=\s*IPV6_MIN_MTU;/, `${name} must clamp MTU to 1280`);
    assert.doesNotMatch(body, /RTAX_FEATURE_ALLFRAG|allfrag/i,
        `${name} must not enable per-destination fragmentation`);
}

console.log('IPv6 PMTU atomic-fragment regression: ok');