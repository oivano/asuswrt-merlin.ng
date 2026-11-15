'use strict';

const assert = require('assert');
const fs = require('fs');

const root = `${__dirname}/../..`;
const rcSource = fs.readFileSync(`${root}/release/src/router/rc/udhcpc.c`, 'utf8');
const kernelSource = fs.readFileSync(
    `${root}/release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/ndisc.c`,
    'utf8'
);

assert(!rcSource.includes('RA_HOPLIMIT'), 'rc must not apply the RA hop limit to the interface');

const interfaceHoplimitUpdate = kernelSource.match(
    /if \(ra_msg->icmph\.icmp6_hop_limit\) \{([\s\S]*?)\n\t\}/
);
assert(interfaceHoplimitUpdate, 'kernel RA hop-limit block must exist');
assert(
    /in6_dev->cnf\.hop_limit < ra_msg->icmph\.icmp6_hop_limit/.test(interfaceHoplimitUpdate[1]),
    'kernel must only raise the interface hop limit'
);
assert(
    /in6_dev->cnf\.hop_limit = ra_msg->icmph\.icmp6_hop_limit/.test(interfaceHoplimitUpdate[1]),
    'kernel must retain the higher RA hop limit'
);

function resultingHoplimit(current, advertised) {
    return advertised > 0 && current < advertised ? advertised : current;
}

for (const [current, advertised, expected] of [
    [64, 1, 64],
    [64, 30, 64],
    [64, 64, 64],
    [64, 255, 255]
]) {
    assert.strictEqual(resultingHoplimit(current, advertised), expected);
}

console.log('PASS: rc ignores RA_HOPLIMIT; kernel rejects lower/equal values and accepts increases.');