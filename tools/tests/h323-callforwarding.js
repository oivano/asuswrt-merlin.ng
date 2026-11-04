'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const h323 = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/nf_conntrack_h323_main.c');
const rc = read('release/src/router/rc/common.c');
const defaults = read('release/src/router/shared/defaults.c');
const page = read('release/src/router/www/Advanced_NATPassThrough_Content.asp');

const endpointCheck = h323.match(/static int callforward_addr_is_endpoint\([\s\S]*?\n}\n/);
assert.ok(endpointCheck, 'call-forward address endpoint validator exists');
assert.ok(endpointCheck.index > h323.indexOf('#include <linux/netfilter/nf_conntrack_h323.h>'), 'validator follows kernel headers');
assert.match(endpointCheck[0], /direction = 0; direction < IP_CT_DIR_MAX/);
assert.match(endpointCheck[0], /tuplehash\[direction\]\.tuple\.src\.u3/);
assert.match(endpointCheck[0], /tuplehash\[direction\]\.tuple\.dst\.u3/);

const expectationStart = h323.indexOf('static int expect_callforwarding(');
const addressCheck = h323.indexOf('callforward_addr_is_endpoint(ct, &addr)', expectationStart);
const routeFilter = h323.indexOf('callforward_do_filter(', expectationStart);
const expectationAllocation = h323.indexOf('nf_ct_expect_alloc(ct)', expectationStart);
assert.ok(expectationStart >= 0 && addressCheck > expectationStart);
assert.ok(addressCheck < routeFilter, 'reject unrelated addresses before route filtering');
assert.ok(addressCheck < expectationAllocation, 'reject unrelated addresses before allocating expectations');

const tuples = [
  { src: '10.0.0.20', dst: '198.51.100.8' },
  { src: '198.51.100.8', dst: '203.0.113.4' },
];
const isEndpoint = (address) => tuples.some((tuple) => tuple.src === address || tuple.dst === address);
assert.equal(isEndpoint('10.0.0.20'), true);
assert.equal(isEndpoint('203.0.113.4'), true);
assert.equal(isEndpoint('10.0.0.99'), false, 'unrelated internal host is rejected');

for (const [key, module] of [['fw_pt_h323', 'h323'], ['fw_pt_rtsp', 'rtsp'], ['fw_pt_sip', 'sip']]) {
  assert.match(rc, new RegExp(`nvram_match\\("${key}", "1"\\)\\)\\s*\\{\\s*ct_modprobe\\("${module}"`));
  assert.match(defaults, new RegExp(`\\{ "${key}", "0"`), `${key} defaults off`);
}
assert.match(page, /H\.323, RTSP, and SIP passthrough can create related inbound connections/);

console.log('H.323 call-forwarding endpoint and helper opt-in checks passed');