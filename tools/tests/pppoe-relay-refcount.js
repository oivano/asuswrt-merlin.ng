const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/drivers/net/pppoe.c'), 'utf8');

const receiveStart = source.indexOf('static int pppoe_rcv_core(');
const receiveEnd = source.indexOf('static int pppoe_rcv(', receiveStart);
assert.notEqual(receiveStart, -1);
assert.notEqual(receiveEnd, -1);
const receiveCore = source.slice(receiveStart, receiveEnd);
assert.match(receiveCore,
    /if \(!__pppoe_xmit\(sk_pppox\(relay_po\), skb\)\)\s*goto abort_put;\s*sock_put\(sk_pppox\(relay_po\)\);/);
assert.match(receiveCore,
    /abort_put:\s*sock_put\(sk_pppox\(relay_po\)\);/);
assert.equal((receiveCore.match(/sock_put\(sk_pppox\(relay_po\)\)/g) || []).length, 2,
    'relay target reference is released once on both success and abort');

const ioctlStart = source.indexOf('static int pppoe_ioctl(');
const ioctlEnd = source.indexOf('\nstatic ', ioctlStart + 1);
assert.notEqual(ioctlStart, -1);
assert.notEqual(ioctlEnd, -1);
const ioctl = source.slice(ioctlStart, ioctlEnd);
const relaySetupStart = ioctl.indexOf('case PPPOEIOCSFWD:');
const relaySetupEnd = ioctl.indexOf('case PPPOEIOCDFWD:', relaySetupStart);
assert.notEqual(relaySetupStart, -1);
assert.notEqual(relaySetupEnd, -1);
const relaySetup = ioctl.slice(relaySetupStart, relaySetupEnd);
assert.match(relaySetup, /if \(!capable\(CAP_NET_ADMIN\)\)\s*break;/,
    'relay setup requires CAP_NET_ADMIN');
assert.match(relaySetup,
    /if \(relay_po == po\)\s*\{\s*sock_put\(sk_pppox\(relay_po\)\);\s*err = -EINVAL;/,
    'self-relay is rejected and its lookup reference is released');

console.log('PASS: PPPoE relay reference and ioctl source-contract checks; not compiled-kernel execution');
