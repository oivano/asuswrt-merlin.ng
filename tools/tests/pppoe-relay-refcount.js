const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36');
const pppoxSource = fs.readFileSync(path.join(kernel, 'drivers/net/pppox.c'), 'utf8');
const source = fs.readFileSync(path.join(kernel, 'drivers/net/pppoe.c'), 'utf8');

assert.match(pppoxSource, /#include <linux\/capability\.h>/);
const createStart = pppoxSource.indexOf('static int pppox_create(');
const createEnd = pppoxSource.indexOf('\nstatic const struct net_proto_family', createStart);
assert.notEqual(createStart, -1);
assert.notEqual(createEnd, -1);
assert.match(pppoxSource.slice(createStart, createEnd),
    /if \(!kern && !capable\(CAP_NET_ADMIN\)\)\s*return -EPERM;[\s\S]*?if \(protocol < 0/,
    'userspace PPPoX socket creation requires CAP_NET_ADMIN');

const connectStart = source.indexOf('static int pppoe_connect(');
const connectEnd = source.indexOf('\nstatic int pppoe_getname(', connectStart);
assert.notEqual(connectStart, -1);
assert.notEqual(connectEnd, -1);
assert.match(source.slice(connectStart, connectEnd),
    /if \(!capable\(CAP_NET_ADMIN\)\)\s*return -EPERM;\s*if \(sockaddr_len/,
    'PPPoE connect requires CAP_NET_ADMIN before processing user input');

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

console.log('PASS: PPPoX creation, PPPoE connect, relay authorization, and reference source-contract checks; not compiled-kernel execution');
