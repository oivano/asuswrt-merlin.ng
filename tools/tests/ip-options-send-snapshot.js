'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const udp = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/udp.c');
const raw = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/raw.c');

function functionBody(source, signature, nextSignature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing ${signature}`);
    const end = source.indexOf(nextSignature, start + signature.length);
    assert(end > start, `missing ${nextSignature}`);
    return source.slice(start, end);
}

for (const [name, source, signature, nextSignature] of [
    ['udp', udp, 'int udp_sendmsg(', 'EXPORT_SYMBOL(udp_sendmsg);'],
    ['raw', raw, 'static int raw_sendmsg(', 'static void raw_close('],
]) {
    const send = functionBody(source, signature, nextSignature);
    const snapshot = send.indexOf('if (!ipc.opt) {');
    const lock = send.indexOf('lock_sock(sk);', snapshot);
    const sharedRead = send.indexOf('memcpy(optbuf.data, inet->opt,', lock);
    const unlock = send.indexOf('release_sock(sk);', sharedRead);
    assert(snapshot >= 0 && lock > snapshot && sharedRead > lock && unlock > sharedRead,
        `${name}: shared options must be copied under the socket lock`);
    assert.match(send.slice(snapshot, unlock), /inet->opt->optlen > 40/,
        `${name}: reject options larger than the private buffer`);
    assert.match(send.slice(snapshot, unlock), /sizeof\(struct ip_options\) \+ inet->opt->optlen/,
        `${name}: copy the complete bounded options object`);
    assert.match(send.slice(snapshot, unlock), /ipc\.opt = \(struct ip_options \*\)optbuf\.data/,
        `${name}: subsequent send logic must use the snapshot`);
    assert.doesNotMatch(send.slice(unlock), /ipc\.opt = inet->opt/,
        `${name}: do not retain the shared pointer after unlocking`);
    assert.match(send.slice(unlock), /ip_append_data\(/,
        `${name}: retain the snapshot through packet assembly`);
}

console.log('ip-options-send-snapshot: ok');
