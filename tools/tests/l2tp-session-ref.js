#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');

const base = 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/l2tp/';
const core = fs.readFileSync(`${base}l2tp_core.c`, 'utf8');
const ip = fs.readFileSync(`${base}l2tp_ip.c`, 'utf8');
const ppp = fs.readFileSync(`${base}l2tp_ppp.c`, 'utf8');

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert.notStrictEqual(start, -1, `missing ${signature}`);
    const open = source.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < source.length; index++) {
        if (source[index] === '{') depth++;
        if (source[index] === '}' && --depth === 0)
            return source.slice(open + 1, index);
    }
    assert.fail(`unterminated ${signature}`);
}

const get = functionBody(core, 'struct l2tp_session *l2tp_session_get(');
const recv = functionBody(core, 'void l2tp_recv_common(');
const udp = functionBody(core, 'int l2tp_udp_recv_core(');
const tunnelIoctl = functionBody(ppp, 'static int pppol2tp_tunnel_ioctl(');
const ipRecv = functionBody(ip, 'static int l2tp_ip_recv(');

assert.match(get, /read_lock_bh\(&tunnel->hlist_lock\)/);
assert.match(get, /l2tp_session_inc_refcount\(session\)/);
assert.match(get, /if \(do_ref && session->ref\)[\s\S]*?session->ref\)\(session\)/);
assert.match(get, /rcu_read_lock_bh\(\)/);
assert.doesNotMatch(recv, /l2tp_session_inc_refcount|session->ref\)/);
assert.match(udp, /l2tp_session_get\(tunnel->l2tp_net, tunnel, session_id, 1\)/);
assert.match(udp, /l2tp_session_dec_refcount\(session\)/);
assert.match(ipRecv, /l2tp_session_get\(&init_net, NULL, session_id, 1\)/);
assert.match(ipRecv, /discard_sess:[\s\S]*?l2tp_session_dec_refcount\(session\)/);
assert.match(tunnelIoctl, /l2tp_session_get\(sock_net\(sk\), tunnel,[\s\S]*?stats\.session_id, 1\)/);
assert.match(tunnelIoctl, /session->deref\)\(session\)[\s\S]*?l2tp_session_dec_refcount\(session\)/);

console.log('L2TP session reference contracts passed');