#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const ipv4 = path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4');
const input = fs.readFileSync(path.join(ipv4, 'tcp_input.c'), 'utf8');
const output = fs.readFileSync(path.join(ipv4, 'tcp_output.c'), 'utf8');

const markStart = input.indexOf('static void tcp_mark_head_lost(');
const markEnd = input.indexOf('\n/* Account newly detected lost packet(s) */', markStart);
assert.ok(markStart >= 0 && markEnd > markStart,
    'loss-marking function must exist');
const markHeadLost = input.slice(markStart, markEnd);

assert.match(output, /if \(WARN_ON\(len > skb->len\)\)\s*return -EINVAL;/,
    'invalid fragment lengths must return an error instead of panicking');
assert.doesNotMatch(output, /BUG_ON\(len > skb->len\)/,
    'tcp_fragment must not panic on an invalid requested length');
assert.match(markHeadLost,
    /\(TCP_SKB_CB\(skb\)->sacked & TCPCB_SACKED_ACKED\)/,
    'loss marking must not fragment an skb that is still SACKed');
assert.match(markHeadLost,
    /lost = \(packets - oldcnt\) \* mss;\s*if \(lost < skb->len &&\s*tcp_fragment\(sk, skb, lost, mss\) < 0\)/,
    'loss marking must only split a strict prefix of the skb');

function shouldFragment({ sack, fack, sacked, oldCount, packets, lost, skbLength }) {
    const shouldSkip = (sack && !fack) || sacked || oldCount >= packets;
    return !shouldSkip && lost < skbLength;
}

assert.equal(shouldFragment({
    sack: true, fack: true, sacked: true,
    oldCount: 0, packets: 3, lost: 1200, skbLength: 900
}), false, 'a SACKed skb is not split');
assert.equal(shouldFragment({
    sack: true, fack: true, sacked: false,
    oldCount: 0, packets: 3, lost: 1200, skbLength: 900
}), false, 'reneged skb with an overlong prefix is marked whole');
assert.equal(shouldFragment({
    sack: true, fack: true, sacked: false,
    oldCount: 0, packets: 2, lost: 1200, skbLength: 2400
}), true, 'valid strict-prefix loss marking still fragments');
assert.equal(shouldFragment({
    sack: true, fack: true, sacked: false,
    oldCount: 0, packets: 2, lost: 2400, skbLength: 2400
}), false, 'a full-length split request is avoided');

console.log('PASS: TCP SACK fragment bounds (source contracts/model; not kernel execution)');
