#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');

const root = process.cwd();
const input = fs.readFileSync(`${root}/release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/tcp_input.c`, 'utf8');
const header = fs.readFileSync(`${root}/release/src-rt-6.x.4708/linux/linux-2.6.36/include/net/tcp.h`, 'utf8');
const sysctl = fs.readFileSync(`${root}/release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/sysctl_net_ipv4.c`, 'utf8');

const challengeAck = input.match(/static void tcp_send_challenge_ack\(struct sock \*sk\)([\s\S]*?)\n}\n/);
assert(challengeAck, 'challenge ACK helper exists');
assert.match(challengeAck[1], /spin_lock_irqsave/);
assert.match(challengeAck[1], /time_after_eq\(jiffies, tcp_challenge_ack_reset\)/);
assert.match(challengeAck[1], /net_random\(\) % limit/);
assert.match(challengeAck[1], /tcp_send_ack\(sk\)/);

assert.match(input, /sysctl_tcp_challenge_ack_limit __read_mostly = 1000/);
assert.match(header, /extern int sysctl_tcp_challenge_ack_limit;/);
assert.match(sysctl, /\.procname\s*= "tcp_challenge_ack_limit"/);

const ack = input.match(/static int BCMFASTPATH_HOST tcp_ack\([\s\S]*?\n}\n/);
assert(ack, 'tcp_ack exists');
assert(ack[0].indexOf('before(ack, prior_snd_una - tp->max_window)') <
    ack[0].indexOf('if (before(ack, prior_snd_una))'), 'stale ACK floor precedes old-ACK acceptance');

const validate = input.match(/static int tcp_validate_incoming\([\s\S]*?\n}\n/);
assert(validate, 'incoming validation exists');
assert.match(validate[0], /if \(TCP_SKB_CB\(skb\)->seq == tp->rcv_nxt\)\s+tcp_reset\(sk\);\s+else\s+tcp_send_challenge_ack\(sk\);/);
assert.match(validate[0], /if \(th->syn\)[\s\S]*?tcp_send_challenge_ack\(sk\);[\s\S]*?goto discard;/);
assert(validate[0].indexOf('if (th->syn)') < validate[0].indexOf('tcp_replace_ts_recent'), 'rejected SYN does not update timestamp state');

const established = input.match(/int BCMFASTPATH_HOST tcp_rcv_established\([\s\S]*?\n}\n/);
assert(established, 'established receive path exists');
const oldAckGuard = established[0].indexOf('before(TCP_SKB_CB(skb)->ack_seq,');
const fastQueue = established[0].indexOf('__skb_queue_tail(&sk->sk_receive_queue, skb);');
assert(oldAckGuard >= 0 && oldAckGuard < fastQueue, 'old ACK is rejected before fast-path payload queuing');

function rstResets(seq, rcvNxt) {
    return seq === rcvNxt;
}

function ackIsTooOld(ackNumber, sndUna, maxWindow) {
    const delta = (ackNumber - ((sndUna - maxWindow) >>> 0)) | 0;
    return delta < 0;
}

assert.strictEqual(rstResets(1000, 1000), true);
assert.strictEqual(rstResets(1001, 1000), false);
assert.strictEqual(ackIsTooOld(0x90000000, 0x10000000, 65536), true);
assert.strictEqual(ackIsTooOld(0x0fff0000, 0x10000000, 65536), false);

console.log('TCP RFC 5961 source and boundary checks passed');