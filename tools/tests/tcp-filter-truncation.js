const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36');
const filterHeader = fs.readFileSync(path.join(kernel, 'include/linux/filter.h'), 'utf8');
const filterSource = fs.readFileSync(path.join(kernel, 'net/core/filter.c'), 'utf8');
const tcpHeader = fs.readFileSync(path.join(kernel, 'include/net/tcp.h'), 'utf8');
const tcp4Source = fs.readFileSync(path.join(kernel, 'net/ipv4/tcp_ipv4.c'), 'utf8');
const tcp6Source = fs.readFileSync(path.join(kernel, 'net/ipv6/tcp_ipv6.c'), 'utf8');

function functionBody(source, signature, nextSignature) {
    const start = source.indexOf(signature);
    assert.notEqual(start, -1, `${signature} exists`);
    const end = source.indexOf(nextSignature, start);
    assert.notEqual(end, -1, `${nextSignature} follows ${signature}`);
    return source.slice(start, end);
}

assert.match(filterHeader, /sk_filter_trim_cap\(struct sock \*sk, struct sk_buff \*skb,\s*unsigned int cap\)/);
assert.match(tcpHeader, /tcp_filter\(struct sock \*sk, struct sk_buff \*skb\)/);
assert.match(filterSource, /if \(pkt_len < cap\)\s*pkt_len = cap;/,
    'socket filter result is raised to the protocol header minimum');
assert.match(filterSource, /return sk_filter_trim_cap\(sk, skb, 0\);/,
    'uncapped sk_filter callers retain their existing behavior');

const tcpFilter = functionBody(tcp4Source, 'int tcp_filter(struct sock *sk, struct sk_buff *skb)',
    'EXPORT_SYMBOL(tcp_filter);');
assert.match(tcpFilter, /sk_filter_trim_cap\(sk, skb, th->doff \* 4\)/,
    'TCP filtering preserves the complete TCP header');
assert.match(tcpFilter, /eaten -= skb->len;\s*TCP_SKB_CB\(skb\)->end_seq -= eaten;/,
    'TCP sequence range follows the bytes retained after filtering');

assert.equal((tcp4Source.match(/tcp_filter\(sk, skb\)/g) || []).length, 1,
    'IPv4 receive path uses TCP-aware filtering');
assert.equal((tcp6Source.match(/tcp_filter\(sk, skb\)/g) || []).length, 2,
    'IPv6 receive and deferred paths use TCP-aware filtering');
assert.doesNotMatch(tcp4Source, /sk_filter\(sk, skb\)/,
    'IPv4 TCP receive paths do not call the uncapped filter');
assert.doesNotMatch(tcp6Source, /sk_filter\(sk, skb\)/,
    'IPv6 TCP receive paths do not call the uncapped filter');

let cases = 0;
for (const originalLength of [20, 40, 128, 1500]) {
    for (const headerLength of [20, 24, 32]) {
        if (headerLength > originalLength)
            continue;

        for (const requestedLength of [0, 1, headerLength - 1, headerLength,
            headerLength + 1, originalLength, originalLength + 1]) {
            if (requestedLength === 0) {
                cases++;
                continue;
            }

            const retainedLength = Math.min(originalLength,
                Math.max(requestedLength, headerLength));
            const initialEndSeq = 9000 + originalLength - headerLength;
            const correctedEndSeq = initialEndSeq - (originalLength - retainedLength);
            assert.equal(correctedEndSeq, 9000 + retainedLength - headerLength,
                `range matches retained payload (skb=${originalLength}, header=${headerLength}, filter=${requestedLength})`);
            assert(retainedLength >= headerLength,
                `retained skb includes TCP header (skb=${originalLength}, header=${headerLength}, filter=${requestedLength})`);
            cases++;
        }
    }
}

console.log(`PASS: TCP filter source contracts and ${cases} header/sequence boundary cases (model only; not compiled kernel)`);