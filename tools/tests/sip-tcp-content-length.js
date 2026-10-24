const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const kernel = path.resolve(__dirname, '../../release/src-rt-6.x.4708/linux/linux-2.6.36/net');
const sip = fs.readFileSync(path.join(kernel, 'netfilter/nf_conntrack_sip.c'), 'utf8');
const helper = fs.readFileSync(path.join(kernel, 'ipv4/netfilter/nf_nat_helper.c'), 'utf8');

const tcp = sip.slice(sip.indexOf('static int sip_help_tcp('), sip.indexOf('static int sip_help_udp('));
const bound = tcp.indexOf('if (clen > datalen - (end - dptr))');
assert(bound > tcp.indexOf('end += strlen("\\r\\n\\r\\n");'), 'clen must be bounded after the header terminator');
assert(bound < tcp.indexOf('end += clen;'), 'clen must be bounded before advancing end');
assert(tcp.indexOf('end += clen;') < tcp.indexOf('process_sip_msg('));
assert.doesNotMatch(tcp, /strlen\("\\r\\n\\r\\n"\) \+ clen/);

const mangle = helper.slice(helper.indexOf('int __nf_nat_mangle_tcp_packet('), helper.indexOf('EXPORT_SYMBOL(__nf_nat_mangle_tcp_packet)'));
const check = mangle.indexOf('match_len > skb->len - dataoff - match_offset');
assert(check > 0 && check < mangle.indexOf('enlarge_skb(') && check < mangle.indexOf('mangle_contents('));
assert.match(mangle, /dataoff > skb->len \|\|\s*match_offset > skb->len - dataoff \|\|/);

// Model the C unsigned arithmetic of sip_help_tcp for a single message.
function accepted(datalen, hdrlen, clen) {
    return !(clen > ((datalen - hdrlen) >>> 0));
}
const hdr = 'INVITE sip:x@y SIP/2.0\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n'.length;
for (const clen of [0, 10]) assert(accepted(hdr + 10, hdr, clen));
for (const clen of [11, 300000000, 0x3fffffff, 0xffffffff]) assert(!accepted(hdr + 10, hdr, clen));

function mangleOk(len, dataoff, off, mlen) {
    return !(dataoff > len || off > len - dataoff || mlen > ((len - dataoff - off) >>> 0));
}
assert(mangleOk(100, 40, 50, 10));
assert(!mangleOk(100, 40, 50, 11));
assert(!mangleOk(100, 40, 61, 0));
assert(!mangleOk(100, 40, 0xfffffff0, 0x20));

console.log('sip-tcp-content-length: ok');
