'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), 'utf8');
const rtsp = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/netfilter/nf_nat_rtsp.c');
const natHelper = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/netfilter/nf_nat_helper.c');

assert.match(rtsp, /tranoff > tcplen \|\| tranlen > tcplen-tranoff/);
assert.match(rtsp, /nextparamoff = \(pparamend == NULL\) \? tranlen : pparamend-ptran\+1/);
assert.doesNotMatch(rtsp, /nextparamoff\s*=\s*pparamend-ptcp/);
assert.match(rtsp, /memchr\(ptran\+off, ',', tranlen-off\)/);
assert.match(rtsp, /rtsp_strtou16\(const char\* pbuf, const char\* end/);
assert.match(rtsp, /while \(p < end && isdigit\(\*p\)\)/);
assert.equal((rtsp.match(/rtsp_strtou16\(ptran\+[^,]+,\s*ptran\+nextfieldoff/g) || []).length, 2);
assert.match(rtsp, /nf_nat_mangle_tcp_packet\(skb, ct, ctinfo,[\s\S]{0,80}tranoff\+off/);
assert.match(rtsp, /nf_nat_mangle_tcp_packet\(skb, ct, ctinfo,[\s\S]{0,80}tranoff\+origoff/);
assert.match(rtsp, /diff = \(int\)origlen-\(int\)rbuflen/);
assert.match(rtsp, /if \(diff >= 0\)[\s\S]*?tranlen -= diff[\s\S]*?else[\s\S]*?tranlen \+= -diff/);

const tcpGuard = natHelper.indexOf('int __nf_nat_mangle_tcp_packet(');
const tcpBody = natHelper.slice(tcpGuard, natHelper.indexOf('EXPORT_SYMBOL(__nf_nat_mangle_tcp_packet);', tcpGuard));
assert.ok(tcpGuard >= 0);
assert.match(tcpBody, /match_offset > skb->len - dataoff/);
assert.match(tcpBody, /match_len > skb->len - dataoff - match_offset/);
assert.ok(tcpBody.indexOf('return 0;') < tcpBody.indexOf('mangle_contents('));

function clientPortsInTransport(transportLine) {
  const found = [];
  for (const parameter of transportLine.split(',')) {
    for (const field of parameter.split(';')) {
      if (!field.startsWith('client_port='))
        continue;
      const digits = field.slice('client_port='.length).match(/^\d+/);
      if (digits)
        found.push(Number(digits[0]) & 0xffff);
    }
  }
  return found;
}

const laterHeader = `X: ;client_port=${'0'.repeat(4096)}8\r\n`;
const packetHeaders = `SETUP /stream RTSP/1.0\r\nTransport: RTP/AVP;unicast;client_port=8\r\n${laterHeader}\r\n`;
const transportStart = packetHeaders.indexOf('Transport:');
const transportEnd = packetHeaders.indexOf('\r\n', transportStart) + 2;
const transportLine = packetHeaders.slice(transportStart, transportEnd);
assert.deepEqual(clientPortsInTransport(transportLine), [8]);

function updateLength(length, oldLength, newLength) {
  const delta = oldLength - newLength;
  return delta >= 0 ? length - delta : length + -delta;
}

assert.equal(updateLength(30, 1, 5), 34);
assert.equal(updateLength(30, 5, 1), 26);

console.log('RTSP NAT parser bounds and TCP mangle contracts passed');