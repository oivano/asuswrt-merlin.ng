const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/openconnect/ppp.c'), 'utf8');
const loop = source.slice(source.indexOf('static int ppp_mainloop'), source.indexOf('handle_outgoing:', source.indexOf('static int ppp_mainloop')));
const mru = source.slice(source.indexOf('static int handle_config_request'), source.indexOf('static int handle_config_ack'));

assert.match(mru, /vpninfo->ip_info\.mtu = mru/);
assert.match(loop, /receive_slack = ppp->exp_ppp_hdr_size/);
assert.match(loop, /alloc_len < sizeof\(struct pkt\) \+ receive_mtu \+ receive_slack/);
assert.match(loop, /alloc_pkt\(vpninfo, receive_mtu \+ receive_slack\)/);
assert.match(loop, /this = vpninfo->cstp_pkt = alloc_pkt\(vpninfo, receive_mtu \+ receive_slack\)/);
assert.match(loop, /buffer_size = this->alloc_len - \(eh - \(unsigned char \*\)this\)/);
assert.match(loop, /buffer_size < receive_size \+ receive_slack/);
assert.match(loop, /receive_size - vpninfo->partial_rec_size/);
assert.match(loop, /partial_rec_size >= receive_size/);
assert.ok(loop.indexOf('receive_size = receive_mtu + rsv_hdr_size') < loop.indexOf('ssl_nonblock_read'));
assert.ok(loop.indexOf('alloc_pkt(vpninfo, receive_mtu + receive_slack)') < loop.indexOf('ssl_nonblock_read'));

function receiveCapacity(mtu, encapHeader, expectedPppHeader) {
    const allocatedData = mtu + expectedPppHeader;
    const readLimit = mtu + encapHeader + expectedPppHeader;
    const readCapacity = allocatedData + encapHeader + expectedPppHeader;
    return { allocatedData, readLimit, readCapacity };
}

const initial = receiveCapacity(16384, 4, 4);
const grown = receiveCapacity(65535, 4, 4);
assert.equal(initial.readLimit, 16392);
assert.equal(grown.readLimit, 65543);
assert.ok(grown.readCapacity >= grown.readLimit + 4);
assert.ok(grown.allocatedData > initial.allocatedData);

let partial = 0;
for (const recordLength of [16384, 16384, 16384, 10851]) {
    partial += recordLength;
    assert.ok(partial <= grown.readLimit);
}
assert.equal(partial, 60003);
assert.ok(partial < grown.readLimit);

console.log('openconnect-ppp-rx-bounds: allocation, read and partial-frame bounds passed');
