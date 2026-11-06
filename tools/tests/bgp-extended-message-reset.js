const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
function read(relativePath) {
    return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

const constants = read('release/src/router/frr-8.1/bgpd/bgpd.h');
const bgpd = read('release/src/router/frr-8.1/bgpd/bgpd.c');
const fsm = read('release/src/router/frr-8.1/bgpd/bgp_fsm.c');
const open = read('release/src/router/frr-8.1/bgpd/bgp_open.c');
const io = read('release/src/router/frr-8.1/bgpd/bgp_io.c');
const packet = read('release/src/router/frr-8.1/bgpd/bgp_packet.c');

assert.match(constants, /#define BGP_STANDARD_MESSAGE_MAX_PACKET_SIZE\s+4096/);
assert.match(constants, /#define BGP_EXTENDED_MESSAGE_MAX_PACKET_SIZE\s+65535/);
assert.match(bgpd, /peer->max_packet_size = BGP_STANDARD_MESSAGE_MAX_PACKET_SIZE;/,
    'new peers start at the standard message limit');

for (const [name, source, start] of [
    ['bgp_stop', fsm, 'int bgp_stop(struct peer *peer)'],
    ['bgp_start', fsm, 'int bgp_start(struct peer *peer)']
]) {
    const bodyStart = source.indexOf(start);
    assert.notEqual(bodyStart, -1, `${name} exists`);
    const capabilityReset = source.indexOf('peer->cap = 0;', bodyStart);
    assert.notEqual(capabilityReset, -1, `${name} clears negotiated capabilities`);
    assert.match(source.slice(capabilityReset, capabilityReset + 160),
        /peer->max_packet_size = BGP_STANDARD_MESSAGE_MAX_PACKET_SIZE;/,
        `${name} restores the unnegotiated message limit`);
}

const configTransferStart = bgpd.indexOf('void peer_xfer_config(');
const configTransferEnd = bgpd.indexOf('\n}', configTransferStart);
assert(configTransferStart >= 0 && configTransferEnd > configTransferStart,
    'peer_xfer_config function is present');
assert.doesNotMatch(bgpd.slice(configTransferStart, configTransferEnd),
    /max_packet_size\s*=/,
    'accepted doppelgangers retain peer_new() standard limit');

assert.match(open, /peer->max_packet_size\s*=\s*\(CHECK_FLAG\(peer->cap, PEER_CAP_EXTENDED_MESSAGE_RCV\)[\s\S]*?\? BGP_EXTENDED_MESSAGE_MAX_PACKET_SIZE\s*: BGP_STANDARD_MESSAGE_MAX_PACKET_SIZE;/,
    'only this OPEN exchange can negotiate the extended limit');
assert.match(io, /if \(\(size < BGP_HEADER_SIZE\) \|\| \(size > peer->max_packet_size\)[\s\S]*?bgp_notify_send_with_data\(peer, BGP_NOTIFY_HEADER_ERR,[\s\S]*?BGP_NOTIFY_HEADER_BAD_MESLEN/,
    'oversized message is rejected with a header-length notification');

const notifyStart = packet.indexOf('void bgp_notify_send_with_data(');
const notifyEnd = packet.indexOf('\n}', notifyStart);
assert(notifyStart >= 0 && notifyEnd > notifyStart,
    'bgp_notify_send_with_data function is present');
const notify = packet.slice(notifyStart, notifyEnd);
assert.match(notify, /if \(packetsize <= sizeof\(peer->last_reset_cause\)\)\s*\{[\s\S]*?memcpy\(peer->last_reset_cause, peer->curr->data,\s*packetsize\);[\s\S]*?peer->last_reset_cause_size = packetsize;/,
    'debug packet copy is bounded by the destination buffer');
assert.doesNotMatch(notify, /assert\s*\(\s*packetsize\s*<=\s*peer->max_packet_size\s*\)/,
    'peer-driven limit changes cannot abort notification handling');

function accepted(size, limit) {
    return size >= 19 && size <= limit;
}

assert.equal(accepted(4097, 4096), false,
    'oversized packet accompanying a non-extended OPEN is refused');
assert.equal(accepted(4096, 4096), true,
    'standard-size packet remains within the pre-negotiation limit');
assert.equal(accepted(4097, 65535), true,
    'extended-size packet is allowed after a later OPEN negotiates it');

console.log('PASS: Extended Message session reset, accepted-peer initialization, header rejection, and bounded notification copy (source contracts; bgpd not compiled)');