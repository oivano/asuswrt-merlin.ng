const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const sourcePath = path.resolve(__dirname, '../../release/src/router/busybox/networking/udhcp/dhcpc.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const functionBody = source.match(/static NOINLINE int udhcp_recv_raw_packet\([\s\S]*?\n\}/)?.[0];
assert(functionBody, 'raw receive function is present');

const lengthGuard = functionBody.indexOf(
    'if (ntohs(packet.ip.tot_len) < sizeof(packet.ip) + sizeof(packet.udp)\n\t || ntohs(packet.udp.len) < sizeof(packet.udp)'
);
const receiveBufferLimit = functionBody.indexOf('iov.iov_len = sizeof(packet);');
const receivedLengthCheck = functionBody.indexOf('if (bytes < ntohs(packet.ip.tot_len))');
const trustedLengthAssignment = functionBody.indexOf('bytes = ntohs(packet.ip.tot_len);');
const payloadCopy = functionBody.indexOf('bytes -= sizeof(packet.ip) + sizeof(packet.udp);');
assert(lengthGuard >= 0, 'IP total length and UDP length minimums are checked');
assert(receiveBufferLimit >= 0, 'recvmsg is bounded by the packet structure');
assert(lengthGuard < receivedLengthCheck, 'minimum lengths are checked before using the IP length');
assert(lengthGuard < trustedLengthAssignment, 'minimum lengths are checked before replacing received bytes');
assert(trustedLengthAssignment < payloadCopy, 'payload subtraction happens only after length validation');

const ipHeaderLength = 20;
const udpHeaderLength = 8;
const headerLength = ipHeaderLength + udpHeaderLength;
const packetCapacity = 576;

function acceptedPayloadLength(receivedLength, totalLength, udpLength) {
    if (receivedLength < headerLength || totalLength < headerLength || udpLength < udpHeaderLength)
        return null;
    if (receivedLength < totalLength || udpLength !== totalLength - ipHeaderLength)
        return null;
    return totalLength - headerLength;
}

for (let totalLength = 0; totalLength < headerLength; totalLength++) {
    const udpLength = (totalLength - ipHeaderLength + 0x10000) & 0xffff;
    assert.equal(
        acceptedPayloadLength(packetCapacity, totalLength, udpLength),
        null,
        `reject tot_len ${totalLength} with a matching 16-bit udp.len`
    );
}
assert.equal(acceptedPayloadLength(packetCapacity, headerLength, udpHeaderLength), 0);
assert.equal(acceptedPayloadLength(packetCapacity, headerLength + 1, udpHeaderLength + 1), 1);
assert.equal(acceptedPayloadLength(packetCapacity, packetCapacity, packetCapacity - ipHeaderLength),
    packetCapacity - headerLength);
assert(acceptedPayloadLength(packetCapacity, packetCapacity, packetCapacity - ipHeaderLength) <=
    packetCapacity - headerLength, 'payload copy is bounded by the DHCP data structure');
assert.equal(acceptedPayloadLength(packetCapacity, headerLength, udpHeaderLength - 1), null,
    'reject UDP lengths smaller than the UDP header');

console.log('udhcpc raw packet length validation: ok');
