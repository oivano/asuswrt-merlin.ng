const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.resolve(__dirname,
    '../../release/src/router/openconnect/pulse.c'), 'utf8');

function functionBody(start, end) {
    const first = source.indexOf(start);
    assert(first >= 0, `missing ${start}`);
    const last = source.indexOf(end, first + start.length);
    assert(last > first, `missing ${end}`);
    return source.slice(first, last);
}

const parser = functionBody('static int parse_avp(',
    'static int pulse_request_realm_entry(');
assert.match(parser,
    /if \(len > l \|\| len < 8 \|\| \(\(flags & AVP_VENDOR\) && len < 12\)\)\s*return -EINVAL;/);
assert.match(parser, /\*avp_len = len;/);

const realmChoice = functionBody('static int pulse_request_realm_choice(',
    'static int pulse_request_session_kill(');
const sessions = functionBody('static int pulse_request_session_kill(',
    'static int dup_prompt(');
const authenticate = functionBody('static int pulse_authenticate(',
    'int pulse_connect(');

assert.equal((realmChoice.match(/avp_len < 0/g) || []).length, 1);
assert.equal((sessions.match(/avp_len < 0/g) || []).length, 1);
assert.equal((sessions.match(/avp_len2 < 0/g) || []).length, 1);
assert.equal((authenticate.match(/avp_len < 0/g) || []).length, 2);
assert.match(functionBody('static int dup_prompt(',
    '/*\n * There is complex client-side logic'),
    /if \(avp_len < 0\)\s*return -EINVAL;/);

function makeAvp(code, length, vendorFlag) {
    const packet = Buffer.alloc(length);
    packet.writeUInt32BE(code, 0);
    packet.writeUInt32BE((length | (vendorFlag ? 0x80000000 : 0)) >>> 0, 4);
    if (vendorFlag && length >= 12)
        packet.writeUInt32BE(0x583, 8);
    return packet;
}

function parseAvp(packet) {
    const packetLength = packet.length;
    if (packetLength < 8)
        return null;

    const lengthAndFlags = packet.readUInt32BE(4);
    const length = lengthAndFlags & 0xffffff;
    const flags = packet[4];
    if (length > packetLength || length < 8 ||
        ((flags & 0x80) && length < 12))
        return null;

    const payloadOffset = 8 + ((flags & 0x80) ? 4 : 0);
    return { payloadOffset, payloadLength: length - payloadOffset };
}

for (const code of [0xd53, 0xd80]) {
    for (let length = 8; length <= 11; length++)
        assert.equal(parseAvp(makeAvp(code, length, true)), null,
            `vendor AVP ${code.toString(16)} length ${length} must fail`);
}

assert.deepEqual(parseAvp(makeAvp(0xd53, 12, true)),
    { payloadOffset: 12, payloadLength: 0 });
assert.deepEqual(parseAvp(makeAvp(0xd80, 13, true)),
    { payloadOffset: 12, payloadLength: 1 });
assert.deepEqual(parseAvp(makeAvp(0xd53, 8, false)),
    { payloadOffset: 8, payloadLength: 0 });
assert.equal(parseAvp(makeAvp(0xd53, 12, true).subarray(0, 11)), null);

console.log('openconnect-pulse-avp: ok');