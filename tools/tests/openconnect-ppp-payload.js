#!/usr/bin/env node
"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const source = fs.readFileSync(
    path.join(__dirname, "../../release/src/router/openconnect/ppp.c"),
    "utf8"
);

function requireOrder(text, first, second, message) {
    const firstIndex = text.indexOf(first);
    const secondIndex = text.indexOf(second);
    assert(firstIndex >= 0, `missing ${first}: ${message}`);
    assert(secondIndex >= 0, `missing ${second}: ${message}`);
    assert(firstIndex < secondIndex, message);
}

function parsePppHeader(payload) {
    let offset = 0;
    if (!payload.length)
        return null;
    if (payload.length >= 2 && payload[0] === 0xff && payload[1] === 0x03)
        offset += 2;
    if (offset >= payload.length)
        return null;

    let proto = payload[offset++];
    if (!(proto & 1)) {
        if (offset >= payload.length)
            return null;
        proto = (proto << 8) | payload[offset++];
    }
    return { proto, payload: payload.length - offset };
}

const queueStart = source.indexOf("static int queue_config_packet(");
const queueEnd = source.indexOf("#define PROTO_TAG_LEN", queueStart);
assert(queueStart >= 0 && queueEnd > queueStart, "queue_config_packet not found");
const queue = source.slice(queueStart, queueEnd);
requireOrder(queue, "if (len < 0)", "alloc_pkt(vpninfo, len + 4)",
    "negative lengths must be rejected before allocation");
requireOrder(queue, "if (len > 0xffff - 4)", "alloc_pkt(vpninfo, len + 4)",
    "payload must fit the PPP length field before allocation");
requireOrder(queue, "p->alloc_len < sizeof(*p) + 4 + len",
    "memcpy(p->data + 4, payload, len)",
    "the packet capacity must cover the copy");

const headerStart = source.indexOf("/* check PPP header and extract protocol */");
const headerEnd = source.indexOf("kai->last_rx = time(NULL)", headerStart);
assert(headerStart >= 0 && headerEnd > headerStart, "PPP header parser not found");
const header = source.slice(headerStart, headerEnd);
requireOrder(header, "if (payload_len < 1)", "pp[0] == 0xff",
    "the first PPP byte must be present before inspection");
assert(header.includes("payload_len >= 2 && pp[0] == 0xff && pp[1] == 0x03"),
    "address/control compression check must not read beyond the payload");
requireOrder(header, "if (pp - ph >= payload_len)", "proto = *pp++",
    "the protocol byte must be present before reading");
const protocolRead = header.indexOf("proto = *pp++");
const secondByteGuard = header.indexOf("if (pp - ph >= payload_len)", protocolRead);
const secondByteRead = header.indexOf("proto += *pp++", protocolRead);
assert(secondByteGuard > protocolRead && secondByteGuard < secondByteRead,
    "the second protocol byte must be present before reading");
requireOrder(header, "proto += *pp++", "payload_len -= pp - ph",
    "payload length is reduced only after the complete header is validated");
assert(source.includes("malformed_ppp_header:") && source.includes("next_frame:"),
    "malformed PPP frames must be dropped through the normal next-frame path");

function f5Payload(frame) {
    const payloadLength = frame.readUInt16BE(2);
    if (frame.length < 4 + payloadLength)
        return null;
    return frame.subarray(4, 4 + payloadLength);
}

function fortinetPayload(frame) {
    const payloadLength = frame.readUInt16BE(4);
    if (frame.readUInt16BE(0) !== payloadLength + 6 ||
        frame.readUInt16BE(2) !== 0x5050 || frame.length < 6 + payloadLength)
        return null;
    return frame.subarray(6, 6 + payloadLength);
}

assert.strictEqual(parsePppHeader(f5Payload(Buffer.from("f5000000ff0380fd", "hex"))), null,
    "an F5 frame with zero payload must not borrow bytes beyond its frame");
assert.strictEqual(parsePppHeader(f5Payload(Buffer.from("f500000180fd", "hex"))), null,
    "an F5 frame with one truncated protocol byte must be discarded");
assert.strictEqual(parsePppHeader(fortinetPayload(Buffer.from("00075050000180", "hex"))), null,
    "a Fortinet frame with one truncated protocol byte must be discarded");
assert.strictEqual(parsePppHeader(Buffer.from([0xff, 0x03])), null,
    "a truncated address/control header must be discarded");
assert.strictEqual(parsePppHeader(Buffer.from([0xff, 0x03, 0x80])), null,
    "a truncated two-byte protocol must be discarded");
assert.deepStrictEqual(parsePppHeader(Buffer.from([0xff, 0x03, 0x80, 0xfd])),
    { proto: 0x80fd, payload: 0 }, "a complete uncompressed PPP header must parse");
assert.deepStrictEqual(parsePppHeader(Buffer.from([0x21, 0x45])),
    { proto: 0x21, payload: 1 }, "a complete compressed PPP header must parse");

console.log("PASS: OpenConnect PPP payload bounds and Protocol-Reject copy guards");