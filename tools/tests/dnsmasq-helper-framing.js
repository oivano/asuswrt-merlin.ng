const assert = require("assert");
const fs = require("fs");

const source = fs.readFileSync("release/src/router/dnsmasq/src/helper.c", "utf8");
const helper = source.slice(
    source.indexOf("int create_helper("),
    source.indexOf("static void buff_alloc(")
);
const producer = source.slice(
    source.indexOf("void queue_script("),
    source.indexOf("#ifdef HAVE_DHCP6\nvoid queue_relay_snoop")
);

assert(source.includes("#define MAX_HELPER_DATA (DHCP_PACKET_MAX * 16)"), "helper payload limit should allow expanded DHCP data");
assert(helper.includes("data_len > MAX_HELPER_DATA"), "helper must reject impossible frame lengths");
assert(helper.includes("send_event(event_fd, EVENT_DIE, 0, NULL)"), "impossible frames must trigger dnsmasq's fatal helper event");
assert(!helper.includes("data.ed_len > MAXDNAMESTR"), "valid expanded extradata must not be rejected at the domain-name limit");

const payloadRead = helper.indexOf("read_write(pipefd[0], buf, data_len, RW_READ)");
const unsupportedAction = helper.indexOf("else\n\t continue;", payloadRead);
assert(payloadRead !== -1 && unsupportedAction > payloadRead, "payload must be consumed before unsupported actions are skipped");
assert(helper.includes("unsigned char discard[1024]"), "allocation failure must use a bounded drain buffer");
assert(helper.includes("read_write(pipefd[0], discard, chunk, RW_READ)"), "allocation failure must drain the complete payload");

const countCheck = helper.indexOf("data.vendorclass_count < 0");
const shellCountLoop = helper.indexOf("for (i = 0; i < data.vendorclass_count - 1; i++)", countCheck);
const luaCountLoop = helper.indexOf("for (i = 0; i < data.vendorclass_count - 1; i++)", shellCountLoop + 1);
assert(countCheck !== -1 && shellCountLoop > countCheck && luaCountLoop > shellCountLoop,
    "vendor-class count must be bounded before both script paths loop");
const producerLimit = producer.indexOf("ed_len > MAX_HELPER_DATA - data_len");
assert(producerLimit !== -1 && producerLimit < producer.indexOf("buff_alloc(total_len)"),
    "producer must not emit payloads above the helper limit");
assert(producer.includes("buf->ed_len = (int)ed_len"), "bounded extradata length must be serialized");

function encodeFrame(action, payload) {
    const header = Buffer.alloc(112);
    header.writeInt32LE(action, 4);
    header.writeInt32LE(payload.length, 24);
    return Buffer.concat([header, payload]);
}

function decodeFrames(stream) {
    const frames = [];
    let offset = 0;
    while (offset < stream.length) {
        const header = stream.subarray(offset, offset + 112);
        assert.strictEqual(header.length, 112, "complete header required");
        const payloadLength = header.readInt32LE(16) + header.readInt32LE(20) + header.readInt32LE(24);
        const payloadStart = offset + 112;
        const payloadEnd = payloadStart + payloadLength;
        assert(payloadEnd <= stream.length, "complete payload required");
        frames.push({ action: header.readInt32LE(4), payload: stream.subarray(payloadStart, payloadEnd) });
        offset = payloadEnd;
    }
    return frames;
}

const oversizedOptions = Buffer.alloc(1020, 0x37);
const normalLease = Buffer.from([0x61, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0, 0x6d, 0x61, 0x63, 0, 0x69, 0x70]);
const decoded = decodeFrames(Buffer.concat([
    encodeFrame(3, oversizedOptions),
    encodeFrame(1, normalLease)
]));
assert.strictEqual(decoded.length, 2, "later lease frame must remain aligned");
assert.strictEqual(decoded[1].action, 1, "later lease action must be preserved");
assert.deepStrictEqual(decoded[1].payload, normalLease, "later lease MAC/IP data must be preserved");

console.log("dnsmasq helper framing checks passed");