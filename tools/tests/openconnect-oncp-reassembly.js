const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/openconnect/oncp.c'), 'utf8');
const parseStart = source.indexOf('static int parse_conf_pkt(');
const parse = source.slice(parseStart, source.indexOf('\nint oncp_connect', parseStart));
const connectStart = source.indexOf('int oncp_connect(struct openconnect_info *vpninfo)');
const connect = source.slice(connectStart, source.indexOf('\nint ', connectStart + 1));
assert.notEqual(parseStart, -1, 'parse_conf_pkt must exist');
assert.notEqual(connectStart, -1, 'oncp_connect must exist');
const continuation = connect.slice(connect.indexOf('continuation_len ='), connect.indexOf('/*\n\t\t * Sometimes'));

assert.match(parse, /uint32_t grouplen, attrlen;/,
    'decode server-supplied group and attribute lengths as unsigned 32-bit values');
assert.match(parse, /if \(grouplen > pktlen - ofs\)\s*goto eparse;\s*groupend = ofs \+ \(int\)grouplen;/,
    'bound group length by remaining packet bytes before adding it to the cursor');
assert.match(parse, /if \(attrlen > groupend - ofs\)\s*goto eparse;\s*if \(process_attr/,
    'bound attribute length by remaining group bytes before dispatch');
assert.match(parse, /group, attr, bytes \+ ofs, \(int\)attrlen\)/,
    'narrow the attribute length only after its packet-bound check');

assert.match(connect, /if \(kmplen > sizeof\(bytes\) - 22\)/,
    'reject a KMP frame whose 22-byte overhead plus payload exceeds bytes');
assert.match(continuation, /!continuation_len/,
    'reject zero-length records that would not advance reassembly');
assert.match(continuation, /continuation_len > sizeof\(bytes\) - len/,
    'bound every continuation record by remaining buffer space');
assert.match(continuation, /bytes \+ len \+ reclen/,
    'append partial continuation reads at their accumulated offset');
assert.match(continuation, /if \(thislen <= 0\)/,
    'fail on negative and zero SSL reads');
assert.doesNotMatch(connect, /while \(len < check_len \+ 2\) \{[^}]*if \(len < 0\)/,
    'do not test the accumulated length for SSL read failure');

const capacity = 65538;
const frameOverhead = 22;

function checkedEnd(length, offset, boundary) {
    if (length > boundary - offset)
        throw new Error('TLV length exceeds remaining bytes');
    return offset + length;
}

for (const encodedLength of [0xfffffffa, 0x80000000]) {
    const header = Buffer.alloc(6);
    header.writeUInt32BE(encodedLength, 2);
    const decodedLength = header.readUInt32BE(2);
    assert.throws(() => checkedEnd(decodedLength, 6, 32), /exceeds remaining/,
        `reject unsigned TLV length 0x${encodedLength.toString(16)}`);
}
assert.equal(checkedEnd(0, 6, 32), 6, 'zero-length TLV still advances past its header');
assert.equal(checkedEnd(26, 6, 32), 32, 'accept a TLV that exactly fills the remaining bytes');
assert.throws(() => checkedEnd(27, 6, 32), /exceeds remaining/,
    'reject a TLV one byte beyond the remaining packet');

function reassemble(kmpLength, initial, records) {
    if (kmpLength > capacity - frameOverhead)
        throw new Error('KMP frame too large');

    const bytes = Buffer.alloc(capacity);
    initial.copy(bytes);
    let length = initial.length;
    let continuationReads = 0;
    const targetLength = kmpLength + frameOverhead;

    while (length < targetLength) {
        const fragments = records[continuationReads++];
        if (!fragments)
            throw new Error('missing continuation');
        const recordLength = fragments.reduce((total, fragment) => total + fragment.length, 0);
        if (!recordLength || recordLength > capacity - length || recordLength + length > targetLength)
            throw new Error('invalid continuation length');

        let recordLengthRead = 0;
        for (const fragment of fragments) {
            if (!fragment.length)
                throw new Error('empty SSL read');
            assert(fragment.length <= recordLength - recordLengthRead);
            fragment.copy(bytes, length + recordLengthRead);
            recordLengthRead += fragment.length;
        }
        length += recordLengthRead;
    }

    return { frame: bytes.subarray(0, length), continuationReads };
}

const initial = Buffer.alloc(22, 0x41);
assert.throws(() => reassemble(0xffff, initial, [[Buffer.alloc(20)]]), /too large/);

const expected = Buffer.concat([initial, Buffer.from('abcdefghijkl')]);
const assembled = reassemble(12, initial, [
    [Buffer.from('ab'), Buffer.from('cde')],
    [Buffer.from('f'), Buffer.from('ghij'), Buffer.from('kl')]
]);
assert.deepEqual(assembled.frame, expected, 'fragmented TLS reads preserve every frame byte');
assert.equal(assembled.continuationReads, 2);

const maxFit = Buffer.alloc(capacity);
const maxFitResult = reassemble(capacity - frameOverhead, maxFit, []);
assert.equal(maxFitResult.frame.length, capacity, 'the largest fitting KMP frame remains accepted');
assert.throws(() => reassemble(1, initial, [[Buffer.alloc(0)]]), /invalid continuation length/);
assert.throws(() => reassemble(1, initial, [[Buffer.alloc(0), Buffer.from('x')]]), /empty SSL read/);

console.log('PASS: oNCP KMP frame bounds, fragmented continuation offsets, and failed-read handling (source contracts/model; not compiled C)');