const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/frr-8.1/bgpd/bgp_attr.c'), 'utf8');
const packetSource = fs.readFileSync(path.join(root, 'release/src/router/frr-8.1/bgpd/bgp_packet.c'), 'utf8');
const parser = source.slice(source.indexOf('bgp_attr_parse_ret_t bgp_attr_parse('),
    source.indexOf('/*\n * Extract the tunnel type'));
const exit = parser.slice(parser.indexOf('\ndone:'));
const alignment = exit.match(/done:\s*(if \(ret == BGP_ATTR_PARSE_WITHDRAW\)\s*stream_set_getp\(BGP_INPUT\(peer\), endp - STREAM_DATA\(BGP_INPUT\(peer\)\)\);)/);
assert(alignment, 'shared WITHDRAW exit must align to the complete attribute field');
const parserCode = parser.replace(/\/\*[\s\S]*?\*\//g, '');
assert.equal((parserCode.match(/\breturn\b[^;]*;/g) || []).length, 1, 'no early returns bypass cleanup');
assert.match(parser, /return ret;\s*}\s*$/);
assert.match(parser, /if \(bgp_attr_flag_invalid\(&attr_args\)\) {\s*ret = bgp_attr_malformed\([\s\S]*?if \(ret == BGP_ATTR_PARSE_PROCEED\)\s*continue;\s*goto done;\s*}/);
assert.match(parser, /if \(ret == BGP_ATTR_PARSE_WITHDRAW\) {[\s\S]*?goto done;\s*}/);
assert.match(source, /if \(length < 4\) {[\s\S]*?return bgp_attr_encap_malformed\(\s*args, BGP_NOTIFY_UPDATE_OPT_ATTR_ERR\);/);
assert.match(source, /if \(args->type == BGP_ATTR_ENCAP\)\s*return bgp_attr_malformed\(args, subcode, args->total\);/);
assert.match(source, /case BGP_ATTR_ENCAP:\s*return BGP_ATTR_PARSE_WITHDRAW;/);
assert.match(packetSource, /#define NLRI_ATTR_ARG \(attr_parse_ret != BGP_ATTR_PARSE_WITHDRAW \? &attr : NULL\)/);
assert.match(packetSource, /update_len = end - stream_pnt\(s\);/);
assert.match(packetSource, /bgp_nlri_parse\(peer, NLRI_ATTR_ARG,/);
assert(packetSource.indexOf('if (stream_pnt(s) + attribute_len > end)')
    < packetSource.indexOf('attr_parse_ret = bgp_attr_parse('), 'caller bounds-checks attribute field');

const stream = { base: 4096, getp: 0 };
const align = vm.runInNewContext(`(function(ret, endp) { ${alignment[1]} })`, {
    BGP_ATTR_PARSE_WITHDRAW: -2,
    peer: {},
    BGP_INPUT: () => stream,
    STREAM_DATA: input => input.base,
    stream_set_getp: (input, offset) => { input.getp = offset; }
});

function attribute(flags, type, value, extended = false) {
    const header = Buffer.alloc(extended ? 4 : 3);
    header[0] = flags | (extended ? 0x10 : 0);
    header[1] = type;
    if (extended) header.writeUInt16BE(value.length, 2);
    else header[2] = value.length;
    return Buffer.concat([header, value]);
}

function update(attributes, nlri, withdrawn = Buffer.alloc(0)) {
    const header = Buffer.alloc(19, 0xff);
    const withdrawLength = Buffer.alloc(2);
    const attributeLength = Buffer.alloc(2);
    withdrawLength.writeUInt16BE(withdrawn.length);
    attributeLength.writeUInt16BE(attributes.length);
    const packet = Buffer.concat([header, withdrawLength, withdrawn, attributeLength, attributes, nlri]);
    packet.writeUInt16BE(packet.length, 16);
    packet[18] = 2;
    return { packet, attributeStart: 23 + withdrawn.length,
        attributeEnd: 23 + withdrawn.length + attributes.length };
}

function prefixes(bytes) {
    const result = [];
    for (let offset = 0; offset < bytes.length;) {
        const length = bytes[offset++];
        assert(length <= 32, 'invalid IPv4 NLRI prefix length');
        const size = Math.ceil(length / 8);
        assert(offset + size <= bytes.length, 'truncated IPv4 NLRI');
        const address = Buffer.alloc(4);
        bytes.copy(address, 0, offset, offset + size);
        result.push(`${[...address].join('.')}/${length}`);
        offset += size;
    }
    return result;
}

const mandatory = Buffer.concat([
    attribute(0x40, 1, Buffer.from([0])),
    attribute(0x40, 2, Buffer.from([2, 1, 0xfd, 0xe8])),
    attribute(0x40, 3, Buffer.from([192, 0, 2, 1]))
]);
const largeCommunity = attribute(0xc0, 32, Buffer.from([
    0, 0, 0xfd, 0xe8, 0, 0, 0, 1, 0, 0, 0, 2
]));
const nlri = Buffer.from([24, 203, 0, 113, 24, 198, 51, 100]);
const expected = ['203.0.113.0/24', '198.51.100.0/24'];
let cases = 0;
for (const extended of [false, true]) {
    for (const partial of [false, true]) {
        const malformedEncap = attribute(partial ? 0xe0 : 0xc0, 23, Buffer.from([0]), extended);
        const invalidOriginFlags = attribute(0x80, 1, Buffer.from([0]), extended);
        for (const [before, malformed] of [[mandatory, malformedEncap], [Buffer.alloc(0), invalidOriginFlags]]) {
            for (const trailingFlags of [0x40, 0x80, 0xc0, 0xe0]) {
                const trailing = trailingFlags === 0xc0 ? largeCommunity
                    : attribute(trailingFlags, 99, Buffer.from([0]));
                for (const suffix of [trailing, Buffer.concat([largeCommunity,
                    attribute(trailingFlags, 99, Buffer.from([0]))]), Buffer.alloc(0)]) {
                    for (const announced of [nlri, Buffer.alloc(0)]) {
                        const attributes = Buffer.concat([before, malformed, suffix]);
                        const fixture = update(attributes, announced, Buffer.from([24, 192, 0, 2]));
                        const staleGetp = fixture.attributeStart + before.length + malformed.length;
                        if (suffix.length) {
                            assert.throws(() => prefixes(fixture.packet.subarray(staleGetp)), /prefix length/,
                                'negative control: old exit interprets trailing flags as NLRI');
                        }
                        stream.getp = staleGetp;
                        align(-2, stream.base + fixture.attributeEnd);
                        assert.equal(stream.getp, fixture.attributeEnd);
                        assert.deepEqual(fixture.packet.subarray(stream.getp), announced);
                        const withdrawn = prefixes(fixture.packet.subarray(stream.getp));
                        assert.deepEqual(withdrawn, announced.length ? expected : []);
                        const routes = new Set([...expected, '10.0.0.0/8']);
                        for (const prefix of withdrawn) routes.delete(prefix);
                        assert.deepEqual([...routes], announced.length ? ['10.0.0.0/8'] : [...expected, '10.0.0.0/8']);
                        for (const otherResult of [0, -1, -3]) {
                            stream.getp = staleGetp;
                            align(otherResult, stream.base + fixture.attributeEnd);
                            assert.equal(stream.getp, staleGetp, 'non-WITHDRAW exit unchanged');
                        }
                        cases++;
                    }
                }
            }
        }
    }
}
console.log(`PASS: BGP WITHDRAW source contracts and ${cases} packet/alignment models (not compiled bgpd)`);