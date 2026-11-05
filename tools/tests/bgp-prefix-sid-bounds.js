const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/frr-8.1/bgpd/bgp_attr.c'), 'utf8');

function functionBody(name, nextName) {
    const start = source.indexOf(name);
    assert.notEqual(start, -1, `${name} exists`);
    const end = source.indexOf(nextName, start);
    assert.notEqual(end, -1, `${nextName} follows ${name}`);
    return source.slice(start, end);
}

const prefixSid = functionBody('bgp_attr_parse_ret_t bgp_attr_prefix_sid(',
    '/* PMSI tunnel attribute');
const psidSub = functionBody('static bgp_attr_parse_ret_t bgp_attr_psid_sub(',
    '/* Prefix SID attribute');
const service = functionBody('bgp_attr_srv6_service(struct bgp_attr_parser_args *args, size_t available)',
    '/*\n * Read an individual SID value');
const serviceData = functionBody('bgp_attr_srv6_service_data(struct bgp_attr_parser_args *args,',
    '/* SRv6 Service Sub-TLV attribute');

assert.match(prefixSid, /args->length - psid_parsed_length < headersz/,
    'top-level TLV header is contained by Prefix-SID attribute');
assert.match(prefixSid, /length > args->length - psid_parsed_length - headersz/,
    'top-level TLV body is contained by Prefix-SID attribute');
assert.match(psidSub, /if \(length < 1 \|\| STREAM_READABLE\(peer->curr\) < length\)/,
    'SRv6 L3 Service reserved byte requires a nonempty value');
assert.match(psidSub, /if \(length < 1[\s\S]*?return bgp_attr_malformed\(/,
    'short SRv6 L3 Service values use normal malformed-attribute handling');
assert.match(psidSub, /bgp_attr_srv6_service\(args, length - 1\)/,
    'service parser receives only bytes inside its parent TLV');
assert.match(service, /if \(length < BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_INFO_LENGTH\)/,
    'SID Information fixed fields are length-checked before reads');
assert.match(service, /if \(length < BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_INFO_LENGTH\)[\s\S]*?return bgp_attr_malformed\(/,
    'short SID Information values use normal malformed-attribute handling');
assert.match(service, /length > available - headersz/,
    'SID Information body is contained by the service TLV');
assert.match(serviceData, /if \(length < BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_STRUCTURE_LENGTH\)/,
    'SID Structure fixed fields are length-checked before reads');
assert.match(serviceData, /if \(length < BGP_PREFIX_SID_SRV6_L3_SERVICE_SID_STRUCTURE_LENGTH\)[\s\S]*?return bgp_attr_malformed\(/,
    'short SID Structure values use normal malformed-attribute handling');
assert.match(serviceData, /length > available - headersz/,
    'SID Structure body is contained by the SID Information TLV');
for (const body of [service, serviceData]) {
    assert.match(body, /available < headersz/,
        'nested TLV header is contained by its parent');
}

function malformedByLength(parentLength, headerLength, bodyLength, minimum) {
    return parentLength < headerLength || bodyLength > parentLength - headerLength
        || bodyLength < minimum;
}

let cases = 0;
const reportedAttribute = Buffer.from([0xc0, 0x28, 0x03, 0x05, 0x00, 0x00]);
const reportedUpdate = Buffer.alloc(29, 0xff);
reportedUpdate.writeUInt16BE(reportedUpdate.length, 16);
reportedUpdate[18] = 2;
reportedUpdate.writeUInt16BE(0, 19);
reportedUpdate.writeUInt16BE(reportedAttribute.length, 21);
reportedAttribute.copy(reportedUpdate, 23);
assert.deepEqual(reportedUpdate.subarray(23), reportedAttribute,
    'no-NLRI UPDATE ends with the reported Prefix-SID attribute bytes');
assert(malformedByLength(reportedAttribute[5], 0, reportedAttribute[5], 1),
    'empty SRv6 L3 Service TLV rejected');
cases++;
for (let length = 0; length < 21; length++) {
    assert(malformedByLength(length, 0, length, 21), `short SID Information length ${length} rejected`);
    cases++;
}
for (let length = 0; length < 6; length++) {
    assert(malformedByLength(length, 0, length, 6), `short SID Structure length ${length} rejected`);
    cases++;
}
assert(malformedByLength(3, 3, 1, 0), 'nested TLV overrun of SID Information rejected');
assert(malformedByLength(4, 3, 2, 0), 'nested TLV body beyond parent rejected');
assert(!malformedByLength(21, 0, 21, 21), 'minimum SID Information length accepted');
assert(!malformedByLength(6, 0, 6, 6), 'minimum SID Structure length accepted');
cases += 4;

console.log(`PASS: Prefix-SID nested length contracts and ${cases} boundary cases (not compiled bgpd)`);