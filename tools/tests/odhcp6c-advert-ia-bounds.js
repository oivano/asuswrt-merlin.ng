const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(
    path.join(root, 'release/src/router/odhcp6c/src/dhcpv6.c'), 'utf8');

function functionBody(signature) {
    const start = source.indexOf(signature);
    assert.ok(start >= 0, `missing ${signature}`);
    const open = source.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < source.length; index++) {
        if (source[index] === '{') depth++;
        if (source[index] === '}' && --depth === 0)
            return source.slice(open + 1, index);
    }
    assert.fail(`unterminated ${signature}`);
}

const advert = functionBody('dhcpv6_handle_advert(');
assert.match(advert, /dhcpv6_parse_ia\(ia_hdr,\s*odata \+ olen\s*\)/);
assert.doesNotMatch(advert, /dhcpv6_parse_ia\(ia_hdr,\s*odata \+ olen \+/);

const datagramEnd = 1536;
const iaDataOffset = datagramEnd - 25;
const prefixDataOffset = iaDataOffset + 12 + 4;
const declaredPrefixLength = 25;
const availablePrefixLength = datagramEnd - prefixDataOffset;
const wrongEnd = datagramEnd + 16;

assert.equal(availablePrefixLength, 9);
assert.equal(prefixDataOffset + declaredPrefixLength, wrongEnd);
assert.ok(prefixDataOffset + declaredPrefixLength > datagramEnd,
    'a truncated IA_PREFIX must not fit within the received datagram');

console.log('PASS: Advertise IA parsing ends at the IA option boundary (1536-byte truncated-prefix boundary model)');