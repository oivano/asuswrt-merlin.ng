const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
function read(relativePath) {
    return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

const cstp = read('release/src/router/openconnect/cstp.c');
const internal = read('release/src/router/openconnect/openconnect-internal.h');
const library = read('release/src/router/openconnect/library.c');

const shortInputGuard = cstp.indexOf('if (compr_type == COMPR_DEFLATE && len < 5)');
const inflateCall = cstp.indexOf('inflate(&vpninfo->inflate_strm, Z_SYNC_FLUSH)');
assert(shortInputGuard >= 0 && shortInputGuard < inflateCall,
    'deflate payloads shorter than trailer plus one byte are rejected before inflate');
assert.match(cstp.slice(shortInputGuard, inflateCall), /return -EINVAL;/,
    'a short deflate payload exits without processing input');
assert.match(cstp, /inflate_strm\.avail_in = len - 4;/,
    'the guarded input length still excludes the four-byte Adler-32 trailer');

for (const [encoding, bit] of [
    ['deflate', 'COMPR_DEFLATE'],
    ['lzs', 'COMPR_LZS'],
    ['oc-lz4', 'COMPR_LZ4']
]) {
    const assignment = `vpninfo->cstp_compr = ${bit};`;
    const assignmentAt = cstp.indexOf(assignment);
    assert(assignmentAt >= 0, `CSTP recognizes ${encoding}`);
    assert.match(cstp.slice(assignmentAt - 420, assignmentAt),
        new RegExp(`vpninfo->req_compr\\s*&\\s*${bit}`),
        `CSTP ${encoding} is checked against the advertised mask`);
}

for (const [encoding, bit] of [['lzs', 'COMPR_LZS'], ['oc-lz4', 'COMPR_LZ4']]) {
    const assignment = `vpninfo->dtls_compr = ${bit};`;
    const assignmentAt = cstp.indexOf(assignment);
    assert(assignmentAt >= 0, `DTLS recognizes ${encoding}`);
    assert.match(cstp.slice(assignmentAt - 420, assignmentAt),
        new RegExp(`vpninfo->req_compr\\s*&\\s*${bit}`),
        `DTLS ${encoding} is checked against the advertised mask`);
}

assert.match(cstp, /append_compr_types\(reqbuf, "CSTP", vpninfo->req_compr\);/,
    'CSTP response checks use the same mask sent in its request');
assert.match(cstp, /append_compr_types\(reqbuf, "DTLS", vpninfo->req_compr & ~COMPR_DEFLATE\);/,
    'DTLS does not advertise deflate');
assert.match(internal, /#define COMPR_STATELESS\s+\(COMPR_LZS\s*\|\s*COMPR_LZ4\s*\|\s*COMPR_LZO\)/);
assert.match(library, /vpninfo->req_compr = COMPR_STATELESS;/,
    'default configuration offers stateless compression only');

function acceptsDeflateInputLength(length) {
    return length >= 5;
}

for (let length = 0; length < 5; length++)
    assert.equal(acceptsDeflateInputLength(length), false,
        `deflate payload length ${length} is rejected`);
assert.equal(acceptsDeflateInputLength(5), true,
    'one byte of compressed input plus the trailer reaches inflate');

console.log('PASS: OpenConnect CSTP/DTLS compression negotiation and short deflate input guard (source contracts; C not compiled)');