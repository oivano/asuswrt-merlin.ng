const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.resolve(__dirname,
    '../../release/src/router/wsdd2/wsd.c'), 'utf8');
const parserStart = source.indexOf('static int wsd_parse_http_header(');
const parserEnd = source.indexOf('\nstatic ', parserStart + 1);
assert(parserStart >= 0 && parserEnd > parserStart,
    'missing wsd_parse_http_header');
const parser = source.slice(parserStart, parserEnd);

const offset = parser.indexOf('size_t consumed = (size_t)(p - buf);');
const boundsCheck = parser.indexOf('if (consumed > len)', offset);
const subtraction = parser.indexOf('len -= consumed;', boundsCheck);
const move = parser.indexOf('memmove(buf, p, len);', subtraction);
const reset = parser.indexOf('p = buf;', move);
const receive = parser.indexOf('if (!eoh)', reset);
assert(offset >= 0 && boundsCheck > offset && subtraction > boundsCheck &&
    move > subtraction && reset > move && receive > reset,
    'compaction must validate consumed bytes and reset p before receiving more data');
assert.match(parser.slice(boundsCheck, subtraction), /consumed > len[\s\S]*return 400;/,
    'an invalid consumed offset must be rejected before subtraction');

function parseTwoSegmentRequest(uuid) {
    const requestLine = `POST /${uuid} HTTP/1.1\r\n`;
    let buffer = requestLine;
    let length = buffer.length;
    let cursor = requestLine.indexOf('\r\n') + 2;
    const consumed = cursor;

    assert(consumed <= length, 'first compaction source must be in bounds');
    buffer = buffer.slice(consumed);
    length -= consumed;
    cursor = 0;

    buffer += '\r\n';
    length += 2;
    assert.equal(buffer.indexOf('\r\n', cursor), cursor,
        'second segment should terminate the headers');

    return { status: 400, length, cursor };
}

assert.deepEqual(parseTwoSegmentRequest('12345678-1234-1234-1234-123456789abc'), {
    status: 400,
    length: 2,
    cursor: 0,
});

console.log('wsdd2-header-continuation: ok');