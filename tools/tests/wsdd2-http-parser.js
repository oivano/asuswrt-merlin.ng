const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.resolve(__dirname,
    '../../release/src/router/wsdd2/wsd.c'), 'utf8');
const parserStart = source.indexOf('static int wsd_parse_http_header(');
const parserEnd = source.indexOf('\nint wsd_init(', parserStart);
assert(parserStart >= 0 && parserEnd > parserStart, 'HTTP parser exists');
const parser = source.slice(parserStart, parserEnd);

const requestLineEnd = parser.indexOf('char *eol = strstr(p, "\\r\\n");');
const nullGuard = parser.indexOf('if (!eol) {', requestLineEnd);
const nullWrite = parser.indexOf('*eol = \'\\0\';', requestLineEnd);
assert(requestLineEnd >= 0, 'request-line CRLF search exists');
assert(nullGuard > requestLineEnd && nullGuard < nullWrite,
    'missing CRLF is rejected before the request-line terminator is written');
assert.match(parser.slice(nullGuard, nullWrite), /return 400;/,
    'unterminated request line returns HTTP 400');
assert.match(source,
    /if \(status > 200\) \{\s*send_http_resp_header\(fd, ep, &sa, status, 0\);[\s\S]*?close\(fd\);\s*return 0;/,
    'parser errors are answered and the TCP connection is closed');

function requestLineStatus(data) {
    const eol = data.indexOf('\r\n');
    if (eol < 0) return 400;
    return 200;
}

assert.equal(requestLineStatus('POST /x'), 400,
    'request line without CRLF is rejected');
assert.equal(requestLineStatus('POST /x\r\n'), 200,
    'request line with CRLF passes this validation');

console.log('wsdd2-http-parser: missing request-line CRLF rejected');