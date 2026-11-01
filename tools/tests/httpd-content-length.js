const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const httpd = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.c'), 'utf8');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');

assert.match(httpd, /#define HTTPD_MAX_FORM_BODY \(65535 - 1\)/);
assert.match(httpd, /#define HTTPD_MAX_UPLOAD_BODY \(64 \* 1024 \* 1024\)/);
assert.match(httpd, /upgrade\.cgi\*\|upload\.cgi\*\|jffsupload\.cgi\*\|vpnupload\.cgi\*\|upload_server_ovpn_cert\.cgi\*\|splash_page\.cgi\*\|ipsecupload\.cgi\*\|caupload\.cgi\*/);

const lengthStart = httpd.indexOf('else if (strncasecmp( cur, "Content-Length:"');
const lengthEnd = httpd.indexOf('else if (strncasecmp( cur, "Transfer-Encoding:"', lengthStart);
assert(lengthStart >= 0 && lengthEnd > lengthStart);
const contentLength = httpd.slice(lengthStart, lengthEnd);
assert.match(contentLength, /content_length_seen\+\+/);
assert.match(contentLength, /strtoul\(cp, &end, 10\)/);
assert.match(contentLength, /parsed_length > HTTPD_MAX_UPLOAD_BODY/);
assert.match(contentLength, /cl = \(int\)parsed_length/);

const limitCheck = httpd.indexOf('if (cl > httpd_request_body_limit(url))');
const dispatch = httpd.indexOf('for (handler = &mime_handlers[0]; handler->pattern; handler++)');
assert(limitCheck >= 0 && limitCheck < dispatch, 'body limit must be checked before handler dispatch');
assert.doesNotMatch(httpd, /while \(cl--\)\s*\(void\)fgetc\(conn_fp\)/);

const formStart = web.indexOf('static void do_html_post_and_get(char *url, FILE *stream, int len, char *boundary){');
const formEnd = web.indexOf('static void do_html_get(', formStart);
assert(formStart >= 0 && formEnd > formStart);
const formParser = web.slice(formStart, formEnd);
assert.match(formParser, /while \(len > 0\) \{\s*if \(fgetc\(stream\) == EOF\)\s*break;/);
assert.doesNotMatch(formParser, /while\s*\(len--\)/);

function parseLength(value) {
    if (!/^[0-9]+$/.test(value)) return null;
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) && parsed <= 64 * 1024 * 1024 ? parsed : null;
}

assert.equal(parseLength('65534'), 65534);
assert.equal(parseLength(String(64 * 1024 * 1024)), 64 * 1024 * 1024);
for (const value of ['2147483647', '4294967296', '-1', '+1', '12x', ''])
    assert.equal(parseLength(value), null, `reject invalid or oversized Content-Length ${JSON.stringify(value)}`);

console.log('httpd Content-Length bounds and EOF-safe draining checks passed');