const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const src = fs.readFileSync(path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/xt_webstr.c'), 'utf8');

function body(start, end) {
    const a = src.indexOf(start);
    assert(a >= 0, `missing ${start}`);
    const b = src.indexOf(end, a + start.length);
    assert(b > a, `missing ${end}`);
    return src.slice(a, b);
}

// Source contracts (the disabled #if 0 mangle helper is excluded).
const active = src.replace(/#if 0[\s\S]*?#endif/g, '');
assert.doesNotMatch(active, /get_http_info6|match6|payload_len|ihl\*4/);
const parser = body('static int get_http_info(', 'static int url_has_suffix(');
assert.match(parser, /skb_header_pointer\(skb, thoff, sizeof\(_tcph\), &_tcph\)/);
assert.match(parser, /tcph->doff \* 4 < sizeof\(_tcph\)/);
assert.match(parser, /dataoff >= skb_headlen\(skb\)/);
assert.match(parser, /datalen = skb_headlen\(skb\) - dataoff;/);
assert.match(parser, /found != 1 \|\| !hostlen/);
assert.match(parser, /found != 1 \|\| pathlen <= sizeof\(" HTTP\/x\.x"\) - 1/);
const finder = body('static int find_pattern2(', '#if 0');
assert.match(finder, /j < dlen && data\[j\] != term/);
assert.match(finder, /if \(j >= dlen\)\s*return -1;/);
const matcher = body('static bool match(', 'static int checkentry(');
const init = matcher.indexOf('htinfo.hostlen = htinfo.urllen = 0;');
assert(init > 0 && init < matcher.indexOf('get_http_info('), 'lengths must be initialised before parsing');
assert.match(matcher, /par->fragoff != 0/);
assert.match(matcher, /get_http_info\(skb, par->thoff, flags, &htinfo\)/);
assert.match(matcher, /hlen = \(parsed > 1\) \? htinfo\.urllen : 0;/);
assert.match(matcher, /else if \(parsed > 1\) \{\s*\/\* IPT_WEBSTR_CONTENT \*\//);
assert.doesNotMatch(matcher, /htinfo\.url \+ htinfo\.urllen - vicelen/);
assert.match(src, /htinfo->urllen >= len &&/);
const reg = body('static struct xt_match xt_webstr_match[]', 'static int __init init(');
assert.equal((reg.match(/\.proto\t*= IPPROTO_TCP,/g) || []).length, 2);
assert.equal((reg.match(/\.match\t*= match,/g) || []).length, 2);

// Model of the parser and matcher; every buffer access is bounds-checked.
const BUFSIZE = 1024;
function at(buf, i) {
    if (i < 0 || i >= buf.length) throw new RangeError(`read ${i} outside ${buf.length}`);
    return buf[i];
}
function nicmp(a, ai, b, n) {
    for (let k = 0; k < n; k++) {
        const x = at(a, ai + k).toLowerCase(), y = b[k].toLowerCase();
        if (x !== y) return 1;
        if (x === '\0') return 0;
    }
    return 0;
}
function findPattern(data, dlen, pat) {
    const plen = pat.length;
    if (dlen === 0) return { found: 0 };
    if (dlen <= plen) return { found: nicmp(data, 0, pat, dlen) === 0 ? -1 : 0 };
    let state = 0;
    for (let i = 0; i <= dlen - plen; i++) {
        const c = at(data, i);
        if (c === '\r') state = state % 2 ? 0 : state + 1;
        else if (c === '\n') state = state % 2 ? state + 1 : 0;
        else state = 0;
        if (state >= 4) break;
        if (data.slice(i, i + plen) !== pat) continue;
        let j = i + plen, k = 0;
        while (j < dlen && at(data, j) !== '\r') { j++; k++; }
        if (j >= dlen) return { found: -1, off: 0, len: 0 };
        return { found: 1, off: i + plen, len: k };
    }
    return { found: 0 };
}
function getHttpInfo(payload, info) {
    const data = payload, datalen = payload.length;
    if (datalen < 10 || !/^(GET |POST |HEAD )/.test(data)) return 0;
    let r = findPattern(data, datalen, 'Host: ');
    if (r.found !== 1 || !r.len) return 0;
    const hostlen = Math.min(r.len, BUFSIZE);
    info.host = data.substr(r.off, hostlen) + '\0';
    info.hostlen = hostlen;
    r = findPattern(data, datalen, 'GET ');
    if (!r.found) r = findPattern(data, datalen, 'POST ');
    if (!r.found) r = findPattern(data, datalen, 'HEAD ');
    if (r.found !== 1 || r.len <= 9) return 1;
    let pathlen = r.len - 9;
    pathlen = pathlen + hostlen < BUFSIZE ? pathlen : BUFSIZE - hostlen;
    info.url = info.host.slice(0, hostlen) + data.substr(r.off, pathlen) + '\0';
    info.urllen = hostlen + pathlen;
    return 2;
}
function urlMatch(payload, keyword) {
    const info = { host: '\0', url: '\0', hostlen: 0, urllen: 0 };
    const parsed = getHttpInfo(payload, info);
    if (parsed < 1) return { parsed, hlen: 0, found: false };
    const hlen = parsed > 1 ? info.urllen : 0;
    const nlen = keyword.length;
    if (!nlen || !hlen || nlen > hlen) return { parsed, hlen, found: false };
    for (let t = 0; t <= hlen - nlen; t++)
        if (nicmp(info.url, t, keyword, nlen) === 0) return { parsed, hlen, found: true };
    return { parsed, hlen, found: false };
}

// Reported exploit: host-only partial parse searches nothing.
let r = urlMatch('GET /\r\nHost: a\r\n', 'a');
assert.deepEqual(r, { parsed: 1, hlen: 0, found: false });
r = urlMatch('GET  HTTP/1.1\r\nHost: a\r\n', 'a');
assert.deepEqual(r, { parsed: 1, hlen: 0, found: false });
r = urlMatch('GET / HTTP/1.1\r\nHost: a\r\n', 'a/');
assert.deepEqual(r, { parsed: 2, hlen: 2, found: true });
// Normal requests still match.
assert.equal(urlMatch('GET /bad/path HTTP/1.1\r\nHost: example.com\r\n\r\n', 'BAD').found, true);
assert.equal(urlMatch('GET /ok HTTP/1.1\r\nHost: example.com\r\n\r\n', 'bad').found, false);
assert.equal(urlMatch('POST /x HTTP/1.1\r\nHost: evil.example\r\n\r\n', 'evil').found, true);
// Unterminated headers at the payload end never read past it.
for (const p of ['GET /x HTTP/1.1\r\nHost: abc', 'GET /abcdef', 'GET /x HTTP/1.1\r\nHost: a\r\nX']) urlMatch(p, 'a');
// Oversized host/path stays within BUFSIZE.
r = urlMatch(`GET /${'p'.repeat(3000)} HTTP/1.1\r\nHost: ${'h'.repeat(2000)}\r\n\r\n`, 'h');
assert.equal(r.hlen, BUFSIZE);

// Negative control: the old matcher used a stale urllen after a partial parse.
const stale = { url: 'a\0', urllen: 300000 };
assert.throws(() => { for (let t = 0; t <= stale.urllen - 1; t++) nicmp(stale.url, t, 'zz', 2); }, RangeError);

console.log('xt-webstr-bounds: ok');
