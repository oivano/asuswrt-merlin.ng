const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/key/af_key.c'), 'utf8');

const parserStart = source.indexOf('parse_ipsecrequest(struct xfrm_policy *xp');
const parserEnd = source.indexOf('\nstatic int\nparse_ipsecrequests', parserStart);
assert.notEqual(parserStart, -1);
assert.notEqual(parserEnd, -1);
const requestParser = source.slice(parserStart, parserEnd);
assert.match(requestParser, /parse_sockaddr_pair\(\(struct sockaddr \*\)\(rq \+ 1\),\s*rq_len - sizeof\(\*rq\)/);

const requestsStart = parserEnd;
const requestsEnd = source.indexOf('\nstatic ', requestsStart + 1);
const requestsParser = source.slice(requestsStart, requestsEnd);
assert.match(requestsParser,
    /if \(\(unsigned int\)pol->sadb_x_policy_len \* 8 <\s*sizeof\(struct sadb_x_policy\)\)\s*return -EINVAL;/);
assert.match(requestsParser, /while \(len > 0\)/);
assert.match(requestsParser, /if \(len < sizeof\(\*rq\)\)\s*return -EINVAL;/);
assert.match(requestsParser, /rq_len = rq->sadb_x_ipsecrequest_len;/);
assert.match(requestsParser,
    /if \(rq_len < sizeof\(\*rq\) \|\| rq_len > len \|\| \(rq_len & 7\)\)\s*return -EINVAL;/);
assert.match(requestsParser, /len -= rq_len;/);
assert.match(requestsParser, /\(u8\*\)rq \+ rq_len/);

const pairStart = source.indexOf('static int parse_sockaddr_pair(', requestsEnd);
const pairEnd = source.indexOf('\n#ifdef CONFIG_NET_KEY_MIGRATE', pairStart);
assert.notEqual(pairStart, -1);
assert.notEqual(pairEnd, -1);
const pairParser = source.slice(pairStart, pairEnd);
assert.match(pairParser,
    /if \(ext_len < \(int\)sizeof\(sa_family_t\)\)\s*return -EINVAL;[\s\S]*?sa->sa_family/);
assert.match(pairParser, /ext_len < pfkey_sockaddr_pair_size\(sa->sa_family\)/);

function validPolicyHeaderLength(length, headerLength) {
    return length >= headerLength;
}

function parseRecords(extensionLength, records) {
    let remaining = extensionLength;
    for (const record of records) {
        if (remaining <= 0 || remaining < record.headerLength)
            return false;
        if (record.length < record.headerLength || record.length > remaining ||
            record.length % 8 !== 0)
            return false;
        if (record.tunnel &&
            record.length - record.headerLength < record.addressPairLength)
            return false;
        remaining -= record.length;
    }
    return remaining === 0;
}

const header = 16;
const ipv4Pair = 32;
const ipv6Pair = 56;
assert.equal(validPolicyHeaderLength(0, header), false, 'zero-length policy extension');
assert.equal(validPolicyHeaderLength(header - 1, header), false,
    'policy extension shorter than header');
assert.equal(validPolicyHeaderLength(header, header), true, 'header-only policy extension');
assert.equal(parseRecords(0, []), true, 'empty policy request list');
assert.equal(parseRecords(header, [{ headerLength: header, length: 0 }]), false,
    'zero-length request');
assert.equal(parseRecords(header, [{ headerLength: header, length: header - 1 }]), false,
    'request shorter than header');
assert.equal(parseRecords(header, [{ headerLength: header, length: header + 8 }]), false,
    'request extending past policy extension');
assert.equal(parseRecords(header + 8,
    [{ headerLength: header, length: header + 8, tunnel: true, addressPairLength: ipv6Pair }]), false,
    'truncated tunnel sockaddr pair');
assert.equal(parseRecords(header + ipv4Pair,
    [{ headerLength: header, length: header + ipv4Pair, tunnel: true, addressPairLength: ipv4Pair }]), true,
    'complete IPv4 tunnel sockaddr pair');
assert.equal(parseRecords(header + ipv6Pair,
    [{ headerLength: header, length: header + ipv6Pair, tunnel: true, addressPairLength: ipv6Pair }]), true,
    'complete IPv6 tunnel sockaddr pair');
assert.equal(parseRecords(header + 1, [{ headerLength: header, length: header }]), false,
    'trailing fragment smaller than request header');
assert.equal(parseRecords(header + 8, [{ headerLength: header, length: header + 1 }]), false,
    'misaligned request stride');

console.log('PASS: AF_KEY request and tunnel-address bounds source/model checks; not compiled-kernel execution');