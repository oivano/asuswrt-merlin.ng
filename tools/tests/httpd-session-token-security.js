const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const httpd = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.c'), 'utf8');
const header = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.h'), 'utf8');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');

const randomReader = httpd.match(/static int\nhttpd_read_random\([\s\S]*?\n}\n/);
const tokenGenerator = httpd.match(/int\nhttpd_gen_asus_token_cookie\([\s\S]*?\n}\n/);
assert(randomReader, 'source-owned random reader exists');
assert(tokenGenerator, 'source-owned cookie generator exists');
assert.match(randomReader[0], /open\("\/dev\/urandom", O_RDONLY\)/);
assert.match(randomReader[0], /while \(offset < length\)/);
assert.match(randomReader[0], /read\(fd, buffer \+ offset, length - offset\)/);
assert.match(randomReader[0], /count < 0 && errno == EINTR/);
assert.match(randomReader[0], /count <= 0/);
assert.match(randomReader[0], /close\(fd\)/);
assert.match(tokenGenerator[0], /unsigned char random_bytes\[31\]/);
assert.match(tokenGenerator[0], /charset\[random_bytes\[index\] % \(sizeof\(charset\) - 1\)\]/);
assert.match(tokenGenerator[0], /add_asus_token\(token\)/);
assert.match(tokenGenerator[0], /"%s=%s; HttpOnly;%s"/);
assert.doesNotMatch(tokenGenerator[0] + randomReader[0], /\b(?:srand|rand)\s*\(/);
assert.match(tokenGenerator[0], /name = "asus_s_token"/);
assert.match(tokenGenerator[0], /secure = " Secure;"/);
assert.match(header, /httpd_gen_asus_token_cookie/);
assert.doesNotMatch(httpd + web + header, /\bgen_asus_token_cookie\s*\(/);

const sessionStruct = httpd.match(/struct browser_session \{[\s\S]*?\} browser_sessions/);
assert(sessionStruct);
assert.match(sessionStruct[0], /uaddr peer;/);
const registration = httpd.match(/browser_session_register\([^;]+\)\n\{[\s\S]*?\n}\n/);
assert(registration);
assert.match(registration[0], /slot->peer = login_uip_tmp/);
const peerGate = httpd.match(/browser_session_peer_allowed\(const char \*cookies\)[\s\S]*?\n}\n/);
assert(peerGate);
assert.match(peerGate[0], /session->authenticated/);
assert.match(peerGate[0], /uaddr_is_unspecified/);
assert.match(peerGate[0], /uaddr_is_equal\(&session->peer, &peer\)/);
const authCall = httpd.indexOf('auth_result = auth_check(url, file, cookies, fromapp, &add_try);');
const addressCheck = httpd.indexOf('browser_session_peer_allowed(cookies)', authCall - 300);
assert(addressCheck >= 0 && addressCheck < authCall,
    'full peer binding runs before the native auth checker');
assert.match(httpd, /if \(!browser_session_peer_allowed\(cookies\)\)/,
    'User-Agent classification does not bypass the peer-address check');
assert.match(httpd, /uip->family = AF_INET;\s*uip->in\.s_addr = uip->in6\.s6_addr32\[3\]/);
assert.match(httpd, /case AF_INET6:\s*return IN6_ARE_ADDR_EQUAL\(&a->in6, &b->in6\)/);

const alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
function tokenFromBytes(bytes) {
    return [...bytes].map(value => alphabet[value % alphabet.length]).join('');
}
const tokenA = tokenFromBytes(Buffer.alloc(31, 1));
const tokenB = tokenFromBytes(Buffer.alloc(31, 2));
assert.equal(tokenA.length, 31);
assert.notEqual(tokenA, tokenB, 'independent random reads produce distinct token streams');
assert(31 * Math.log2(256 / 5) >= 128,
    '31 base-62 characters retain at least 128 bits of min-entropy after modulo reduction');

function peerEqual(left, right) {
    return left.family === right.family && left.bytes.every((byte, index) => byte === right.bytes[index]);
}
const v4 = { family: 4, bytes: [192, 0, 2, 7] };
const mappedV4 = { family: 4, bytes: [192, 0, 2, 7] };
const v6SameLow32 = { family: 6, bytes: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 7] };
const otherV6 = { family: 6, bytes: [0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 1, 192, 0, 2, 7] };
assert(peerEqual(v4, mappedV4), 'IPv4-mapped peers normalize to IPv4');
assert(!peerEqual(v4, v6SameLow32), 'IPv4 and IPv6 peers with the same low 32 bits differ');
assert(!peerEqual(v6SameLow32, otherV6), 'the complete IPv6 address is compared');

console.log('httpd session token security: source contracts and address-binding models passed (not compiled C)');