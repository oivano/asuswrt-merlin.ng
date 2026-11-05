const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = name => fs.readFileSync(path.join(root, 'release/src/router/phddns/src', name), 'latin1');
const md5 = source('md5.c');
const generate = source('generate.c');
const header = source('generate.h');
const update = source('phupdate.c');
const phddnsLog = source('log.c');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'latin1');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'latin1');
const minimum = Number(header.match(/#define PH_CHALLENGE_MIN_LEN (\d+)/)[1]);
const maximum = Number(header.match(/#define PH_CHALLENGE_MAX_LEN (\d+)/)[1]);
assert.equal(minimum, 10);
assert.equal(maximum, 64);

function body(text, signature) {
    const start = text.indexOf('{', text.indexOf(signature));
    let depth = 1;
    let end = start + 1;
    for (; depth; end++) {
        if (text[end] === '{') depth++;
        if (text[end] === '}') depth--;
        assert(end < text.length, 'balanced function body');
    }
    return text.slice(start + 1, end - 1);
}

const hmacBody = body(md5, 'unsigned int KeyMD5Encode(');
assert(hmacBody.indexOf('nKeyLen > PADLEN') < hmacBody.indexOf('memcpy(K,'));
assert(hmacBody.indexOf('nSize > MAXMD5SOURCESTRINGLEN') < hmacBody.indexOf('memcpy(firstPad + PADLEN,'));
const hmacJS = hmacBody
    .replace(/\/\/[^\n]*/g, '')
    .replace(/unsigned char /g, 'let ')
    .replace(/(\w+)\[([^\]]+)\] = \{0\}/g, '$1 = new Uint8Array($2)')
    .replace(/\bint i;/, 'let i;')
    .replace(/'\\x0'/g, '0')
    .replace(/memcpy\(firstPad \+ PADLEN, szData, nSize\)/, 'firstPad.set(szData.subarray(0, nSize), PADLEN)')
    .replace(/midResult \+ PADLEN/g, 'midResult.subarray(PADLEN)');
const hmac = new Function('szEncoded', 'szData', 'nSize', 'szKey', 'nKeyLen', 'memset', 'memcpy', 'MDString',
    `const PADLEN = 64, MAXMD5SOURCESTRINGLEN = 1024; ${hmacJS}`);
const fill = (target, value, length) => target.fill(value, 0, length);
const copy = (target, input, length) => target.set(input.subarray(0, length));
const digest = (input, length, output) => output.set(crypto.createHash('md5').update(input.subarray(0, length)).digest());
function runHmac(key, data, keyLength = key.length, dataLength = data.length) {
    const output = Buffer.alloc(16, 0xa5);
    const result = hmac(output, data, dataLength, key, keyLength, fill, copy, digest);
    return { result, output };
}
for (const keyLength of [0, 10, 16, 63, 64]) {
    for (const dataLength of [0, 8, 1024]) {
        const key = Buffer.alloc(keyLength, 0x3c);
        const data = Buffer.alloc(dataLength, 0x61);
        const actual = runHmac(key, data);
        assert.equal(actual.result, 16);
        assert.deepEqual(actual.output, crypto.createHmac('md5', key).update(data).digest());
    }
}
for (const keyLength of [65, 255, 0xffffffff]) {
    const actual = runHmac(Buffer.alloc(255), Buffer.from('password'), keyLength);
    assert.equal(actual.result, 0);
    assert.deepEqual(actual.output, Buffer.alloc(16, 0xa5));
}
assert.equal(runHmac(Buffer.alloc(16), Buffer.alloc(1025)).result, 0);

const generateBody = body(generate, 'int GenerateCrypt(');
assert.match(generateBody, /\bint nDecodedLen;/);
const guardStart = generateBody.indexOf("szResult[0] = '\\0';");
const timestampStart = generateBody.indexOf('uTemp = *(szDecoded +9)');
assert(guardStart >= 0 && timestampStart > guardStart);
const guardJS = generateBody.slice(guardStart, timestampStart).replace(/sizeof\(szDecoded\)/g, 'szDecoded.length');
const challengeGuard = new Function('szChallenge64', 'szResult', 'lutil_b64_pton',
    `const PH_CHALLENGE_MIN_LEN = ${minimum}, PH_CHALLENGE_MAX_LEN = ${maximum};
    const szDecoded = new Uint8Array(256); let nDecodedLen; ${guardJS}`);
function decodeModel(encoded) {
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) return -1;
    const decoded = Buffer.from(encoded, 'base64');
    if (decoded.toString('base64') !== encoded || decoded.length > 255) return -1;
    return decoded.length;
}
for (const length of [0, 1, 6, 9, 10, 16, 63, 64, 65, 255, 256]) {
    const encoded = Buffer.alloc(length, 0x42).toString('base64');
    const output = ['unchanged'];
    const result = challengeGuard(encoded, output, decodeModel);
    assert.equal(result, length >= minimum && length <= maximum ? undefined : -1);
    assert.equal(output[0], '\0');
}
for (const encoded of ['!', 'AAAA!', 'A', 'AA=A', 'AB==']) {
    assert.equal(challengeGuard(encoded, [], decodeModel), -1);
}
assert.match(generateBody, /if \(nKey != 16\)\s*return -1;/);
assert(generateBody.indexOf('if (nKey != 16)') < generateBody.indexOf('szKey[nKey]'));

const userGuardStart = generateBody.indexOf('nUser = strnlen(');
const userCopyStart = generateBody.indexOf('memcpy(szAscii, szUser, nUser)');
assert(userGuardStart > generateBody.indexOf('if (nKey != 16)'));
assert(userCopyStart > userGuardStart);
assert.match(generateBody, /size_t nUser;/);
const userGuardJS = generateBody.slice(userGuardStart, userCopyStart)
    .replace(/sizeof\(szAscii\)/g, '256');
const userGuard = new Function('szUser', 'nKey', 'strnlen',
    `let nUser; ${userGuardJS} return nUser;`);
const boundedLength = (user, limit) => Math.min(user.indexOf('\0') < 0 ? user.length : user.indexOf('\0'), limit);
for (const length of [0, 1, 128, 230, 231, 232, 255, 256, 760]) {
    assert.equal(userGuard('A'.repeat(length), 16, boundedLength), length <= 231 ? length : -1);
}
assert.equal(userGuard('user\0' + 'A'.repeat(760), 16, boundedLength), 4);

const executeBody = body(update, 'int ExecuteUpdate(');
const framing = executeBody.match(/if \((len < 6[^\n]+)\)\s*goto invalid_challenge;/)[1];
const framingJS = framing.replace(/sizeof\(buffer\)/g, '1024');
const framingInvalid = new Function('len', 'buffer', 'strncmp', `return ${framingJS};`);
const comparePrefix = (left, right, count) => left.slice(0, count).localeCompare(right.slice(0, count));
for (const [length, line, invalid] of [[4, '334 ', true], [6, '334 !', false],
    [1024, '334 ' + 'A'.repeat(1020), true], [28, '500 invalid', true],
    [30, '334 ' + Buffer.alloc(16).toString('base64'), false]]) {
    assert.equal(framingInvalid(length, line, comparePrefix), invalid);
}
const decoderOffset = executeBody.indexOf('lutil_b64_pton(buffer+4');
const generateOffset = executeBody.indexOf('len = GenerateCrypt(');
assert(executeBody.indexOf('goto invalid_challenge;') < decoderOffset);
const decodedGuard = executeBody.slice(decoderOffset, generateOffset);
assert.match(decodedGuard, /nChallengeLen < PH_CHALLENGE_MIN_LEN/);
assert.match(decodedGuard, /nChallengeLen > PH_CHALLENGE_MAX_LEN\)\s*goto invalid_challenge;/);
const failedSession = executeBody.slice(executeBody.indexOf('invalid_challenge:'), executeBody.indexOf('strcat(sendbuffer'));
assert.match(failedSession, /nChallengeLen = 0;/);
assert.match(failedSession, /memset\(phglobal->szChallenge, 0, sizeof\(phglobal->szChallenge\)\)/);
assert.match(failedSession, /phClose\(&phglobal->m_tcpsocket\)/);
assert.match(failedSession, /LOG\(1\) \("ExecuteUpdate invalid server challenge/);
assert.match(failedSession, /return errorConnectFailed;/);
assert.match(executeBody.slice(generateOffset), /if \(len <= 0 \|\| len > sizeof\(sendbuffer\) - 3\)/);
assert.doesNotMatch(executeBody, /SERVER SIDE KEY/);

const hostBody = body(update, 'static int ValidRedirectHost(');
const hostJS = hostBody
    .replace(/size_t offset, label = 0;/, 'let offset, label = 0;')
    .replace(/int numeric = 1;/, 'let numeric = 1;')
    .replace(/struct in_addr address;/, '')
    .replace(/unsigned char value = host\[offset\];/, 'let value = host.charCodeAt(offset);')
    .replace(/value == '\.'/g, 'value == 46')
    .replace(/value == '-'/g, 'value == 45')
    .replace(/value (>=|<=|<|>) '([a-zA-Z0-9])'/g,
        (_, operator, character) => `value ${operator} ${character.charCodeAt(0)}`)
    .replace(/inet_pton\(AF_INET, host, &address\)/, 'isIPv4(host)');
const validHost = new Function('host', 'length', 'isIPv4', hostJS);
const validate = host => Number(validHost(host, host.length, value => Number(net.isIP(value) === 4)));
const maxHost = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(61)].join('.');
for (const host of ['phddns60.oray.net', 'PHDDNS60.Oray.NET', '6.6.6.6', 'server', 'ddns-1.oray.net',
    'ddns.oray.net.', maxHost]) {
    assert.equal(validate(host), 1, host);
}
const badHosts = ['', 'A'.repeat(1000), '6.6.6.6 ' + 'A'.repeat(990),
    'a'.repeat(64) + '.net', maxHost + 'e', '.oray.net', 'oray..net', '-oray.net',
    'oray-.net', 'oray.net-', 'oray.net..', 'oray_net', '6.6.6.6:6060', '6.6.6.999',
    '127.1', '12345', 'oray.net/path', 'oray.net\t', 'oray.net\r', 'oray.net\n',
    'oray.net\0suffix', 'oray.net\xff', '::1', 'oray<net'];
for (const host of badHosts) assert.equal(validate(host), 0, JSON.stringify(host));

const ddnsBody = body(update, 'static int ValidDdnsHostname(')
    .replace(/size_t length =/, 'let length =');
const validDdns = new Function('host', 'strnlen', 'ValidRedirectHost', ddnsBody);
const validateDdns = host => Number(validDdns(host, boundedLength,
    (value, length) => validHost(value, length, address => Number(net.isIP(address) === 4))));
const storeMatch = executeBody.match(/if\(ValidDdnsHostname\(phglobal->szActiveDomains\[i\]\)\)\s*nvram_set\("ddns_hostname_x", phglobal->szActiveDomains\[i\]\);/);
assert(storeMatch, 'validate each server domain before writing NVRAM');
assert.equal((executeBody.match(/nvram_set\("ddns_hostname_x"/g) || []).length, 1);
const storeDdns = new Function('hostname', 'ValidDdnsHostname', 'nvram_set',
    storeMatch[0].replace(/phglobal->szActiveDomains\[i\]/g, 'hostname'));
const goodDdns = ['router.example', 'DDNS-1.Oray.NET', 'a'.repeat(63),
    'a'.repeat(59) + '.net', 'router.example.'];
const invalidDdns = [...badHosts.filter(host => !host.includes('\0')),
    '%n%n%s%s%x%x', 'router%p.example', 'router".example',
    "router'.example", 'a$(touch /tmp/pwn)', 'a`id`', 'a;b', 'a<b', 'a>b', 'two words',
    'a'.repeat(64), 'a'.repeat(60) + '.net', '.'];
assert.match(executeBody, /else\s*\{\s*LOG\(1\) \("ExecuteUpdate discarded invalid DDNS hostname\.\\n"\);\s*continue;/);
for (const [hosts, accepted] of [[goodDdns, true], [invalidDdns, false]]) {
    for (const host of hosts) {
        let stored = 'unchanged.example';
        let writes = 0;
        assert.equal(validateDdns(host), Number(accepted), JSON.stringify(host));
        storeDdns(host, validateDdns, (key, value) => {
            assert.equal(key, 'ddns_hostname_x');
            stored = value;
            writes++;
        });
        assert.equal(writes, Number(accepted), JSON.stringify(host));
        assert.equal(stored, accepted ? host : 'unchanged.example', JSON.stringify(host));
    }
}

const redirectStart = executeBody.indexOf('if (strcmp(buffer,"536") == 0)');
const redirectEnd = executeBody.indexOf('if (strcmp(buffer,"250") == 0)', redirectStart);
const redirect = executeBody.slice(redirectStart, redirectEnd);
assert.doesNotMatch(redirect, /strcpy/);
assert.match(redirect, /hostlen < sizeof\(phglobal->szHost\) &&\s*ValidRedirectHost/);
const redirectJS = redirect
    .replace(/strcmp\(buffer,"536"\) == 0/, 'true')
    .replace(/char \*pos0 = strchr\(buffer \+ 4, '<'\);/, "let pos0 = find(buffer, 4, '<');")
    .replace(/char \*pos1 = strchr\(pos0 \+ 1, '>'\);/, "let pos1 = find(buffer, pos0 + 1, '>');")
    .replace(/size_t hostlen/, 'let hostlen')
    .replace(/\*pos1 = '\\0';/, 'buffer = buffer.slice(0, pos1);')
    .replace(/sizeof\(phglobal->szHost\)/g, '256')
    .replace(/ValidRedirectHost\(pos0 \+ 1, hostlen\)/, 'validate(buffer.slice(pos0 + 1))')
    .replace(/memcpy\(phglobal->szHost, pos0 \+ 1, hostlen \+ 1\)/,
        'store(buffer.slice(pos0 + 1), hostlen + 1)')
    .replace(/&phglobal->m_tcpsocket/g, '0');
const runRedirect = new Function('buffer', 'find', 'validate', 'store', 'phClose', 'nvram_set',
    `const okRedirecting = 1, errorAuthFailed = -1; ${redirectJS}`);
const find = (line, offset, delimiter) => {
    const index = line.indexOf(delimiter, offset);
    return index < 0 ? null : index;
};
for (const line of [...badHosts.map(host => `536 <${host}>`), '536 missing', '536 <missing',
    '536 <phddns60.oray.net>', '536 <6.6.6.6>']) {
    const state = Buffer.alloc(1284, 0xa5);
    const before = Buffer.from(state);
    let closes = 0;
    const result = runRedirect(line, find, validate, (host, length) => {
        assert(length <= 256);
        Buffer.from(host + '\0', 'latin1').copy(state, 0);
    }, () => closes++, () => {});
    assert.equal(closes, 1);
    assert.deepEqual(state.subarray(256), before.subarray(256), 'adjacent configuration unchanged');
    if (['536 <phddns60.oray.net>', '536 <6.6.6.6>'].includes(line)) {
        assert.equal(result, 1);
    } else {
        assert.equal(result, -1);
        assert.deepEqual(state, before, 'invalid redirect leaves all configuration unchanged');
    }
}
const responseGuard = executeBody.indexOf('if (len < 5 || len >= sizeof(buffer))');
assert(responseGuard >= 0 && responseGuard < redirectStart);
assert(executeBody.slice(responseGuard, redirectStart).includes('return errorConnectFailed;'));
const responseExpression = executeBody.slice(responseGuard).match(/^if \(([^\n]+)\)/)[1];
const invalidResponse = new Function('len', `return ${responseExpression.replace(/sizeof\(buffer\)/, '1024')};`);
for (const length of [-1, 0, 3, 4, 1024]) assert.equal(invalidResponse(length), true);
assert.equal(invalidResponse(1023), false);

const readerBody = body(source('phsocket.c'), 'int phReadOneLine(');
const readerJS = readerBody
    .replace(/int nReadCount = 0;/, 'let nReadCount = 0;')
    .replace(/char value;/, 'const value = [];')
    .replace(/lpszBuf == NULL/g, 'lpszBuf == null')
    .replace(/&value/g, 'value')
    .replace(/value ==/g, 'value[0] ==')
    .replace(/= value;/g, '= value[0];');
const readLine = new Function('m_hSocket', 'lpszBuf', 'nBufLen', 'phDataReadable', 'recv', readerJS);
function stream(input, size = 255, timeout = false) {
    let offset = 0;
    return () => {
        const bytes = new Array(size).fill('\xa5');
        const guarded = new Proxy(bytes, { set(target, index, value) {
            assert(Number(index) >= 0 && Number(index) < size, 'socket buffer write is in bounds');
            target[index] = value;
            return true;
        } });
        const result = readLine(0, guarded, size, () => Number(!timeout), (fd, output) => {
            if (offset === input.length) return 0;
            output[0] = input[offset++];
            return 1;
        });
        assert(bytes.includes('\0'), 'every returned buffer is terminated');
        return { result, text: bytes.slice(0, bytes.indexOf('\0')).join('') };
    };
}
for (const [input, result, text] of [['router.example\r\n', 16, 'router.example'],
    ['router.example\n', 15, 'router.example'], ['.\r\n', 3, '.'], ['\n', 1, ''],
    ['A'.repeat(254) + '\n', 255, 'A'.repeat(254)],
    ['A'.repeat(255) + '\n', -1, 'A'.repeat(254)],
    ['A'.repeat(1024), -1, 'A'.repeat(254)], ['partial', -1, 'partial'],
    ['a\0suffix\n', -1, 'a']]) {
    const actual = stream(input)();
    assert.equal(actual.result, result);
    assert.equal(actual.text, text);
}
assert.equal(stream('partial', 255, true)().result, 0);
assert.equal(readLine(0, null, 255), -1);
assert.equal(readLine(0, [], 0), -1);
assert.equal(stream('\n', 1)().result, 1);
assert.equal(stream('a\n', 1)().result, -1);

const listStart = executeBody.indexOf('for (i=0,totaldomains=0;i<255;i++)');
const listEnd = executeBody.indexOf('phglobal->cLastResult = okDomainListed;', listStart);
const listBody = executeBody.slice(listStart, listEnd);
assert.doesNotMatch(listBody, /strcpy\(phglobal->szActiveDomains\[i\]/);
assert.match(listBody, /strcmp\(domains\[i\], "\."\) == 0/);
assert.match(listBody, /i == 255/);
const listJS = listBody
    .replace(/goto invalid_domain_list;/g, 'return failed();')
    .replace(/invalid_domain_list:/, '')
    .replace(/sizeof\(domains\[i\]\)/g, '255')
    .replace(/sizeof\(regicommand\)/g, '255')
    .replace(/sizeof\(COMMAND_REGI\)/g, '7')
    .replace(/len = phReadOneLine\([^;]+;/, 'const row = read(); len = row.result; domains[i] = row.text;')
    .replace(/LOG\(1\)[^;]+;/g, '')
    .replace(/memset\(phglobal->szActiveDomains, 0, sizeof\(phglobal->szActiveDomains\)\);/, '')
    .replace(/strcpy\(phglobal->szActiveDomains\[0\], "\."\);/, '')
    .replace(/phClose\(&phglobal->m_tcpsocket\);/, '')
    .replace(/nvram_set\([^;]+;/g, '')
    .replace(/return errorDomainListFailed;/, 'return failed();')
    .replace(/memcpy\(phglobal->szActiveDomains\[i\], domains\[i\], strlen\(domains\[i\]\) \+ 1\);/,
        'active.push(domains[i]);');
const parseList = new Function('read', 'ValidRedirectHost', 'strcmp', 'strlen',
    `let i, len, totaldomains; const domains = [], active = []; const failed = () => ({failed: true, active: []});
    ${listJS} return {failed: false, active, totaldomains};`);
const parse = input => parseList(stream(input), (host, length) => validHost(host, length,
    value => Number(net.isIP(value) === 4)), (left, right) => Number(left !== right), value => value.length);
const maxDomain = ['a'.repeat(63), 'b'.repeat(63), 'c'.repeat(63), 'd'.repeat(53)].join('.');
assert.equal(maxDomain.length, 245);
for (const input of ['A'.repeat(254) + '\n.\n', 'A'.repeat(255 * 3) + '\nshort\n.\n',
    maxDomain + 'd\n.\n', 'router.example\n', '.\n', '.bad\n.\n', 'router example\n.\n',
    'router\0.example\n.\n', 'router.example\rjunk\n.\n', 'router.example\n'.repeat(255) + '.\n']) {
    assert.deepEqual(parse(input), {failed: true, active: []});
}
for (const domains of [['router.example'], [maxDomain], new Array(254).fill('router.example')]) {
    const actual = parse(domains.join('\r\n') + '\r\n.\r\n');
    assert.equal(actual.failed, false);
    assert.equal(actual.totaldomains, domains.length);
    assert.deepEqual(actual.active, [...domains, '.']);
    for (const domain of domains) assert(Buffer.byteLength(`regi a ${domain}\r\n`) < 255);
}
const regiStart = executeBody.indexOf('//send domain regi commands list');
const regiEnd = executeBody.indexOf('//send confirm', regiStart);
const regiBody = executeBody.slice(regiStart, regiEnd);
assert.match(regiBody, /for \(i=0;i<totaldomains;i\+\+\)/);
assert.match(regiBody, /snprintf\(regicommand, sizeof\(regicommand\), "%s %s\\r\\n", COMMAND_REGI, domains\[i\]\)/);
assert.match(regiBody, /len < 0 \|\| len >= sizeof\(regicommand\)/);
assert.doesNotMatch(regiBody, /strcpy|strcat/);
assert.match(listBody, /Domain List Failed/);
assert.match(listBody, /phClose\(&phglobal->m_tcpsocket\)/);
assert.match(executeBody.slice(regiEnd), /for \(i=0;i<totaldomains;i\+\+\)/);
assert.match(body(update, 'static char *ReadStatResponse('), /if \(len <= 0\)\s*\{\s*free\(xmldata\);\s*return NULL;/);

const keys = [...update.match(/ddns_nvram_keys\[\] = \{([^}]+)\}/)[1].matchAll(/"([^"]+)"/g)].map(match => match[1]);
assert.deepEqual(keys, ['ddns_return_code', 'ddns_return_code_chk', 'ddns_updated', 'ddns_hostname_x']);
const requestBody = body(update, 'static int ValidDdnsNvramRequest(')
    .replace(/request->/g, 'request.')
    .replace(/sizeof\(ddns_nvram_keys\) \/ sizeof\(ddns_nvram_keys\[0\]\)/g, '4')
    .replace(/sizeof\(request.value\)/g, '64')
    .replace(/NULL/g, 'null');
const validRequest = new Function('request', 'ValidDdnsHostname', 'memchr', 'strcmp', requestBody);
const checkRequest = (key, value) => Number(validRequest({key, value}, host => validateDdns(host),
    (host, character, length) => host.slice(0, length).includes(character) ? 1 : null,
    (left, right) => Number(left.split('\0')[0] !== right)));
for (const key of [0, 1]) {
    for (const value of ['connect_fail', 'auth_fail', '200']) assert.equal(checkRequest(key, value + '\0'), 1);
    for (const value of ['1', '0', 'arbitrary', '200\ninjected']) assert.equal(checkRequest(key, value + '\0'), 0);
}
assert.equal(checkRequest(2, '1\0'), 1);
assert.equal(checkRequest(2, '200\0'), 0);
assert.equal(checkRequest(3, 'router.example\0'), 1);
for (const value of ['%n%n\0', 'a'.repeat(64), 'router example\0', '../secret\0']) {
    assert.equal(checkRequest(3, value), 0);
}
for (const key of [4, 255, 0xffffffff]) assert.equal(checkRequest(key, '200\0'), 0);
assert.equal(checkRequest(0, '200'), 0);
assert.equal(checkRequest(0, 'a'.repeat(64) + '\0'), 0);

const privsep = body(update, 'static int StartDdnsPrivsep(');
assert.match(privsep, /socketpair\(AF_UNIX, SOCK_SEQPACKET, 0, sockets\)/);
assert.match(privsep, /prctl\(PR_SET_NAME, "phddns-nvram"/);
const childStart = privsep.indexOf('if (child == 0)');
const childEnd = privsep.indexOf('close(sockets[1]);', childStart);
const childBody = privsep.slice(childStart, childEnd);
assert.match(childBody, /setgroups\(0, NULL\).*setgid\(65534\).*setuid\(65534\)/s);
assert.match(childBody, /getuid\(\) != 65534.*geteuid\(\) != 65534.*getgid\(\) != 65534.*getegid\(\) != 65534/s);
const dropGuard = childBody.match(/if \((setgroups[^]+?)\)\s*\{/)[1].replace(/NULL/g, 'null');
const failedDrop = new Function('setgroups', 'setgid', 'setuid', 'getuid', 'geteuid', 'getgid', 'getegid', 'prctl',
    `const PR_SET_NAME = 15; return ${dropGuard};`);
const dropCalls = ['setgroups', 'setgid', 'setuid', 'getuid', 'geteuid', 'getgid', 'getegid', 'prctl'];
for (const failure of [null, ...dropCalls]) {
    const calls = [];
    const invalid = failedDrop(...dropCalls.map(name => (...args) => {
        calls.push(name);
        if (name === 'setgroups') assert.deepEqual(args, [0, null]);
        if (name === 'setuid' || name === 'setgid') assert.deepEqual(args, [65534]);
        if (name === failure) return name.startsWith('get') ? 0 : -1;
        return name.startsWith('get') ? 65534 : 0;
    }));
    assert.equal(invalid, failure !== null, String(failure));
    assert.deepEqual(calls, failure === null ? dropCalls : dropCalls.slice(0, dropCalls.indexOf(failure) + 1));
}
const broker = privsep.slice(childEnd);
assert.match(broker, /received = recv\(sockets\[0\], &request, sizeof\(request\), MSG_TRUNC\)/);
assert.match(broker, /received == sizeof\(request\) && ValidDdnsNvramRequest\(&request\)/);
assert.match(broker, /nvram_set\(ddns_nvram_keys\[request.key\], request.value\)/);
assert.match(broker, /if \(received <= 0\) break;/);
assert.match(broker, /close\(sockets\[0\]\);\s*_exit\(0\);/);
assert.match(broker, /memset\(phglobal, 0, sizeof\(\*phglobal\)\)/);
assert.match(broker, /log_close\(\)/);
const setter = body(update, 'static int DdnsNvramSet(');
assert.match(setter, /strnlen\(value, sizeof\(request.value\)\) >= sizeof\(request.value\)/);
assert.match(setter, /!ValidDdnsNvramRequest\(&request\)/);
assert.match(setter, /MSG_NOSIGNAL/);
assert.match(setter, /received == sizeof\(result\) \? result : -1/);
assert.match(update, /#define nvram_set DdnsNvramSet/);
assert(update.indexOf('#define nvram_set DdnsNvramSet') > update.indexOf('result = nvram_set(ddns_nvram_keys'));
const step = body(update, 'int phddns_step(');
assert(step.indexOf('StartDdnsPrivsep(phglobal)') < step.indexOf('InitializeSockets(phglobal)'));
assert.match(step, /if \(!StartDdnsPrivsep\(phglobal\)\)[^]+?exit\(EXIT_FAILURE\)/);

const phddnsConfigOpen = body(services, 'ddns_phddns_config_open(');
assert.match(phddnsConfigOpen, /openat\(dirfd, "phddns\.conf"[^]+?O_CREAT \| O_EXCL \| O_NOFOLLOW/);
assert.match(phddnsConfigOpen, /\(!created && st\.st_uid != 0\)/);
assert.match(phddnsConfigOpen, /fchown\(fd, 0, 0\) < 0/);
assert(phddnsConfigOpen.indexOf('fchmod(fd, 0600)') < phddnsConfigOpen.indexOf('fchown(fd, 0, 0)'));
assert(phddnsConfigOpen.indexOf('fchmod(fd, 0600)') < phddnsConfigOpen.indexOf('ftruncate(fd, 0)'));
assert.match(phddnsConfigOpen, /st\.st_nlink != 1/);
const phddnsDirectoryOpen = body(services, 'ddns_phddns_directory_open(');
assert.match(phddnsDirectoryOpen, /open\("\/tmp\/etc", O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(phddnsDirectoryOpen, /st\.st_uid != 0.*st\.st_gid != 0/s);
const removeConfig = body(services, 'ddns_phddns_remove_config(');
assert.match(removeConfig, /fstatat\(dirfd, "phddns\.conf", &st, AT_SYMLINK_NOFOLLOW\)/);
assert.match(removeConfig, /unlinkat\(dirfd, "phddns\.conf", 0\)/);
const stopDdns = body(services, 'stop_ddns(void)');
assert(stopDdns.indexOf('killall("phddns"') < stopDdns.indexOf('ddns_phddns_remove_config()'));
const startDdnsStart = services.indexOf('int\nstart_ddns(char *caller)');
const startDdnsGuard = services.slice(startDdnsStart, services.indexOf('if (!is_routing_enabled())', startDdnsStart));
assert.match(startDdnsGuard, /!nvram_get_int\("ddns_enable_x"\) \|\| !nvram_match\("ddns_server_x", "WWW\.ORAY\.COM"\)\)\s*ddns_phddns_remove_config\(\)/);

const logOpen = body(phddnsLog, 'void log_open(');
assert.match(phddnsLog, /^#define _GNU_SOURCE/m);
assert.match(logOpen, /open\(file, O_WRONLY \| O_APPEND \| O_CREAT \| O_NOFOLLOW \| O_NONBLOCK, 0600\)/);
assert.match(logOpen, /st\.st_uid != 0/);
assert.match(logOpen, /fchmod\(descriptor, 0600\)/);
assert(logOpen.indexOf('fchmod(descriptor, 0600)') < logOpen.indexOf('fchown(descriptor, 0, 0)'));
assert.match(logOpen, /st\.st_gid != 0/);

const nvramGet = body(web, 'ej_nvram_get_impl(int eid, webs_t wp, int argc, char_t **argv, int escape_backslash)');
const nvramOutput = nvramGet.slice(nvramGet.indexOf('for (; *c; c++)'));
assert.match(nvramOutput, /\*c != '\\''/);
assert.match(nvramOutput, /else if\s*\(\*c == '\\''\)\s*ret \+= websWrite\(wp, "&#39;"\);/);
const encodedHostname = "router&#39;;globalThis.__ddns_xss = true;//";
const vm = require('node:vm');
const page = { __ddns_xss: false };
vm.runInNewContext(`var ddns_hostname_x = '${encodedHostname}';`, page);
assert.equal(page.__ddns_xss, false);
assert.equal(page.ddns_hostname_x, encodedHostname);

console.log('phddns challenge: challenge/redirect, bounded socket/domain/REGI parsing, NVRAM allowlist and fail-closed privilege-drop regressions passed');
console.log('httpd nvram template output: single quote is encoded and script-string payload remains inert');
console.log('Not compiled C, ASan, socket/fake-server, or hardware validation.');