const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = name => fs.readFileSync(path.join(root, 'release/src/router/phddns/src', name), 'latin1');
const md5 = source('md5.c');
const generate = source('generate.c');
const header = source('generate.h');
const update = source('phupdate.c');
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

console.log('phddns challenge: source-derived HMAC, challenge guards and disconnect contracts passed');
console.log('Not compiled C, ASan, socket/fake-server, or hardware validation.');