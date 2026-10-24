const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');

const decoder = web.slice(web.indexOf('\nb64_decode( const char* str'), web.indexOf('\n}', web.indexOf('\nb64_decode( const char* str')));
assert.match(decoder, /b64_decode_table\[\(unsigned char\)\*cp\]/);
assert.doesNotMatch(decoder, /b64_decode_table\[\(int\)\*cp\]/);

const calls = [...web.matchAll(/(\w+) = b64_decode\(([^;]*)\);\s*\n\s*(\w+)\[\1\] = '\\0';/g)];
const sites = (web.match(/\bb64_decode\(/g) || []).length - 1;
assert.equal(calls.length, sites, 'every b64_decode call site terminates its result');
assert.equal(calls.length, 4);

const names = new Set();
for (const [, , args, terminated] of calls) {
    const dest = args.match(/\(unsigned char\*\)\s*(\w+)\s*,\s*sizeof\((\w+)\)\s*-\s*1\s*$/);
    assert(dest, `missing reserved terminator byte: ${args}`);
    assert.equal(dest[1], dest[2]);
    assert.equal(dest[1], terminated);
    names.add(terminated);
}
assert.deepEqual([...names].sort(), ['authinfo', 'captcha_text', 'passwd_str', 'username_str']);

for (const [name, size] of [['authinfo', 500], ['captcha_text', 6], ['username_str', 128], ['passwd_str', 128]]) {
    assert.match(web, new RegExp(`\\b${name}\\[${size}\\]`));
}

// Model the decoder's store bound with the reported oversized inputs.
function decodedLength(chars, size) {
    let idx = 0;
    for (let i = 0; i < chars; i++) if (i % 4 !== 0 && idx < size) idx++;
    return idx;
}
for (const [chars, size] of [[700, 500], [9, 6], [10000, 128]]) {
    const l = decodedLength(chars, size - 1);
    assert(l < size, `terminator index ${l} within ${size}`);
}

console.log('httpd b64_decode bounds: ok');
