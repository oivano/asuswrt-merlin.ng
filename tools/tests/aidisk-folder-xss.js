const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const util = require('node:util');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const helper = source.match(/static void aidisk_write_folder_string\([^]*?\n\}/)[0];
const handler = source.match(/int ej_get_AiDisk_status\([^]*?\n\}/)[0];
assert.match(handler, /aidisk_write_folder_string\(wp, folder_list\[i\]\);/);
assert.doesNotMatch(handler, /websWrite\([^;]*folder_list|folder_name|string_to_htmlencode/);

// Execute the encoder's C control flow with byte-oriented input and mocked websWrite.
const translated = helper.slice(helper.indexOf('{') + 1, helper.lastIndexOf('}'))
    .replace(/const unsigned char \*cursor = \(const unsigned char \*\)name;/, 'let cursor = 0;')
    .replace(/\(unsigned int\)\*cursor/g, 'name[cursor]')
    .replace(/cursor\[(\d+)\]/g, 'name[cursor + $1]')
    .replace(/\*cursor/g, 'name[cursor]')
    .replace(/'(?:\\.|[^'\\])'/g, literal => String(vm.runInNewContext(literal).charCodeAt(0)));
const encode = input => {
    const bytes = Buffer.concat([Buffer.isBuffer(input) ? input : Buffer.from(input), Buffer.from([0])]);
    const chunks = [];
    const websWrite = (wp, format, ...args) => {
        const output = format === '%c' ? Buffer.from([args[0]])
            : Buffer.from(format === '\\u%04x' ? '\\u' + args[0].toString(16).padStart(4, '0')
                : util.format(format.replace('%u', '%d'), ...args));
        chunks.push(output);
        return output.length;
    };
    vm.runInNewContext(translated, { name: bytes, wp: null, websWrite });
    return Buffer.concat(chunks).toString('utf8');
};

const payload = 'x"]}}alert(1);function q(){{return["';
const names = ['', 'photos', payload, 'a\\', "'\"\\<>&", '\\u2028', '\\x22',
    '\r\n\t', '\u2028\u2029', 'caf\u00e9-\u65e5\u672c-\ud83d\udcc1',
    'a'.repeat(255), '"'.repeat(255), '\\'.repeat(255)];
for (let byte = 1; byte < 128; byte++) names.push('a' + String.fromCharCode(byte) + 'b');

for (const name of names) {
    const literal = encode(name);
    assert.equal(vm.runInNewContext(literal), name);
    assert.doesNotMatch(literal.slice(1, -1), /["'<>&\x00-\x1f\x7f\u2028\u2029]/);
}
for (const byte of ['\\', '"', "'", '<', '>', '&', '\n', '\x7f'])
    assert.match(encode(byte), /^"\\u[0-9a-f]{4}"$/);
assert.equal(encode('\u2028\u2029'), '"\\u2028\\u2029"');
for (const bytes of [[0xe2], [0xe2, 0x80], [0xe2, 0x80, 0xa8], [0xff, 0x22]])
    assert.doesNotThrow(() => new vm.Script(encode(Buffer.from(bytes))));

// Use the handler's actual framing for a pool containing all regression names.
const writes = [...handler.matchAll(/websWrite\(wp, ("(?:\\.|[^"\\])*")/g)]
    .map(match => JSON.parse(match[1]));
const start = writes.find(text => text === 'function get_sharedfolder_in_pool(poolName){\n');
const branch = writes.find(text => text.startsWith('if(poolName == "%s")'));
const array = writes.find(text => text.includes('return [""'));
assert(start && branch && array);
const makeScript = literals => start + branch.replace('%s', 'sda1') + array + ', ' +
    literals.join(', ') + '];\n    }\n}\n';
let executions = 0;
const context = { alert: () => executions++ };
vm.createContext(context);
vm.runInContext(makeScript(names.map(encode)), context);
assert.equal(executions, 0);
assert.deepEqual(Array.from(context.get_sharedfolder_in_pool('sda1')), ['', ...names]);
assert.equal(context.get_sharedfolder_in_pool('missing'), undefined);
assert.doesNotMatch(makeScript(names.map(encode)), /<\/script/i);
vm.runInContext(makeScript(['"' + payload + '"']), context);
assert.equal(executions, 1, 'negative control must execute the original raw-name injection');

for (const file of ['device-map/disk.asp', 'Advanced_AiDisk_samba.asp', 'Advanced_AiDisk_ftp.asp',
    'Advanced_AiDisk_NFS.asp', 'aidisk/popCreateFolder.asp']) {
    const page = fs.readFileSync(path.join(root, 'release/src/router/www', file), 'utf8');
    assert.match(page, /<%\s*get_AiDisk_status\(\);\s*%>/);
}
console.log(`PASS: AiDisk folder encoder source/control-flow checks, ${names.length} literal round trips, generated function and raw-injection negative control (not compiled C or hardware)`);