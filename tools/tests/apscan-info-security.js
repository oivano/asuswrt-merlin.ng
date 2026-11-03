const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const wireless = read('release/src/router/rc/wireless.c');
const web = read('release/src/router/httpd/web.c');
const scanner = wireless.slice(wireless.indexOf('#define APSCAN_DIR'),
    wireless.indexOf('static int lock = -1;'));
const hookStart = web.indexOf('static int ej_get_ap_info(');
const hook = web.slice(hookStart, web.indexOf('\n}\n', hookStart) + 3);

assert.match(scanner, /#define APSCAN_DIR "\/tmp\/apscan"/);
assert.match(scanner, /lstat\("\/tmp"/);
assert.match(scanner, /O_DIRECTORY \| O_NOFOLLOW/);
assert.match(scanner, /st_uid != 0/);
assert.match(scanner, /mkdir\(APSCAN_DIR, 0700\)/);
assert.match(scanner, /O_CREAT \| O_EXCL \| O_NOFOLLOW/);
assert.match(scanner, /fstat\(fd, &st\)/);
assert.doesNotMatch(wireless, /APSCAN_INFO "\/tmp\/apscan_info\.txt"/);
assert.match(hook, /openat\(directory_fd, APSCAN_INFO_FILE, O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK\)/);
assert.match(hook, /S_ISREG\(st\.st_mode\)/);
assert.match(hook, /st_uid != 0 \|\| st\.st_nlink != 1/);
assert.match(hook, /json_tokener_parse\(row_json\)/);
assert.match(hook, /json_object_to_json_string\(ap_row\)/);
assert.doesNotMatch(hook, /websWrite\(wp, "%s", buf\)/);
assert.doesNotMatch(web, /fopen\("\/tmp\/apscan_info\.txt"/);

const payloads = [
    'normal network',
    '"];globalThis.injected=true;//',
    '</script><img src=x onerror=alert(1)>',
    '\\";globalThis.injected=true;//',
    'line\nbreak',
];
for (const payload of payloads) {
    const row = [payload, '00:11:22:33:44:55', '6', 'WPA2-Personal', 'AES', '-50',
        '00:11:22:33:44:55', '11n', '0'];
    const rowContent = JSON.stringify(row).slice(1, -1);
    const parsed = JSON.parse(`[${rowContent}]`);
    assert.equal(parsed.length, 9);
    const context = {};
    vm.runInNewContext(`aplist = [[${JSON.stringify(parsed).slice(1, -1)}]];`, context);
    assert.deepEqual(Array.from(context.aplist[0]), row);
    assert.equal(context.injected, undefined);
}

for (const invalidRow of [
    '0]];globalThis.injected=true;//',
    '"ssid",null,"6","security","crypto","-50","mac","mode","0"',
    '"too","few","fields"',
]) {
    let parsed;
    try {
        parsed = JSON.parse(`[${invalidRow}]`);
    } catch (_error) {
        continue;
    }
    const accepted = (parsed.length === 9 || parsed.length === 10) &&
        parsed.every(field => typeof field === 'string');
    assert.equal(accepted, false);
}

console.log(`PASS: protected site-survey file contracts and ${payloads.length} serialized payload cases`);