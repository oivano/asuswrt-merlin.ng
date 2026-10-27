const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const web = read('release/src/router/httpd/web.c');
const hook = web.slice(web.indexOf('int ej_apps_fsck_log('),
    web.indexOf('int ej_get_disk_format_log('));
assert.match(hook, /ret = dump_file_filter_mode\(wp, file_name, NULL, 1\);/);
assert.doesNotMatch(hook, /\bdump_file\(/);
assert.match(hook, /if\(ret\)\s*websWrite\(wp, "\\n\\n"\);/);

const encoder = web.slice(web.indexOf('static int dump_file_filter_mode('),
    web.indexOf('static int dump_file_filter('));
const entities = new Map([...encoder.matchAll(/case '(\\.|[^'])': entity = "([^"]+)"; break;/g)]
    .map(([, character, entity]) => [character === "\\'" ? "'" : character, entity]));
assert.deepEqual([...entities], [
    ['&', '&amp;'], ['<', '&lt;'], ['>', '&gt;'], ['"', '&quot;'], ["'", '&#39;'],
]);
assert.match(encoder, /websWriteData\(wp, buf \+ start, offset - start\)/);
assert.match(encoder, /websWrite\(wp, "%s", entity\)/);
assert.match(encoder, /start = offset \+ 1/);
assert.match(encoder, /websWriteData\(wp, buf \+ start, len - start\)/);
const encode = text => text.replace(/[&<>"']/g, character => entities.get(character));
const decode = text => text.replace(/&(amp|lt|gt|quot|#39);/g,
    entity => [...entities].find(([, encoded]) => encoded === entity)[0]);

const xml = read('release/src/router/www/disk_fsck.xml');
assert.match(xml, /<disk1><% apps_fsck_log\(\); %><\/disk1>/);
const testPage = read('release/src/router/www/diskmon_test.asp');
assert.match(testPage, /<textarea\b[^>]*><% apps_fsck_log\(\); %><\/textarea>/);
const page = read('release/src/router/www/device-map/disk_utility.asp');
assert.match(page, /<textarea\b[^>]*\bid="textarea_disk0"/);
const refresh = page.match(/function get_disk_log\(\)\{[\s\S]*?\n\}/)[0];
assert.doesNotMatch(refresh, /\.html\(|innerHTML/);

const textarea = { value: 'stale log', style: { display: 'none' } };
const response = {};
let decoded;
let ajax;
const jquery = selector => {
    if (selector === '#textarea_disk0') {
        return { val: value => { textarea.value = value; } };
    }
    assert.equal(selector, response);
    return { find: tag => {
        assert.equal(tag, 'disk1');
        return { text: () => decoded };
    } };
};
jquery.ajax = options => { ajax = options; };
const context = {
    $: jquery, parent: { usbPorts: [{ node: '1.2' }] }, diskOrder: 1,
    document: { getElementById: id => {
        assert.equal(id, 'textarea_disk0');
        return textarea;
    } },
};
vm.runInNewContext(`${refresh}\nget_disk_log();`, context);
assert.equal(ajax.url, '/disk_fsck.xml?diskmon_usbport=1.2');
assert.equal(ajax.dataType, 'xml');
assert.equal(textarea.style.display, '');

const payloads = [
    '&lt;img src=x onerror=alert(1)&gt;&lt;script&gt;',
    '</textarea><img src=x onerror=alert(1)>',
    '<img src=x onerror=alert(1)><script>alert(1)</script>',
    '</disk1><script>alert(1)</script><disk1>',
    `& < > " ' +plus %s`,
    'fsck: clean\n\tfiles checked\r\n',
    'A'.repeat(4095) + '</textarea>' + '&'.repeat(8192),
    '',
];
for (const payload of payloads) {
    const encoded = encode(payload);
    assert(!/[<>"']/.test(encoded));
    decoded = decode(encoded);
    assert.equal(decoded, payload);
    ajax.success(response);
    assert.equal(textarea.value, payload);
}
console.log('PASS: fsck log escaping contracts and actual refresh handler preserve hostile and empty logs as text');