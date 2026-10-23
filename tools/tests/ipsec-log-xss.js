const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const web = read('release/src/router/httpd/web.c');
const encoder = web.slice(web.indexOf('static int dump_file_filter_mode('),
    web.indexOf('static int dump_file_filter('));
const entities = new Map([...encoder.matchAll(/case '(\\.|[^'])': entity = "([^"]+)"; break;/g)]
    .map(([, character, entity]) => [character === "\\'" ? "'" : character, entity]));
assert.equal(entities.size, 5);
assert.match(encoder, /if \(!escape_html\) \{\s*ret \+= websWriteData\(wp, buf, len\);\s*continue;/);
assert.match(encoder, /websWriteData\(wp, buf \+ start, offset - start\)/);
assert.match(encoder, /websWrite\(wp, "%s", entity\)/);
assert.match(encoder, /start = offset \+ 1/);
assert.match(encoder, /websWriteData\(wp, buf \+ start, len - start\)/);
assert.match(web, /\{ "nvram_dump_html", ej_dump_html\}/);
assert.match(web, /ej_dump_html\([^)]*\)\s*\{\s*return ej_dump_impl\(eid, wp, argc, argv, 1\);/);
assert.match(web, /ej_dump\([^)]*\)\s*\{\s*return ej_dump_impl\(eid, wp, argc, argv, 0\);/);
assert.match(web, /strcmp\(file, "ipsec.log"\)==0\)[\s\S]*?dump_file_filter_mode\(wp, filename, NULL, escape_html\)/);
assert.match(web, /if \(escape_html &&[\s\S]*?websError\(wp, 400, "Unsupported HTML log\\n"\);\s*return -1;/);

const encode = text => text.replace(/[&<>"']/g, character => entities.get(character));
const decode = text => text.replace(/&(amp|lt|gt|quot|#39);/g,
    entity => [...entities].find(([, encoded]) => encoded === entity)[0]);
const payloads = [
    '',
    '</textarea><img src=x onerror=alert(1)>',
    "</TeXtArEa><svg/onload=import('//evil.example')>",
    '</ipsec><script>alert(1)</script><ipsec>',
    '&lt;/textarea&gt; &amp; &#39; "quoted" +plus %s',
    'first\n\tsecond\r\nthird',
    'A'.repeat(4095) + '</textarea>' + '&'.repeat(8192),
];

for (const file of ['Advanced_VPN_IPSec.asp', 'Advanced_Instant_Guard.asp']) {
    const source = read(`release/src/router/www/${file}`);
    assert.match(source, /<textarea\b[^>]*><% nvram_dump_html\("ipsec.log",""\); %><\/textarea>/);
    assert.doesNotMatch(source, /nvram_dump\("ipsec.log"/);
    const refresh = source.match(/function update_ipsec_log\(\) \{[\s\S]*?\n\}/)[0];
    for (const payload of payloads) {
        const encoded = encode(payload);
        assert(!/[<>]/.test(encoded));
        assert.equal(decode(encoded), payload);
        let ajax;
        let displayed;
        const jquery = selector => {
            assert.equal(selector, 'textarea#textarea');
            return { val: value => { displayed = value; } };
        };
        jquery.ajax = options => { ajax = options; };
        const context = { $: jquery };
        vm.runInNewContext(`${refresh}\nupdate_ipsec_log();`, context);
        ajax.success({ getElementsByTagName: tag => {
            assert.equal(tag, 'ipsec');
            return [{ textContent: decode(encoded) }];
        } });
        assert.equal(displayed, payload);
    }
}
assert.match(read('release/src/router/www/ajax_ipsec_log.xml'), /nvram_dump_html\("ipsec.log", ""\)|nvram_dump_html\("ipsec.log",""\)/);
for (const file of ['Main_Analysis_Content.asp', 'Main_Netstat_Content.asp', 'cloud_syslog.asp']) {
    const source = read(`release/src/router/www/${file}`);
    assert.match(source, /nvram_dump_html\("(?:syscmd|clouddisk)\.log"/);
    assert.doesNotMatch(source, /nvram_dump\("(?:syscmd|clouddisk)\.log"/);
}
console.log('PASS: IPsec log escaping contracts and refresh handlers preserve hostile and empty logs as text');