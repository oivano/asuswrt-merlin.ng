const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const hook = read('release/src/router/httpd/sysdeps/web-broadcom-am.c');
const page = read('release/src/router/www/Main_WStatus_Content.asp');
const state = read('release/src/router/www/state.js');
const helper = hook.match(/static void\s+wl_hostname_to_js\([^]*?\n\}/)[0];
assert.match(helper, /offset < 32 && hostname\[offset\]/);
assert.match(helper, /snprintf\(output \+ offset \* 4, 5, "\\\\x%02x", \(unsigned char\)hostname\[offset\]\)/);
assert.match(helper, /output\[offset \* 4\] = '\\0';/);
assert.match(hook, /char hostnameentry\[32 \* 4 \+ 1\];/);
assert.equal((hook.match(/if \(found & 2\)\s+wl_hostname_to_js\(hostnameentry, tmp\);/g) || []).length, 2);
assert.doesNotMatch(hook, /str_escape_quotes\(hostnameentry|strlcpy\(hostnameentry/);
assert.equal((hook.match(/%32s %\*s/g) || []).length, 2);
assert.match(page, /<% get_wl_status\(\); %>/);

const encodeScript = hostname => {
    let output = '';
    for (let offset = 0; offset < 32 && hostname.charCodeAt(offset); offset++)
        output += '\\x' + (hostname.charCodeAt(offset) & 255).toString(16).padStart(2, '0');
    return output;
};
const encoder = state.match(/var htmlEnDeCode = \(function \(\) \{[^]*?\n\}\)\(\);/)[0];
const renderer = page.match(/function display_clients\([^]*?\n\}/)[0];
const context = { clientList: {}, based_modelid: 'DSL-AC68U', sw_mode: '1',
    guestnames: [['Guest'], ['Guest']] };
vm.createContext(context);
vm.runInContext(encoder + '\n' + renderer, context);

const payloads = [
    '', 'printer', 'a'.repeat(20), 'b'.repeat(24), 'c'.repeat(25), 'd'.repeat(32),
    '\"><img/src/onerror=alert(1)>@x',
    '</script><svg/onload=alert(1)>@x',
    '</ScRiPt><svg/onload=alert(1)>@x',
    '\" onmouseover=alert(1) x=\"@x',
    '<img/src/onerror=x>@x', '&quot;<svg/onload=x>@x',
    "'\"\\<>&/@x", '\\x3cimg/src/onerror=x>@x',
    '\"'.repeat(32), '\\'.repeat(32), '<'.repeat(32),
];
for (let byte = 1; byte < 128; byte++) payloads.push(String.fromCharCode(byte).repeat(32));

let checks = 0;
for (const payload of payloads) {
    const encoded = encodeScript(payload);
    assert(encoded.length <= 128);
    assert.match(encoded, /^(?:\\x[0-9a-f]{2})*$/);
    const decoded = vm.runInNewContext('"' + encoded + '"');
    assert.equal(decoded, payload.slice(0, 32));
    assert.doesNotMatch(encoded, /<\/script|[<>"']/i);

    for (const guest of [false, true]) {
        for (const fallback of [false, true]) {
            const mac = '00:11:22:33:44:55';
            context.clientList = fallback ? { [mac]: { nickName: decoded, name: decoded } } : {};
            const client = [mac, '192.0.2.2', fallback ? '*' : decoded, '',
                '-50', '100', '100', '00:00:30', '2', 'ac', '80', guest ? 'G1' : ''];
            const target = {};
            context.display_clients([client, []], target, 0);
            const encode = context.htmlEnDeCode.htmlEncode;
            const displayed = fallback && decoded === '' ? '*' : decoded;
            const expected = displayed.length > 24
                ? 'title="' + encode(displayed) + '">' + encode(displayed.substring(0, 20)) + '...</span>'
                : 'color: cyan;">' + encode(displayed) + '</span>';
            assert(target.innerHTML.includes(expected), JSON.stringify({ payload, guest, fallback }));
            assert.doesNotMatch(target.innerHTML, /<(?:img|svg|script)\b/i);
            checks++;
        }
    }
}
assert.match(page, /<%[\s\S]*?%>/);
assert.doesNotMatch(page, /<%[^%]*nvram_(?:get|match)\("\s/);
console.log(`PASS: wireless hostname source contracts, script round trips and ${checks} main/guest/fallback renders (source/model checks, not compiled C or browser DOM)`);