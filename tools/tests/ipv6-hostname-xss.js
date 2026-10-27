const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const arrays = read('release/src/router/httpd/data_arrays.c');
const util = read('release/src/router/dnsmasq/src/util.c');
const connections = read('release/src/router/www/Main_ConnStatus_Content.asp');
const qos = read('release/src/router/www/QoS_Stats.asp');
const hostnameCheck = util.match(/static int check_hostname\(char \*name\)\n\{[^]*?\n\}/)[0];
assert.doesNotMatch(hostnameCheck, /strchr|relax name|c >= 33/);
for (const name of ['network', 'clients']) {
    const hook = arrays.match(new RegExp('ej_lan_ipv6_' + name + '_array\\([^]*?\\n\\}'))[0];
    assert.match(hook, /websWriteJsonString\(wp, hostname\)/);
    assert.match(hook, /ipv6_enabled\(\) && is_routing_enabled\(\)/);
    assert.doesNotMatch(hook, /websWrite\([^;]*, hostname/);
}
for (const page of [connections, qos]) {
    for (const value of ['srchost', 'dsthost', 'srctitle', 'dsttitle'])
        assert.match(page, new RegExp('htmlEnDeCode\\.htmlEncode\\(' + value + '\\)'));
    assert.doesNotMatch(page, /<%[^%]*nvram_(?:get|match)\("\s/);
}
const state = read('release/src/router/www/state.js');
const ipv6 = read('release/src/router/www/Main_IPV6Status_Content.asp');
const ajax = read('release/src/router/www/ajax_conntrack.asp');
const encoder = state.match(/var htmlEnDeCode = \(function \(\) \{[^]*?\n\}\)\(\);/)[0];
const jsonHelper = arrays.match(/static int websWriteJsonString\([^]*?\n\}/)[0];
const escapes = new Map();
for (const match of jsonHelper.matchAll(/case ('(?:\\.|[^'])+'): ret \+= websWrite\(wp, ("(?:\\.|[^"])*")\); break;/g))
    escapes.set(vm.runInNewContext(match[1]), vm.runInNewContext(match[2]));
assert.equal(escapes.size, 11);
assert.match(jsonHelper, /if \(\*p < 0x20\)\s+ret \+= websWrite\(wp, "\\\\u%04x", \*p\);/);
const jsonString = value => '"' + Array.from(value, character => escapes.get(character) ??
    (character.charCodeAt(0) < 32 ? '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0') : character)).join('') + '"';

const hostnameBody = hostnameCheck.slice(hostnameCheck.indexOf('{') + 1, -1)
    .replace('char c, *src = name;', 'let character, offset = 0;')
    .replace('int first;', 'let first;')
    .replace('for (first = 1; (c = *name); name++, first = 0)',
        'for (first = 1; (character = name.charAt(offset)); offset++, first = 0)')
    .replace(/\bc\b/g, 'character')
    .replace('return name - src;', 'return offset;');
const checkName = name => name.length > 0 && name.length <= 253 &&
    name.split('.').every(label => label.length <= 63) && !/[\x00-\x1f\x7f-\uffff]/.test(name);
const checkHostname = new Function('name', 'check_name', hostnameBody);
for (const name of ['printer', 'Printer-2', 'nas_1', 'a', 'host.example', 'z'.repeat(63)])
    assert(checkHostname(name, checkName) >= 0, name);
for (const name of ['', '-host', '_host', 'a"b@c', 'a@b', 'a<b', 'a/b', 'a\\b', 'a b', 'z'.repeat(64)])
    assert.equal(checkHostname(name, checkName), -1, name);
const dhcp4 = read('release/src/router/dnsmasq/src/rfc2131.c');
const dhcp6 = read('release/src/router/dnsmasq/src/rfc3315.c');
assert.match(dhcp4, /OPTION_HOSTNAME, 1\)\)[^]*?if \(valid_hostname\(daemon->dhcp_buff\)\)\s+client_hostname = daemon->dhcp_buff;/);
assert.match(dhcp4, /domain = strip_hostname\(client_hostname\)/);
assert.match(dhcp6, /if \(valid_hostname\(daemon->dhcp_buff\)\)/);

const payloads = ['', 'printer', 'a'.repeat(32), 'b'.repeat(40),
    '";alert(1)//@', '</script>@', '</ScRiPt><svg/onload=alert(1)>@',
    '<img/src/onerror=alert(1)>@', '" onmouseover="alert(1)', "'\"\\<>&/@", '&quot;<img/src/onerror=x>@'];
for (let byte = 1; byte < 128; byte++) payloads.push(String.fromCharCode(byte));
const sourceAddress = '2001:db8:1::100';
const destinationAddress = '2001:db8:2::200';
const mac = '00:11:22:33:44:55';
const context = { console, showhide() {}, genClientList() {}, table_sort() { return 0; },
    compIPV6(value) { return value; }, get_qos_class() { return 0; },
    sortfield_nat: 0, sortdir_nat: 0, sortfield_route: 0, sortdir_route: 0,
    sortfield: 0, sortdir: 0, maxrendered: 100, maxshown: 100, qos_type: 1,
    bwdpi_labels_ordered: ['Default'], validator: { isPrivateIP() { return true; } } };
vm.createContext(context);
const connectionRenderer = connections.match(/function draw_table\(type\)\{[^]*?\n\}/)[0];
const qosRenderer = qos.match(/function draw_conntrack_table\(\)\{[^]*?\n\}/)[0];
const ipv6Renderer = ipv6.match(/function show_ipv6clients\(\) \{[^]*?\n\}/)[0];
vm.runInContext(encoder + '\n' + connectionRenderer + '\n' + qosRenderer + '\n' + ipv6Renderer, context);
const htmlEncode = context.htmlEnDeCode.htmlEncode;
const networkOutput = arrays.match(/ret \+= websWrite\(wp, "\["\);\s+ret \+= websWriteJsonString\(wp, hostname\);[^]*?websWrite\(wp, "\],"\);/)[0];
const clientOutput = arrays.match(/ret \+= websWrite\(wp, "ipv6clientarray\["\);[^]*?websWrite\(wp, ";\\n"\);/)[0];
function renderOutput(source, hostname) {
    const output = { ret: 0, wp: null, hostname, macaddr: mac, ipaddrs: sourceAddress,
        addrbuf: sourceAddress, output: '' };
    output.websWrite = (wp, value) => { output.output += value; return value.length; };
    output.websWriteJsonString = (wp, value) => output.websWrite(wp, jsonString(value));
    vm.runInNewContext(source, output);
    return output.output;
}
let renders = 0;
for (const payload of payloads) {
    const encoded = jsonString(payload);
    assert.equal(vm.runInNewContext(encoded), payload);
    assert.doesNotMatch(encoded, /[<>]|<\/script/i);
    const hostname = payload.length > 32 ? payload.slice(0, 29) + '...' : payload;
    const networkScript = 'var ipv6clientarray = [' + renderOutput(networkOutput, hostname) + '[]];';
    const clientScript = 'var ipv6clientarray = {};\n' + renderOutput(clientOutput, hostname);
    assert.equal(vm.runInNewContext(networkScript + 'ipv6clientarray[0][0]'), hostname);
    assert.equal(vm.runInNewContext(clientScript + 'ipv6clientarray["' + sourceAddress + '"]'), hostname);
    for (const [page, output] of [[ipv6, networkScript], [connections, clientScript], [qos, clientScript], [ajax, clientScript]]) {
        const expanded = page.replace(/<%\s*get_ipv6(?:net|clients)_array\(\);\s*%>/g, output)
            .replace(/<%[^]*?%>/g, '0');
        const scripts = page === ajax ? [expanded] : Array.from(expanded.matchAll(/<script\b[^>]*>([^]*?)<\/script>/gi), match => match[1]);
        for (const script of scripts) new vm.Script(script);
    }
    if (['";alert(1)//@', '</script>@', '<img/src/onerror=alert(1)>@'].includes(payload))
        assert.equal(checkHostname(payload, checkName), -1, payload);

    for (const fallback of [false, true]) {
        context.ipv6clientarray = fallback ? {} : { [sourceAddress]: payload, [destinationAddress]: payload };
        context.clientFromIP = () => fallback ? { nickName: '', name: payload } : undefined;
        for (const showNames of [0, 1]) {
            for (const privateIP of [false, true]) {
                context.showNames = showNames;
                context.validator.isPrivateIP = () => privateIP;
                context.filter = { nat: [], route: [] };
                for (const type of ['nat', 'route']) {
                    const elements = {};
                    context.document = { getElementById(id) { return elements[id] ||= { style: {} }; } };
                    context.connarray = [['TCP', sourceAddress, '1234', destinationAddress, '443', 'ESTABLISHED']];
                    context.connarray_route = context.connarray.map(row => row.slice());
                    context.draw_table(type);
                    const markup = elements['connblock_' + type].innerHTML;
                    const visible = showNames && payload ? payload : sourceAddress;
                    const title = !showNames && payload ? payload : sourceAddress;
                    assert(markup.includes('title="' + htmlEncode(title) + '"'));
                    assert(markup.includes('>' + htmlEncode(visible) + '<'));
                    assert.doesNotMatch(markup, /<(?:img|svg|script)\b/i);
                    renders++;
                }
            }
        }
        const elements = {};
        context.document = { getElementById(id) { return elements[id] ||= { style: {} }; } };
        context.filter = [];
        context.bwdpi_conntrack = [['TCP', sourceAddress, '1234', destinationAddress, '443', 'HTTPS', 0, 0]];
        context.draw_conntrack_table();
        assert(elements.tracked_connections.innerHTML.includes('>' + htmlEncode(payload || sourceAddress) + '</td>'));
        assert.doesNotMatch(elements.tracked_connections.innerHTML, /<(?:img|svg|script)\b/i);
        renders++;
    }
    context.ipv6clientarray = [[payload, mac, sourceAddress], ['printer', mac, destinationAddress], []];
    context.tableApi = { genTableAPI(table) { assert.equal(table.data[0][0], htmlEncode(payload)); } };
    context.show_ipv6clients();
    renders++;
}
let injectedCalls = 0;
vm.runInNewContext('var ipv6clientarray = {}; ipv6clientarray["x"] = "' + '";alert(1)//@' + '";',
    { alert() { injectedCalls++; } });
assert.equal(injectedCalls, 1);
vm.runInNewContext('var ipv6clientarray = {}; ipv6clientarray["x"] = ' + jsonString('";alert(1)//@') + ';',
    { alert() { injectedCalls++; } });
assert.equal(injectedCalls, 1);
console.log(`PASS: IPv6 hostname source contracts, DHCP validation, four-page script parsing and ${renders} actual page-function renders (source/model checks, not compiled C or browser DOM)`);