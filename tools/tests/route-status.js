const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const template = fs.readFileSync(path.join(root, 'release/src/router/www/Main_RouteStatus_Content.asp'), 'utf8');
const script = [...template.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
    .map(match => match[1]).join('\n').replace(/<%[\s\S]*?%>/g, '0');
const elements = {};
for (const id of ['route_controls', 'route_filters', 'route_filter_title',
    'route_controls_legacy_refresh', 'frr_nav_button', 'routev4block', 'routev6block',
    'route_refresh_spinner', 'route_table_row']) {
    elements[id] = { style: {}, innerHTML: '' };
}
elements.route_table = {
    options: [{ text: 'Main', value: 'main' }],
    remove(index) { this.options.splice(index, 1); }
};
elements.route_table.options.add = option => elements.route_table.options.push(option);
let pending;
let timer;
const jquery = () => ({ css() { }, hide() { return this; }, fadeIn() { }, empty() { }, html() { } });
jquery.ajax = options => { pending = options; };
const context = {
    document: { getElementById: id => elements[id], write() { } },
    Option: function (text, value) { this.text = text; this.value = value; },
    $: jquery,
    gen_switch_menu: () => '',
    setTimeout: (callback, delay) => { timer = delay; return 1; },
    clearTimeout() { }
};
vm.createContext(context);
vm.runInContext(script, context);

context.set_controls_visibility(false);
assert.equal(elements.route_table.options.length, 1);
assert.equal(elements.route_table_row.style.display, 'none');
assert.equal(elements.route_table.options[0].text, 'Main');
context.select_route_table('ipsec');
assert.equal(context.routeTable, 'main');
assert.equal(elements.route_controls.style.display, '');

const sample = [
    { prefix: '172.16.210.0/32', nexthop: '10.99.99.99', iface: 'ipsec0', source: '', metric: 20, protocol: 186, onlink: true, type: 1 },
    { prefix: '10.99.99.99/32', nexthop: '', iface: 'ipsec0', source: '', metric: 20, protocol: 196, onlink: false, type: 1 },
    { prefix: '138.2.180.75/32', nexthop: '', iface: '', source: '', metric: 0, protocol: 4, onlink: false, type: 9 },
    { prefix: '10.0.0.0/26', nexthop: '', iface: 'br0', dev: 'LAN', source: '10.0.0.62', metric: 0, protocol: 2, onlink: false, type: 1 },
    { prefix: '172.16.210.0/24', nexthop: '10.99.99.99', iface: 'ipsec0', source: '', metric: 20, protocol: 186, onlink: true, type: 1 },
    { prefix: '0.0.0.0/0', nexthop: '', iface: 'ipsec0', source: '10.0.0.62', metric: 0, protocol: 4, onlink: false, type: 1 }
];
context.ipsec_route_active = true;
context.ipsec_route_v4 = sample;
context.ipsec_route_v6 = [{ prefix: '2001:db8::/64', nexthop: 'fe80::1', iface: 'ipsec0', source: '', metric: 20, protocol: 4, onlink: true, type: 1 }];
context.routearray = [['10.0.0.0', '*', '255.255.255.192', 'U', '0', '0', '0', 'LAN'], []];
context.set_controls_visibility(false);
assert.equal(elements.route_table.options.length, 2);
assert.equal(elements.route_table_row.style.display, '');
assert.equal(elements.route_table.options[0].text, 'Main');
assert.equal(elements.route_table.options[1].text, '220');
context.select_route_table('ipsec');
const legacy220 = elements.routev4block.innerHTML;
for (const text of ['IPv4 Routing table - IPsec (table 220)', 'Genmask', 'Ref', 'default', '172.16.210.0', '255.255.255.255', '255.255.255.192', 'UGH', '138.2.180.75 (throw)', '>LAN<', '>ipsec0<'])
    assert(legacy220.includes(text), text);
for (const text of ['Protocol', '[D/M]', 'AS Path', 'BGP', 'Preferred source'])
    assert(!legacy220.includes(text), text);
assert.equal(elements.route_filters.style.display, 'none');
for (const text of ['IPv6 Routing table - IPsec (table 220)', '2001:db8::/64', 'fe80::1', '>UG<'])
    assert(elements.routev6block.innerHTML.includes(text), text);
context.ipsec_route_v6 = [];
context.show_routev6();
assert(elements.routev6block.innerHTML.includes('No IPv6 routes.'));
context.ipsec_route_v4 = [{ ...sample[0], iface: '<img src=x onerror=alert(1)>' }];
context.show_routev4();
assert(elements.routev4block.innerHTML.includes('&lt;img'));
context.ipsec_route_v4 = sample;

context.get_route_status();
pending.success();
assert.equal(elements.route_table_row.style.display, '');
context.select_route_table('main');
assert.equal(context.routeTable, 'main');
context.select_route_table('ipsec');
assert.equal(context.routeTable, 'ipsec');
context.ipsec_route_active = false;
context.get_route_status();
pending.success();
assert.equal(context.routeTable, 'main');
assert.equal(elements.route_table.options.length, 1);
assert.equal(elements.route_table_row.style.display, 'none');

context.refreshRate = 3;
context.schedule_route_refresh();
assert.equal(timer, 3000);
context.frr_route_overlay_enabled = 1;
context.update_frr_overlay_flag();
context.frr_route_origin_v4 = { '192.0.2.0/24': [{ proto: 'bgp', active: 1, nexthop: '10.0.0.1', iface: 'br0', aspath: '12345' }] };
context.set_controls_visibility(true);
context.show_routev4();
assert(elements.routev4block.innerHTML.includes('192.0.2.0/24'));
assert.equal(elements.route_table_row.style.display, 'none');
assert(/<tr id="route_table_row" style="display:none;">/.test(template));
assert(!/route_viewport|routeScroll|position:\s*sticky|table-layout:\s*fixed|overflow-wrap:\s*anywhere/.test(template));
assert(!/<%\s*\w+\(\s*"\s+/.test(template));

context.ipsec_route_active = true;
context.ipsec_route_v4 = sample;
context.frr_ipsec_overlay_enabled = 1;
context.frr_ipsec_route_v4 = {
    '0.0.0.0/0': [
        { proto: 'bgp', active: 0, nhactive: 1, nexthop: '10.99.99.99', iface: 'ipsec0', dist: 20, metric: 0, age: '00:01:23', aspath: '' },
        { proto: 'kernel', active: 1, nhactive: 1, nexthop: '', direct: 1, iface: 'ipsec0', dist: 0, metric: 0, age: '00:02:14', aspath: '' }
    ],
    '10.99.99.99/32': [{ proto: 'static', active: 1, nhactive: 1, nexthop: '', direct: 1, iface: 'ipsec0', dist: 1, metric: 0, age: '00:02:00', aspath: '' }],
    '172.16.210.0/24': [{ proto: 'bgp', active: 1, nhactive: 1, nexthop: '10.99.99.99', iface: 'ipsec0', dist: 20, metric: 0, age: '00:01:23', aspath: '64513' }]
};
context.frr_ipsec_route_v6 = {};
context.select_route_table('ipsec');
const zebra220 = elements.routev4block.innerHTML;
for (const text of ['IPsec (table 220)', 'BGP', 'Static', 'Kernel', '[20/0]', '[1/0]', '00:01:23', '64513', '172.16.210.0/24', '(throw)', '138.2.180.75/32', '10.0.0.0/26'])
    assert(zebra220.includes(text), text);
assert.equal(elements.route_filters.style.display, '');
context.set_route_filter('proto', { value: 'bgp' });
assert(elements.routev4block.innerHTML.includes('2 / 7 routes shown.'));
context.set_route_filter('proto', { value: '' });
context.set_route_filter('destination', { value: '172.16.210.' });
assert(elements.routev4block.innerHTML.includes('2 / 7 routes shown.'));
context.set_route_filter('longestMatch', { checked: true });
assert(elements.routev4block.innerHTML.includes('1 / 7 routes shown.'));
context.set_route_filter('longestMatch', { checked: false });
context.set_route_filter('nexthop', { value: 'not-present' });
assert(elements.routev4block.innerHTML.includes('No matching IPv4 routes.'));
context.set_route_filter('nexthop', { value: '' });
context.set_route_filter('destination', { value: '' });
context.sortfield_v4 = 1;
context.sortdir_v4 = 0;
context.show_routev4();
const sorted = elements.routev4block.innerHTML;
assert(sorted.indexOf('172.16.210.0/24') < sorted.indexOf('172.16.210.0/32'));
context.frr_ipsec_overlay_enabled = 0;
context.select_route_table('ipsec');
assert(elements.routev4block.innerHTML.includes('Genmask'));
assert.equal(elements.route_filters.style.display, 'none');

const frrBackend = fs.readFileSync(path.join(root, 'release/src/router/httpd/frr_web.c'), 'utf8');
assert(frrBackend.includes('"show ip route table 220 json"'));
assert(frrBackend.includes('"show ipv6 route table 220 json"'));
assert(/frr_write_ipsec_route_origin\(wp\)/.test(fs.readFileSync(path.join(root, 'release/src/router/httpd/data_arrays.c'), 'utf8')));

const routeWriter = frrBackend.slice(frrBackend.indexOf('static int frr_write_route_origin_object'),
    frrBackend.indexOf('static void frr_append_delimited'));
assert(routeWriter.includes('frr_write_json_string(wp, prefix_key)'));
for (const value of ['proto', 'nh_ip', 'nh_iface', 'age', 'aspath'])
    assert(routeWriter.includes(`frr_write_json_string(wp, ${value})`), value);
assert.match(frrBackend, /getsockopt\(fd, SOL_SOCKET, SO_PEERCRED, &credentials/);
assert.match(frrBackend, /credentials\.pid == expected_pid/);
assert.match(frrBackend, /proc_stat\.st_ino == daemon_stat\.st_ino/);
assert.match(frrBackend, /if \(!frr_vty_peer_matches_daemon\(fd, daemon\)\)/);
assert.match(frrBackend, /return frr_daemon_process_matches\(pid, daemon_name\);/);
const jsEscapes = [
    String.raw`case '"': ret += websWrite(wp, "\\\""); break;`,
    String.raw`case '\'': ret += websWrite(wp, "\\u0027"); break;`,
    String.raw`case '\\': ret += websWrite(wp, "\\\\"); break;`,
    String.raw`case '/': ret += websWrite(wp, "\\/"); break;`,
    String.raw`case '<': ret += websWrite(wp, "\\u003c"); break;`,
    String.raw`case '>': ret += websWrite(wp, "\\u003e"); break;`,
    String.raw`case '&': ret += websWrite(wp, "\\u0026"); break;`,
    String.raw`case '\b': ret += websWrite(wp, "\\b"); break;`,
    String.raw`case '\f': ret += websWrite(wp, "\\f"); break;`,
    String.raw`case '\n': ret += websWrite(wp, "\\n"); break;`,
    String.raw`case '\r': ret += websWrite(wp, "\\r"); break;`,
    String.raw`case '\t': ret += websWrite(wp, "\\t"); break;`
];
for (const escape of jsEscapes)
    assert(frrBackend.includes(escape), `missing source escape ${escape}`);
const bfdConfig = frrBackend.slice(frrBackend.indexOf('int ej_get_frr_bfd_config'),
    frrBackend.indexOf('int ej_get_frr_route_origin_array'));
for (const value of ['peer_value', 'tx_value', 'rx_value'])
    assert(bfdConfig.includes(`frr_write_json_string(wp, ${value})`), value);
assert(frrBackend.includes('p[2] == 0xa8 ? "\\\\u2028" : "\\\\u2029"'));
assert((frrBackend.match(/frr_write_json_script\(wp,/g) || []).length >= 3);
for (const value of ['neighbors', 'neighbor_as', 'neighbor_desc', 'neighbor_src'])
    assert(frrBackend.includes(`frr_write_js_string_contents(wp, parsed_${value})`), value);

const encodeScriptString = value => JSON.stringify(value)
    .replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029')
    .replace(/'/g, '\\u0027');
const hostilePrefix = 'x":[]};alert(1);//';
const hostileDescription = `";alert(2);//</script>&\u2028\u2029'`;
let injected = 0;
const encodedScript = `var routes = {${encodeScriptString(hostilePrefix)}:[]};\n` +
    `var description = ${encodeScriptString(hostileDescription)};`;
const encodedContext = { alert: () => injected++ };
vm.runInNewContext(encodedScript, encodedContext);
assert.equal(injected, 0);
assert.equal(encodedContext.description, hostileDescription);
assert.deepEqual(Object.keys(encodedContext.routes), [hostilePrefix]);

const backend = fs.readFileSync(path.join(root, 'release/src/router/httpd/data_arrays.c'), 'utf8');
assert(backend.includes('nvram_match("ipsec_client_enable", "1")'));
assert(backend.includes('index == 37'));
assert(backend.includes('}:  INSTALLED,'));
assert(backend.includes('execl("/usr/lib/ipsec/stroke"'));
assert(!/waitpid\(child, &child_status, 0\)/.test(backend));
assert(backend.includes('table != 220'));
assert(backend.includes('RTNH_F_ONLINK'));
assert(backend.includes('route->rtm_protocol'));
console.log('PASS: conditional route selector, labels, original layout, sample route forms, filtering, sorting, escaping, refresh, disconnect, FRR and backend source contracts');