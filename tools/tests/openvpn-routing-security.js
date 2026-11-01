const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');

const sourcePath = path.resolve(__dirname, '../../release/src/router/libovpn/openvpn_control.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const root = path.resolve(__dirname, '../..');
const setup = fs.readFileSync(path.join(root, 'release/src/router/libovpn/openvpn_setup.c'), 'utf8');
const dnsmasq = fs.readFileSync(path.join(root, 'release/src/router/dnsmasq/src/option.c'), 'utf8');
const section = (start, end) => {
    const first = source.indexOf(start);
    const last = source.indexOf(end, first);
    assert.ok(first >= 0 && last > first, `missing section ${start}`);
    return source.slice(first, last);
};

const routeHelper = section('static void _ovpn_apply_route_listing(', '\n\nint ovpn_skip_dnsmasq()');
assert.match(routeHelper, /strtok_r\(line, " \\t", &saveptr\)/);
assert.match(routeHelper, /argv\[argc\+\+\] = "table";/);
assert.match(routeHelper, /_eval\(argv, NULL, 0, NULL\)/);
assert.doesNotMatch(routeHelper, /\bsystem\s*\(/);
assert.match(routeHelper, /_ovpn_route_has_dev\(route_args, route_argc, iface\)/);

const clientUp = section('void ovpn_client_up_handler(int unit)', '\n\n// Remove all rules pointing');
assert.match(clientUp, /popen\("\/usr\/sbin\/ip route show table main", "r"\)/);
assert.match(clientUp, /_ovpn_apply_route_listing\(fp_route, unit, "add", NULL, verb\)/);

const clearRules = section('void _clear_routing_rules(int unit)', '\n\n/*\n\tRule priority allocations:');
assert.match(clearRules, /popen\("\/usr\/sbin\/ip rule show", "r"\)/);
assert.match(clearRules, /eval\("\/usr\/sbin\/ip", "rule", "del", "prio", prio_str\)/);
assert.doesNotMatch(clearRules, /\b(system|fopen|unlink)\s*\(/);

const addRoutes = section('void _add_server_routes(', '\n\nvoid _del_server_routes(');
const delRoutesStart = source.indexOf('void _del_server_routes(');
const delRoutesEnd = source.indexOf('\n}', delRoutesStart) + 2;
assert.ok(delRoutesStart >= 0 && delRoutesEnd > delRoutesStart);
const delRoutes = source.slice(delRoutesStart, delRoutesEnd);
for (const handler of [addRoutes, delRoutes]) {
    assert.match(handler, /popen\(/);
    assert.match(handler, /_ovpn_apply_route_listing\(/);
    assert.doesNotMatch(handler, /\b(system|fopen|unlink)\s*\(/);
    assert.doesNotMatch(handler, /grep|vpnroute\d*_tmp/);
}

assert.doesNotMatch(source, /\/tmp\/vpn(?:route|rules)\d*_tmp/);
assert.doesNotMatch(clientUp, /system\(buffer3\)/);

const injectedRoute = '198.51.100.0/24 dev tun0 ; `touch /tmp/pwn` $(id)';
const argv = injectedRoute.trim().split(/[ \t]+/);
assert.ok(argv.includes(';'));
assert.ok(argv.includes('`touch'));
assert.ok(argv.includes('$(id)'));
assert.match(routeHelper, /_eval\(argv, NULL, 0, NULL\)/);

const pushedOptions = clientUp.slice(clientUp.indexOf('// Parse foreign options'), clientUp.indexOf('\nexit:'));
for (const [kind, offset, output] of [
    ['WINS', 17, 'dhcp-option=44,%s'],
    ['DNS', 16, 'server=%s'],
]) {
    assert.match(pushedOptions, new RegExp(`inet_pton\\(AF_INET, &option\\[${offset}\\], &network\\) != 1`));
    assert.match(pushedOptions, /inet_ntop\(AF_INET, &network, address, sizeof\(address\)\)/);
    assert.match(pushedOptions, new RegExp(`Ignoring invalid ${kind} address from client %d`));
    assert.ok(pushedOptions.includes(`"${output}\\n", address`), `${kind} output must use canonical address`);
}
assert.doesNotMatch(pushedOptions, /inet_aton\(&option\[(16|17)\]/);
assert.doesNotMatch(pushedOptions, /fprintf\(fp_(conf|resolv),[^;]*&option\[(16|17)\]/);

const setupStart = setup.indexOf('void write_ovpn_dnsmasq_config(');
const setupEnd = setup.indexOf('\n\nchar *get_ovpn_remote_address', setupStart);
assert.ok(setupStart >= 0 && setupEnd > setupStart, 'missing dnsmasq OpenVPN config writer');
const dnsmasqWriter = setup.slice(setupStart, setupEnd);
assert.match(dnsmasqWriter, /fprintf\(dnsmasq_conf, "dhcp-optsfile=%s\\n", filename\)/);
assert.doesNotMatch(dnsmasqWriter, /read_whole_file|fwrite\(/);

const optsReadStart = dnsmasq.indexOf('if (daemon->dhcp_opts_file)');
assert.ok(optsReadStart >= 0, 'missing dnsmasq DHCP options file reader');
assert.match(dnsmasq.slice(optsReadStart, optsReadStart + 650), /one_file\(hf->fname, LOPT_OPTS\)/);
const parserStart = dnsmasq.indexOf('static int one_file(char *file, int hard_opt)');
const parserEnd = dnsmasq.indexOf('\n#if defined(HAVE_DHCP) && defined(HAVE_INOTIFY)', parserStart);
const parserError = dnsmasq.slice(parserStart, parserEnd);
assert.match(parserError, /if \(hard_opt != 0\)[\s\S]*?my_syslog\(LOG_ERR[\s\S]*?else\s*die\(/);

for (const value of ['1.2.3.4', '255.255.255.255'])
    assert.equal(net.isIPv4(value), true, `${value} should be accepted as an IPv4 address`);
for (const value of ['1.2.3.4 x', '1.2.3.4\t', ' 1.2.3.4', '1.2.3', '2001:db8::1'])
    assert.equal(net.isIPv4(value), false, `${JSON.stringify(value)} should be rejected`);

console.log('OpenVPN routing and pushed DNS/WINS security contracts passed');