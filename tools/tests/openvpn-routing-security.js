const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const sourcePath = path.resolve(__dirname, '../../release/src/router/libovpn/openvpn_control.c');
const source = fs.readFileSync(sourcePath, 'utf8');
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

console.log('OpenVPN routing temp-file and shell-injection contracts passed');