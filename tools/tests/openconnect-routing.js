const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const script = read('release/src/router/openconnect/vpnc-script');
const control = read('release/src/router/rc/rc_openconnect.c');
const wan = read('release/src/router/rc/wan.c');
const services = read('release/src/router/rc/services.c');

const extractShellFunction = name => {
    const match = script.match(new RegExp(`^\\t${name}\\(\\) \\{[\\s\\S]*?^\\t\\}`, 'm'));
    assert.ok(match, `${name} function exists`);
    return match[0];
};
const setDefaultRoute = extractShellFunction('set_default_route');
const setNetworkRoute = extractShellFunction('set_network_route');
const setExcludeRoute = extractShellFunction('set_exclude_route');

const runRouteFunctions = redirect => spawnSync('/bin/sh', ['-c', [
    'IPROUTE=ip',
    'ip() { printf "%s\\n" "$*"; }',
    'ASUSWRT_OPENCONNECT_UNIT=1',
    `ASUSWRT_OPENCONNECT_REDIRECT_GATEWAY=${redirect}`,
    'TUNDEV=tun11',
    setDefaultRoute,
    setNetworkRoute,
    setExcludeRoute,
    'set_default_route',
    'set_network_route 192.168.50.0 255.255.255.0 24 tun11',
    'set_exclude_route 192.168.50.0 255.255.255.0 24'
].join('\n')], { encoding: 'utf8' });

let result = runRouteFunctions(0);
assert.equal(result.status, 0, result.stderr);
assert.doesNotMatch(result.stdout, /route replace default/);
assert.match(result.stdout, /route replace 192\.168\.50\.0\/24 dev tun11 table 301/);
assert.match(result.stdout, /rule add to 192\.168\.50\.0\/24 table 301 priority 8101/);
assert.match(result.stdout, /rule add to 192\.168\.50\.0\/24 lookup main priority 8001/);
assert.doesNotMatch(result.stdout, /route add .*192\.168\.50\.0/);

result = runRouteFunctions(1);
assert.equal(result.status, 0, result.stderr);
assert.match(result.stdout, /route replace default dev tun11 table 301/);
assert.match(result.stdout, /rule add table 301 priority 8201/);
assert.doesNotMatch(result.stdout, /route replace default dev tun11\n/);

const connect = script.slice(script.indexOf('do_connect() {'), script.indexOf('\ndo_disconnect() {'));
assert.ok(connect.indexOf('rule add to "$1" lookup main priority "$PROTECT_PREF"') <
    connect.indexOf('do_ifconfig'));
assert.match(connect, /route show table main/);
assert.match(script, /ASUSWRT_OPENCONNECT_ACCEPT_DNS/);
assert.match(script, /ASUSWRT_OPENCONNECT_ACCEPT_DOMAIN/);
assert.match(script, /openconnect_dnsmasq_update/);
assert.match(control, /nvram_pf_get_int\(varname, "redirect_gateway"\) == 1/);
assert.match(control, /nvram_pf_get_int\(varname, "accept_dns"\) == 1/);
assert.match(control, /nvram_pf_get_int\(varname, "accept_domain"\) == 1/);
assert.match(control, /inet_pton\(AF_INET, server/);
assert.match(control, /inet_pton\(AF_INET6, server/);
assert.match(control, /openconnect_valid_dns_domain/);
assert.match(control, /server=\/%s\/%s/);
assert.match(wan, /write_openconnect_resolv_dnsmasq\(fp_servers\)/);
assert.match(services, /write_openconnect_resolv_dnsmasq\(fp\)/);
assert.match(services, /openconnect_dnsmasq_update/);
assert.match(control, /route.*flush.*table/);
assert.match(control, /SIGKILL/);

console.log('OpenConnect routing and DNS policy checks passed');