const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const dnsfilter = fs.readFileSync(path.join(root, 'release/src/router/rc/dnsfilter.c'), 'utf8');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const page = fs.readFileSync(path.join(root, 'release/src/router/www/DNSDirector.asp'), 'utf8');

const helper = dnsfilter.match(/^void dnsfilter_setup_dnsmasq\(FILE \*fp\) \{([\s\S]*?)^\}/m);
assert(helper, 'DNS Director dnsmasq generator exists');
assert.match(helper[1], /dhcp-option=tag:dnsf%u,6,%s/,
    'per-client IPv4 DNS uses a tagged DHCP option');
assert.match(helper[1], /dhcp-option=tag:dnsf%u,option6:23/,
    'per-client IPv6 DNS uses a tagged DHCP option');
assert.match(helper[1], /dhcp-host=%s,set:dnsf%u/,
    'client host entries set the matching dnsfilter tag');
assert.match(helper[1], /dnsfilter_static_lease_exists\(mac\)/,
    'DNS Director does not emit a duplicate host entry for static leases');
assert.doesNotMatch(helper[1], /dhcp-option=dnsf%u/,
    'DHCP options do not treat the tag as an option code');

const staticLeases = services.match(/^void write_static_leases\(FILE \*fp\)\s*\{([\s\S]*?)^\}/m);
assert(staticLeases, 'static DHCP lease generator exists');
assert.match(staticLeases[1], /dnsfilter_get_client_mode\(mac\)/,
    'static reservations look up the matching DNS Director mode');
assert.match(staticLeases[1], /set:dnsf%d/,
    'static and DNS Director tags are emitted on one dhcp-host entry');
assert.match(staticLeases[1], /if \(\*dnsfilter_tag\)\s*dns = NULL/,
    'DNS Director resolver takes precedence over a reservation DNS option');

const dnsmasqStart = services.indexOf('void start_dnsmasq(void)');
const dnsmasqCall = services.indexOf('dnsfilter_setup_dnsmasq(fp);', dnsmasqStart);
const ipv6Setup = services.indexOf('if (ipv6_enabled() && is_routing_enabled())', dnsmasqStart);
assert(dnsmasqCall >= 0 && ipv6Setup >= 0 && dnsmasqCall < ipv6Setup,
    'DNS Director DHCP options are generated outside the IPv6-only block');

assert.match(page, /action_script" value="restart_firewall;restart_dnsmasq"/,
    'Apply refreshes the firewall and DHCP configuration through supported services');
assert.match(page, /dnsfilter_settings_changed\(\)[\s\S]*?action_script\.value = ""/,
    'unchanged Apply does not dispatch service restarts');

console.log('DNS Director DHCP option contracts passed');