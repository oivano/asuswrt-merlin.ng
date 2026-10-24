const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const lan = fs.readFileSync(path.join(root, 'release/src/router/rc/lan.c'), 'utf8');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');

assert.match(lan, /eval\("ebtables", "--concurrent", "-t", "filter"/);
assert.doesNotMatch(lan, /GUEST_ARP_EBTABLES\("-C"/);
assert.match(lan, /"--arp-mac-src", binding->mac,[\s\S]*?"--arp-ip-src", binding->ip/);
assert.match(lan, /"--arp-ip-src", "0\.0\.0\.0", "-j", "ACCEPT"/);
assert.match(lan, /"-p", "arp",[\s\S]*?"-j", "DROP"/);
assert.match(lan, /guest_arp_binding_find\(current_bindings, current_count,[\s\S]*?binding->ifname, binding->mac, binding->ip\)/);
assert.match(lan, /guest_arp_save_state\(current_bindings, current_count\)/);
assert.match(lan, /active = is_router_mode\(\) && find_in_list\(lan_ifnames, ifnames\[i\]\) &&[\s\S]*?nvram_match\(key, "off"\)/);
assert.match(lan, /guest_arp_filter_refresh\(\);/);
assert.match(lan, /void lanaccess_wl\(void\)[\s\S]*?guest_arp_filter_refresh\(\);/);
assert.match(services, /int dnsmasq_script_main\([\s\S]*?guest_arp_filter_refresh\(\);/);

console.log('guest ARP lease-filter source contracts passed');