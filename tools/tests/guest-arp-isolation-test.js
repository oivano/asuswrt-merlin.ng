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
assert.match(lan, /guest_arp_save_state\(state_dirfd, current_bindings, current_count\)/);
assert.match(lan, /#define GUEST_ARP_STATE_DIR "\/tmp\/guest-arp"/);
const stateLoad = lan.match(/static int guest_arp_load_state\([\s\S]*?\n\}/)[0];
const stateSave = lan.match(/static int guest_arp_save_state\([\s\S]*?\n\}/)[0];
assert.match(lan, /open\(GUEST_ARP_STATE_DIR, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(lan, /st\.st_uid != 0[\s\S]*?st\.st_gid != 0[\s\S]*?fchmod\(fd, 0700\)/);
assert.match(stateLoad, /openat\(dirfd, GUEST_ARP_STATE_NAME, O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK\)/);
assert.match(stateLoad, /S_ISREG\(st\.st_mode\)[\s\S]*?st\.st_uid != 0[\s\S]*?st\.st_nlink != 1/);
assert.doesNotMatch(stateLoad, /fopen\(|GUEST_ARP_STATE_FILE/);
assert.match(stateSave, /O_CREAT \| O_EXCL \| O_NOFOLLOW \| O_NONBLOCK/);
assert.match(stateSave, /S_ISREG\(st\.st_mode\)[\s\S]*?st\.st_uid != 0[\s\S]*?st\.st_nlink != 1/);
assert.match(stateSave, /renameat\(dirfd, GUEST_ARP_STATE_TMP_NAME,[\s\S]*?dirfd, GUEST_ARP_STATE_NAME\)/);
assert.doesNotMatch(stateSave, /\bfopen\(|\bchmod\(|\brename\(|GUEST_ARP_STATE_TMP_FILE/);
assert.match(lan, /active = is_router_mode\(\) && find_in_list\(lan_ifnames, ifnames\[i\]\) &&[\s\S]*?nvram_match\(key, "off"\)/);
assert.match(lan, /guest_arp_filter_refresh\(\);/);
assert.match(lan, /void lanaccess_wl\(void\)[\s\S]*?guest_arp_filter_refresh\(\);/);
assert.match(services, /int dnsmasq_script_main\([\s\S]*?guest_arp_filter_refresh\(\);/);

console.log('guest ARP lease-filter source contracts passed');