#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const wan = read('release/src/router/rc/wan.c');
const wanduck = read('release/src/router/rc/wanduck.c');
const rc = read('release/src/router/rc/rc.c');
const vpnc = read('release/src/router/rc/vpnc.c');
const service = read('release/src/router/rc/services.c');
const openvpn = read('release/src/router/libovpn/openvpn_control.c');
const ipsec = read('release/src/router/rc/rc_ipsec.c');

assert.match(wan, /add_multi_routes\(0, wan_unit\);[\s\S]*?stop_ovpn_eas\(\);\s*notify_rc\("start_vpnrouting"\);/);
assert.match(wan, /add_multi_routes\(1, -1\);\s*#ifdef RTCONFIG_OPENVPN\s*notify_rc\("start_vpnrouting"\);/);
assert.match(wanduck, /add_multi_routes\(0, -1\);\s*#ifdef RTCONFIG_OPENVPN\s*notify_rc\("start_vpnrouting"\);/);
assert.match(rc, /result = add_multi_routes\([\s\S]*?notify_rc\("start_vpnrouting"\);[\s\S]*?return result;/);
assert.match(vpnc, /add_multi_routes\(\);\s*#ifdef RTCONFIG_OPENVPN\s*notify_rc\("start_vpnrouting"\);/);

assert.match(openvpn, /void ovpn_client_route_up_handler\(\)\s*\{\s*ovpn_reapply_routing_rules\(\);/);
assert.match(openvpn, /void ovpn_reapply_routing_rules\(void\)[\s\S]*?file_lock\(VPNROUTING_LOCK\)[\s\S]*?ovpn_set_routing_rules\(unit\);\s*ovpn_set_killswitch\(unit\);/);
assert.match(service, /ovpn_set_routing_rules\(i\);\s*ovpn_set_killswitch\(i\);/);
assert.match(service, /rc_ipsec_reapply_director_rules\(\);/);

assert.match(ipsec, /void rc_ipsec_reapply_director_rules\(void\)[\s\S]*?state-%d[\s\S]*?rules-%d[\s\S]*?_ipsec_director_rules_set\(unit, rules, 1\)[\s\S]*?"pref", "102"/);
assert.match(ipsec, /static bool ipsec_init_done = FALSE;[\s\S]*?if \(conn_status != IPSEC_SET \|\| ipsec_init_done\)\s*pre_bitmap_en\[prof_count\] = cur_bitmap_en_p\[prof_count\];[\s\S]*?if \(conn_status == IPSEC_INIT\)\s*ipsec_init_done = TRUE;/);
console.log('VPN routing recovery contracts passed');