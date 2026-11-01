#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');

const services = fs.readFileSync('release/src/router/rc/services.c', 'utf8');
const watchdog = fs.readFileSync('release/src/router/rc/watchdog.c', 'utf8');

assert.match(services, /static int nas_preauth_add_bss[\s\S]*?nvram_match\(wl_nvname\("preauth", unit, subunit\), "1"\)/);
assert.match(services, /nas_preauth_add_bss[\s\S]*?wl_nvname\("hwaddr", unit, subunit\)[\s\S]*?"-d", \(char \*\)bssid, "-j", "RETURN"/);
assert.match(services, /NAS_PREAUTH_CHAIN, "-j", "DROP"[\s\S]*?foreach_wif\(1, NULL, nas_preauth_add_bss\)/);
assert.match(services, /"-I", "INPUT", "1", "-p", "0x88c7",\s*"-j", NAS_PREAUTH_CHAIN/);
assert.match(services, /drop_all:[\s\S]*?"-I", "INPUT", "1", "-p", "0x88c7",\s*"-j", "DROP"/);
assert.match(services, /update_nas_preauth_filter\(\);[\s\S]*?ret = eval\("\/bin\/eapd"\)/);

assert.match(watchdog, /nas_wpa_bss_enabled[\s\S]*?auth_mode_x[\s\S]*?strstr\(auth_mode, "wpa"\)[\s\S]*?strstr\(auth_mode, "psk"\)/);
assert.match(watchdog, /nas_eapd_check[\s\S]*?if \(\+\+missing < 2\)[\s\S]*?now - last_restart < 60/);
assert.match(watchdog, /pids\("nas"\) && pids\("eapd"\)[\s\S]*?notify_rc\("restart_nas"\)/);
const dnsmasqStart = watchdog.indexOf('void dnsmasq_check()');
const dnsmasqOpen = watchdog.indexOf('{', dnsmasqStart);
let braceDepth = 0;
let dnsmasqEnd = dnsmasqOpen;
for (; dnsmasqEnd < watchdog.length; dnsmasqEnd++) {
	if (watchdog[dnsmasqEnd] === '{') braceDepth++;
	if (watchdog[dnsmasqEnd] === '}' && --braceDepth === 0) break;
}
assert.ok(watchdog.indexOf('static int nas_wpa_bss_enabled') > dnsmasqEnd);
assert.ok(watchdog.indexOf('static int nas_wpa_bss_enabled') < watchdog.indexOf('void wigig_temperatore_check'));
assert.match(watchdog, /dnsmasq_check\(\);[\s\S]*?nas_eapd_check\(\);/);

console.log('NAS pre-auth containment and watchdog contracts passed');