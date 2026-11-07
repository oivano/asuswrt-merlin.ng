const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.resolve(__dirname, '../../release/src/router/rc/firewall.c'), 'utf8');
const defaultStart = source.indexOf('start_default_filter(int lanunit)');
const defaultEnd = source.indexOf('evalRet = eval("iptables-restore"', defaultStart);
assert(defaultStart >= 0 && defaultEnd > defaultStart, 'find the boot-time IPv4 filter generator');

const defaultFilter = source.slice(defaultStart, defaultEnd);
const ports = '37000,38000,39000,42000,43000,51000,59000';
const guard = `fprintf(fp, "-A INPUT ! -i lo -p udp -m multiport --dports ${ports} -j DROP\\n");`;
const guardIndex = defaultFilter.indexOf(guard);
assert(guardIndex >= 0, 'boot-time IPv4 filter drops eapd UDP ports on non-loopback interfaces');
assert(guardIndex < defaultFilter.indexOf('write_guest_ipv4_input_rules'), 'guard precedes guest INPUT allows');
assert(guardIndex < defaultFilter.indexOf('"-A INPUT -i %s -m state --state NEW -j ACCEPT'), 'guard precedes LAN INPUT accept');

assert.equal(source.split(guard).length - 1, 3,
    'default and both complete IPv4 filter generators retain the guard');

console.log('PASS: boot-time and complete IPv4 filter generators drop non-loopback eapd UDP ports before INPUT allows');
