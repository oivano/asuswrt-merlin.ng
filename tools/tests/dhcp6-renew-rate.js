const assert = require('assert');
const fs = require('fs');

const dhcpv6 = fs.readFileSync('release/src/router/odhcp6c/src/dhcpv6.c', 'utf8');
const hook = fs.readFileSync('release/src/router/rc/udhcpc.c', 'utf8');
const services = fs.readFileSync('release/src/router/rc/services.c', 'utf8');

assert.match(dhcpv6, /#define DHCPV6_T1_MINIMUM 60/);
assert.match(dhcpv6, /#define DHCPV6_IRT_MINIMUM 600/);
assert.match(dhcpv6, /refresh = ntohl_unaligned\(odata\);\s*if \(refresh < DHCPV6_IRT_MINIMUM\)\s*refresh = DHCPV6_IRT_MINIMUM;/);
assert.strictEqual((dhcpv6.match(/t1_min = entry\.valid < DHCPV6_T1_MINIMUM \? entry\.valid : DHCPV6_T1_MINIMUM;/g) || []).length, 2);

const bound6 = hook.slice(hook.indexOf('bound6(char *wan_ifname, int bound)'), hook.indexOf('\nstatic int\nra_updated6'));
assert(!bound6.includes('notify_rc("restart_samba")'));
assert.match(bound6, /if \(prefix_changed \|\| lanaddr_changed\)\s*notify_rc\("restart_dnsmasq"\);/);
assert.match(bound6, /if \(dns_changed && nvram_get_int\(ipv6_nvname_by_unit\("ipv6_dnsenable", wan_unit\)\)\)\s*update_resolvconf\(\);/);
const dnsmasqHandlerStart = services.indexOf('else if (strcmp(script, "dnsmasq") == 0)');
const dnsmasqHandler = services.slice(services.lastIndexOf('#ifdef RTCONFIG_IPV6', dnsmasqHandlerStart), services.indexOf('#endif', dnsmasqHandlerStart));
assert.match(dnsmasqHandler, /stop_dnsmasq\(\)[\s\S]*start_dnsmasq\(\)/);

function clampRefresh(seconds) {
    return Math.max(seconds, 600);
}

function clampRenew(t1, t2, valid) {
    if (t1 > t2)
        t1 = t2;
    const minimum = Math.min(valid, 60);
    if (t2 < minimum)
        t2 = minimum;
    if (t1 < minimum)
        t1 = minimum;
    return { t1, t2 };
}

assert.strictEqual(clampRefresh(1), 600);
assert.strictEqual(clampRefresh(600), 600);
assert.strictEqual(clampRefresh(3600), 3600);
assert.deepStrictEqual(clampRenew(1, 3600, 3600), { t1: 60, t2: 3600 });
assert.deepStrictEqual(clampRenew(0, 3600, 3600), { t1: 60, t2: 3600 });
assert.deepStrictEqual(clampRenew(1, 30, 3600), { t1: 60, t2: 60 });
assert.deepStrictEqual(clampRenew(1, 30, 30), { t1: 30, t2: 30 });
assert.deepStrictEqual(clampRenew(120, 3600, 3600), { t1: 120, t2: 3600 });

console.log('DHCPv6 renewal rate checks passed');