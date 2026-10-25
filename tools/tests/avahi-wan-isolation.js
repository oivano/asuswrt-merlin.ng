import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const services = readFileSync(new URL('../../release/src/router/rc/services.c', import.meta.url), 'utf8');
const firewall = readFileSync(new URL('../../release/src/router/rc/firewall.c', import.meta.url), 'utf8');
const mdnsGenerator = services.match(/int generate_mdns_config\(void\)([\s\S]*?)\n\}/)?.[1];

assert.ok(mdnsGenerator, 'Avahi config generator exists');
assert.match(mdnsGenerator, /deny-interfaces=/);
assert.match(mdnsGenerator, /unit < WAN_UNIT_MAX/);
assert.match(mdnsGenerator, /WAN_UNIT_FIRST_MULTISRV_START; unit <= WAN_UNIT_FIRST_MULTISRV_END/);
assert.match(mdnsGenerator, /WAN_UNIT_SECOND_MULTISRV_START; unit <= WAN_UNIT_SECOND_MULTISRV_END/);
assert.match(mdnsGenerator, /wan%d_ifname/);
assert.doesNotMatch(mdnsGenerator, /deny-interfaces=%s.*wan0_ifname/);

assert.match(firewall, /static char \*multicast_upstream_ifname\(void\)/);
assert.match(firewall, /nvram_safe_get\("iptv_ifname"\)/);
assert.match(firewall, /get_wan_ifname\(wan_primary_ifunit\(\)\)/);

const multicastRules = firewall.match(/fprintf\(fp, "-A INPUT[^\n]+224\.0\.0\.0\/4[^\n]+/g) ?? [];
assert.equal(multicastRules.length, 4, 'both firewall generators constrain IPv4 multicast rules');
for (const rule of multicastRules) {
	assert.match(rule, /-i %s/);
	assert.doesNotMatch(rule, /! -d/);
}
assert.equal((firewall.match(/-p udp -d 224\.0\.0\.(?:251|252)|-p udp -d 239\.255\.255\.250/g) ?? []).length, 6,
	'both firewall generators drop discovery groups before accepting multicast');
const multicastBlocks = [...firewall.matchAll(/if \(nvram_get_int\("mr_enable_x"\) \|\| nvram_get_int\("udpxy_enable_x"\)\) \{([\s\S]*?)\n\s*\}/g)]
	.filter(([, block]) => block.includes('-d 224.0.0.0/4'));
assert.equal(multicastBlocks.length, 2, 'single- and dual-WAN multicast blocks exist');
for (const [, block] of multicastBlocks) {
	const acceptIndex = block.indexOf('-d 224.0.0.0/4');
	assert.ok(acceptIndex >= 0, 'broad multicast accept exists');
	for (const group of ['224.0.0.251', '224.0.0.252', '239.255.255.250']) {
		const dropIndex = block.indexOf(`-d ${group} -j DROP`);
		assert.ok(dropIndex >= 0 && dropIndex < acceptIndex, `${group} is dropped before multicast is accepted`);
	}
}

console.log('Avahi WAN isolation source contracts passed');