const assert = require('assert');
const fs = require('fs');

const etc = fs.readFileSync('release/src-rt-6.x.4708/et/sys/etc.c', 'utf8');
const linux = fs.readFileSync('release/src-rt-6.x.4708/et/sys/et_linux.c', 'utf8');

const powerSave = etc.match(/case IOV_ET_POWER_SAVE_MODE:([\s\S]*?)\n\s*case IOV_ET_ROBO_DEVID:/);
assert(powerSave, 'power-save iovar handler exists');

const guard = powerSave[1].match(/if\s*\(\(set && vecarg\[0\] >= MAX_NO_PHYS\) \|\|\s*\(!set && vecarg\[0\] > MAX_NO_PHYS\)\)\s*\{\s*error = -1;\s*break;\s*\}/);
assert(guard, 'invalid ports are rejected before power-save dispatch');
assert(powerSave[1].indexOf(guard[0]) < powerSave[1].indexOf('robo_power_save_mode_set'));
assert(powerSave[1].indexOf(guard[0]) < powerSave[1].indexOf('robo_power_save_mode_get'));
assert(powerSave[1].includes('if (vecarg[0] == MAX_NO_PHYS)'), 'get-all sentinel remains supported');

const isRejected = new Function('set', 'port', `return (set && port >= 5) || (!set && port > 5);`);
for (const port of [0xffffffff, 0xfffff000, 0x80000000]) {
	assert(isRejected(true, port), `set rejects port ${port}`);
	assert(isRejected(false, port), `get rejects port ${port}`);
}
assert(isRejected(true, 5), 'set rejects the get-all sentinel');
assert(!isRejected(false, 4), 'get accepts the last physical port');
assert(!isRejected(false, 5), 'get accepts the get-all sentinel');

const capabilityGate = linux.match(/switch \(cmd\) \{([\s\S]*?)\n\s*switch \(cmd\) \{/);
assert(capabilityGate, 'private ioctl capability gate precedes dispatch');
assert(capabilityGate[1].includes('if (!capable(CAP_NET_ADMIN))\n\t\t\treturn (-EPERM);'));
for (const command of [
	'SIOCSETGETVAR', 'SIOCSETCPHYWR', 'SIOCSETCPHYWR2', 'SIOCSETCROBOWR',
	'SIOCSETCUP', 'SIOCSETCDOWN', 'SIOCSETCLOOP', 'SIOCSETCSETMSGLEVEL',
	'SIOCSETCPROMISC', 'SIOCSETCSPEED', 'SIOCSETCQOS'
]) {
	assert(capabilityGate[1].includes(`case ${command}:`), `${command} is capability-gated`);
}

console.log('et power-save iovar and private ioctl checks passed');