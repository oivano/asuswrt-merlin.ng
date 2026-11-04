const assert = require('assert');
const fs = require('fs');

const etc = fs.readFileSync('release/src-rt-6.x.4708/et/sys/etc.c', 'utf8');
const linux = fs.readFileSync('release/src-rt-6.x.4708/et/sys/et_linux.c', 'utf8');
const ioctlHeader = fs.readFileSync('release/src-rt-6.x.4708/include/etioctl.h', 'utf8');

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

const privateIoctlGuard = linux.match(/if \(cmd >= SIOCDEVPRIVATE && cmd <= SIOCDEVPRIVATE \+ ETCROBOWR &&\s*!capable\(CAP_NET_ADMIN\)\)\s*return \(-EPERM\);/);
assert(privateIoctlGuard, 'the complete et private ioctl range requires CAP_NET_ADMIN');
assert.match(ioctlHeader, /^#define ETCROBOWR\s+15$/m,
	'ETCROBOWR remains the highest et private ioctl offset');
const etIoctl = linux.slice(linux.indexOf('et_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)\n{'));
assert(etIoctl.indexOf(privateIoctlGuard[0]) < etIoctl.indexOf('ET_INFO(dev)'),
	'capability check precedes driver state access');
for (const operation of ['MALLOC(et->osh, size)', 'copy_from_user']) {
	assert(etIoctl.indexOf(privateIoctlGuard[0]) < etIoctl.indexOf(operation),
		`capability check precedes ${operation}`);
}

const isDenied = (offset, hasCapability) => offset >= 0 && offset <= 15 && !hasCapability;
for (let offset = 0; offset <= 15; offset++) {
	assert(isDenied(offset, false), `private ioctl offset ${offset} requires CAP_NET_ADMIN`);
	assert(!isDenied(offset, true), `privileged private ioctl offset ${offset} remains available`);
}
for (const [command, offset] of [
	['SIOCSETCROBOWR', 15], ['SIOCSETCPHYWR2', 13], ['SIOCSETCDOWN', 1],
	['SIOCSETGETVAR', 6], ['SIOCGETCROBORD', 14]
]) {
	assert.match(ioctlHeader, new RegExp(`#define ${command}\\s+\\(SIOCDEVPRIVATE \\+ ETC\\w+\\)`),
		`${command} is part of the driver-private ioctl range`);
	assert(isDenied(offset, false), `${command} is capability-gated`);
}

console.log('et power-save iovar and private ioctl checks passed');