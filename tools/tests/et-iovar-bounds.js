const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const linux = read('release/src-rt-6.x.4708/et/sys/et_linux.c');
const etc = read('release/src-rt-6.x.4708/et/sys/etc.c');
const header = read('release/src-rt-6.x.4708/et/sys/etc.h');
const body = (source, start, end) => {
    const offset = source.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = source.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return source.slice(offset, limit);
};

const ioctl = body(linux, 'et_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)',
    'static struct net_device_stats *');
const iovar = body(etc, 'etc_iovar_valid_len(', '/* common iovar handler. return 0=ok, -1=error */');
const portDump = etc.match(/case IOV_PORTSTATS:[\s\S]*?bcm_binit\(&b, \(char\*\)arg, ([^)]+)\);/);
const arlDump = etc.match(/case IOV_SW_MCTBL:[\s\S]*?bcm_binit\(&b, \(char\*\)arg, ([^)]+)\);/);

assert.match(ioctl, /cmd >= SIOCDEVPRIVATE && cmd <= SIOCDEVPRIVATE \+ ETCROBOWR &&\s*!capable\(CAP_NET_ADMIN\)\)\s*return \(-EPERM\);/,
    'the et private ioctl range requires CAP_NET_ADMIN');
assert.match(ioctl, /!var->buf \|\| var->len < sizeof\(uint\) \|\| var->len > IOCBUFSZ/,
    'reject null, undersized, and oversized buffers before allocation');
assert.ok(ioctl.indexOf('etc_iovar_valid_len(var->cmd, var->set, buffer, var->len)') <
    ioctl.indexOf('error = etc_iovar('), 'selected-iovar length validation precedes dispatch');
assert.equal(portDump && portDump[1], 'len', 'port status output uses the actual allocation size');
assert.equal(arlDump && arlDump[1], 'len', 'ARL output uses the actual allocation size');
assert.match(header, /extern int etc_iovar_valid_len\(uint cmd, uint set, void \*arg, uint len\);/);
assert.match(iovar, /len >= sizeof\(uint\) \* 2/,
    'the PHY power-save iovar requires its second word');
assert.match(iovar, /len >= sizeof\(uint\) \* MAX_NO_PHYS/,
    'the all-PHY response requires space for every result word');

const IOCBUFSZ = 16384;
const MAX_NO_PHYS = 5;
function validLength(cmd, set, selector, len, hasBuffer = true) {
    if (!hasBuffer || len < 4 || len > IOCBUFSZ)
        return false;
    if (cmd === 1 && !set && selector === MAX_NO_PHYS)
        return len >= 4 * MAX_NO_PHYS;
    if (cmd === 1)
        return len >= 8;
    return true;
}

for (const command of [13, 14]) {
    assert.equal(validLength(command, 0, 0, 4), true,
        `four-byte command ${command} remains valid and its output is bounded`);
    for (const [len, hasBuffer] of [[0, true], [1, true], [4, false], [IOCBUFSZ + 1, true]])
        assert.equal(validLength(command, 0, 0, len, hasBuffer), false,
            `command ${command} rejects buffer length ${len}, null=${!hasBuffer}`);
}
assert.equal(validLength(1, 0, 0, 4), false, 'single-PHY query needs two words');
assert.equal(validLength(1, 0, MAX_NO_PHYS, 8), false, 'all-PHY query needs five result words');
assert.equal(validLength(1, 0, MAX_NO_PHYS, 20), true, 'all-PHY query accepts its full response');
assert.equal(validLength(1, 1, 0, 8), true, 'PHY setter accepts its two-word request');
console.log('PASS: et SIOCSETGETVAR source contracts and bounded-length models (not kernel execution)');