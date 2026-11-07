const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const sourcePath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/ipset/ip_set_bitmap_ip.c';
const source = fs.readFileSync(path.join(root, sourcePath), 'utf8');
const start = source.indexOf('\nbitmap_ip_uadt(');
const end = source.indexOf('\nstatic bool\nbitmap_ip_same_set', start);
assert.ok(start >= 0 && end > start, 'find bitmap_ip_uadt');
const handler = source.slice(start, end);
const masking = handler.indexOf('ip_set_mask_from_to(ip, ip_to, cidr);');
const guard = handler.indexOf('if (ip < map->first_ip || ip_to > map->last_ip)');
const loop = handler.indexOf('for (; !before(ip_to, ip); ip += map->hosts)');
const callback = handler.indexOf('ret = adtfn(set, &e, &ext, &ext, flags);');

assert.ok(masking >= 0, 'CIDR masking remains present');
assert.ok(guard > masking && guard < loop,
    'validate the final interval after CIDR masking and before iterating elements');
assert.ok(callback > loop, 'ADT callbacks remain inside the validated interval loop');

const first = 0x0a000001;
const last = 0x0a0000fe;
function addResult(address, cidr) {
    const mask = (0xffffffff << (32 - cidr)) >>> 0;
    const from = (address & mask) >>> 0;
    const to = (from | (~mask >>> 0)) >>> 0;
    if (from < first || to > last)
        return { error: 'range' };
    return { ids: Array.from({ length: to - from + 1 }, (_, offset) => from + offset - first) };
}

assert.deepEqual(addResult(first, 31), { error: 'range' },
    'reject a /31 whose masked start is below the set');
assert.deepEqual(addResult(first, 24), { error: 'range' },
    'reject a /24 whose masked interval exceeds the set');
assert.deepEqual(addResult(first, 32), { ids: [0] },
    'accept the first in-range address');
assert.deepEqual(addResult(last, 32), { ids: [last - first] },
    'accept the last in-range address');

console.log('PASS: ipset bitmap:ip CIDR range guard (source contract/model; not kernel execution)');
