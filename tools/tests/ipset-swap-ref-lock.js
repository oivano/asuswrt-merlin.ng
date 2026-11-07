const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const sourcePath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/ipset/ip_set_core.c';
const source = fs.readFileSync(path.join(root, sourcePath), 'utf8');
const marker = 'IPSET_CBFN(ip_set_swap,';
const markerIndex = source.indexOf(marker);
assert.ok(markerIndex >= 0, 'ip_set_swap implementation exists');

const bodyStart = source.indexOf('{', markerIndex);
let depth = 0;
let bodyEnd = -1;
for (let index = bodyStart; index < source.length; index++) {
    if (source[index] === '{') depth++;
    else if (source[index] === '}' && --depth === 0) {
        bodyEnd = index + 1;
        break;
    }
}
assert.ok(bodyEnd > bodyStart, 'ip_set_swap body is complete');

const swap = source.slice(bodyStart, bodyEnd);
const lock = swap.indexOf('write_lock_bh(&ip_set_ref_lock)');
const check = swap.indexOf('if (from->ref_netlink || to->ref_netlink)');
const busyUnlock = swap.indexOf('write_unlock_bh(&ip_set_ref_lock)', check);
const names = swap.indexOf('strncpy(from_name');
const refs = swap.indexOf('swap(from->ref, to->ref)');
const pointers = swap.indexOf('ip_set(inst, from_id) = to');
const finalUnlock = swap.lastIndexOf('write_unlock_bh(&ip_set_ref_lock)');

assert.ok(lock >= 0 && lock < check,
    'test dump references only after acquiring ip_set_ref_lock');
assert.match(swap.slice(check),
    /if \(from->ref_netlink \|\| to->ref_netlink\) \{\s*write_unlock_bh\(&ip_set_ref_lock\);\s*return -EBUSY;/,
    'referenced sets reject SWAP and release the lock');
assert.ok(check < busyUnlock && busyUnlock < names,
    'name exchange happens only after the referenced-set check');
assert.ok(names < refs && refs < pointers && pointers < finalUnlock,
    'names, references, and index pointers change before releasing the lock');

console.log('PASS: ipset SWAP reference check and mutations share ip_set_ref_lock');
