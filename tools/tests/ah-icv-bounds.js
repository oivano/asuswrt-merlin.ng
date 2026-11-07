const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const kernel = path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36');
const variants = [
    ['net/ipv4/ah4.c', 'static int ah_init_state(', 'static void ah_destroy('],
    ['net/ipv6/ah6.c', 'static int ah6_init_state(', 'static void ah6_destroy(']
];

function functionBody(source, start, end) {
    const first = source.indexOf(start);
    assert(first >= 0, `missing ${start}`);
    const last = source.indexOf(end, first + start.length);
    assert(last > first, `missing ${end}`);
    return source.slice(first, last);
}

for (const [file, start, end] of variants) {
    const source = fs.readFileSync(path.join(kernel, file), 'utf8');
    const init = functionBody(source, start, end);
    assert.doesNotMatch(init, /BUG_ON/);
    assert.match(init, /ahp->icv_trunc_len = x->aalg->alg_trunc_len\/8;/);
    assert.match(init,
        /if \(ahp->icv_trunc_len > MAX_AH_AUTH_LEN\)\s*goto error;/);
    assert.match(init,
        /error:\s*if \(ahp\) \{\s*crypto_free_ahash\(ahp->ahash\);\s*kfree\(ahp\);\s*\}\s*return -EINVAL;/);
}

const ahHeader = fs.readFileSync(path.join(kernel, 'include/net/ah.h'), 'utf8');
const maxIcvBytes = Number(ahHeader.match(/#define MAX_AH_AUTH_LEN\s+(\d+)/)?.[1]);
assert(Number.isInteger(maxIcvBytes));

function accepted(truncBits) {
    return Math.floor(truncBits / 8) <= maxIcvBytes;
}

assert.equal(accepted(96), true);
for (const truncBits of [128, 192, 256, 384, 512])
    assert.equal(accepted(truncBits), false, `${truncBits}-bit ICV must be rejected`);

console.log('ah-icv-bounds: ok');