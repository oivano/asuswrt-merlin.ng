const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/mm/swapfile.c'), 'utf8');
const header = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/include/linux/swap.h'), 'utf8');
assert.match(header, /#define MAX_SWAP_BADPAGES \\\n\s*\(\(__swapoffset\(magic\.magic\) - __swapoffset\(info\.badpages\)\) \/ sizeof\(int\)\)/);
const maxBadpages = Math.floor(((4096 - 10) - (1024 + 12 + 16 + 16 + 117 * 4)) / 4);
const endianPath = kernel.match(/\/\* swap partition endianess hack\.\.\. \*\/[\s\S]*?\/\* Check the swap header's sub-version \*\//)[0];
const countSwab = endianPath.indexOf('swab32s(&swap_header->info.nr_badpages)');
const boundCheck = endianPath.indexOf('swap_header->info.nr_badpages > MAX_SWAP_BADPAGES');
const badpageLoop = endianPath.indexOf('swab32s(&swap_header->info.badpages[i])');

assert.ok(countSwab >= 0);
assert.ok(boundCheck > countSwab, 'check the converted on-disk count');
assert.ok(badpageLoop > boundCheck, 'check the count before touching badpages');
assert.match(endianPath.slice(boundCheck, badpageLoop), /error = -EINVAL;[\s\S]*goto bad_swap;/);

function swap32(value) {
    return ((((value & 0xff) << 24) | ((value & 0xff00) << 8) |
        ((value >>> 8) & 0xff00) | ((value >>> 24) & 0xff)) >>> 0);
}

for (const count of [maxBadpages, maxBadpages + 1, 0xffffffff]) {
    const onDiskCount = swap32(count >>> 0);
    const converted = swap32(onDiskCount);
    assert.equal(converted > maxBadpages, count > maxBadpages);
}

console.log('PASS: swapped bad-page count is bounded before any badpages[] access');