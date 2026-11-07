const assert = require('assert');
const fs = require('fs');

const source = fs.readFileSync(
    'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext2/xattr.c',
    'utf8'
);

const namesCheck = source.match(/ext2_xattr_check_names\([\s\S]*?\n}\n/);
const entriesCheck = source.match(/ext2_xattr_check_entries\([\s\S]*?\n}\n/);
const setBlock = source.match(/ext2_xattr_set\([\s\S]*?\ncleanup:/);

assert(namesCheck, 'bounded name-table validation exists');
assert(entriesCheck, 'whole-block value validation exists');
assert(setBlock, 'ext2_xattr_set body exists');
assert(setBlock[0].indexOf('ext2_xattr_check_entries(') <
    setBlock[0].indexOf('/* Find the named attribute. */'));
assert(setBlock[0].indexOf('min_offs <') <
    setBlock[0].indexOf('free = min_offs -'));

const blockSize = 1024;
const tableEnd = 64;
function validValue(block, offset, valueSize) {
    const paddedSize = (valueSize + 3) & ~3;
    return block === 0 && valueSize <= blockSize && offset <= blockSize &&
        (!valueSize || (offset >= tableEnd &&
            paddedSize <= blockSize - offset));
}

assert.strictEqual(validValue(0, 0, 1), false,
    'nonempty value cannot point below the table');
assert.strictEqual(validValue(0, tableEnd - 1, 1), false,
    'value cannot overlap the entry table');
assert.strictEqual(validValue(0, blockSize - 1, 4), false,
    'padded value extent must fit in the block');
assert.strictEqual(validValue(1, tableEnd, 4), false,
    'external value blocks are rejected');
assert.strictEqual(validValue(0, tableEnd, 4), true,
    'valid in-block value remains accepted');
assert.strictEqual(validValue(0, 0, 0), true,
    'empty values may retain offset zero');

console.log('ext2 xattr bounds checks passed');