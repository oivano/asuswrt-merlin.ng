const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/partitions/mac.c'), 'utf8');
const header = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/partitions/mac.h'), 'utf8');
const entrySize = 136;

assert.match(header, /struct mac_partition\s*\{/);
assert.match(source,
    /mac_partition_entry_fits\(unsigned int offset\)[\s\S]*?return offset <= 512 - sizeof\(struct mac_partition\);/);
assert.match(source,
    /if \(!mac_partition_entry_fits\(secsize % 512\)\)\s*return 0;[\s\S]*?part = \(struct mac_partition \*\) \(data \+ secsize%512\);/);
assert.match(source,
    /for \(blk = 1; blk <= blocks_in_map; \+\+blk\) \{\s*int pos = blk \* secsize;\s*if \(!mac_partition_entry_fits\(pos % 512\)\)\s*\{\s*put_dev_sector\(sect\);\s*return 0;/);
assert.match(source,
    /data = read_part_sector\(state, pos\/512, &sect\);\s*if \(!data\)\s*return -1;\s*if \(!mac_partition_entry_fits\(pos % 512\)\)\s*\{\s*put_dev_sector\(sect\);\s*return 0;\s*\}\s*part = \(struct mac_partition \*\) \(data \+ pos%512\);/);

function entryFits(offset) {
    return offset <= 512 - entrySize;
}

function mapOffsets(blockSize, count) {
    return Array.from({ length: count }, (_, index) =>
        ((index + 1) * blockSize) % 512);
}

for (const blockSize of [1023, 2044, 4088, 4095]) {
    assert.equal(entryFits(blockSize % 512), false,
        `reject initial map entry for block_size ${blockSize}`);
    for (const offset of mapOffsets(blockSize, 8))
        assert.equal(entryFits(offset), false,
            `reject map entry offset ${offset} for block_size ${blockSize}`);
}

for (const blockSize of [512, 2048]) {
    assert.equal(entryFits(blockSize % 512), true,
        `accept initial map entry for block_size ${blockSize}`);
    for (const offset of mapOffsets(blockSize, 8))
        assert.equal(entryFits(offset), true,
            `accept map entry offset ${offset} for block_size ${blockSize}`);
}

assert.equal(entryFits(mapOffsets(640, 1)[0]), true,
    'accept an initially valid map entry');
assert.equal(entryFits(mapOffsets(640, 3)[2]), false,
    'reject a later map entry that crosses the sector boundary');

console.log('PASS: Mac partition entry sector bounds (source contract/model; not compiled-kernel execution)');