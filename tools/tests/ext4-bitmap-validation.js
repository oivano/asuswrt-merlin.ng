const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = 'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext4/';
const header = fs.readFileSync(path.join(root, kernel, 'ext4.h'), 'utf8');
const balloc = fs.readFileSync(path.join(root, kernel, 'balloc.c'), 'utf8');
const ialloc = fs.readFileSync(path.join(root, kernel, 'ialloc.c'), 'utf8');
const superSource = fs.readFileSync(path.join(root, kernel, 'super.c'), 'utf8');
const body = (source, start, end) => {
    const offset = source.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = source.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return source.slice(offset, limit);
};

const locationCheck = body(header, 'static inline int ext4_valid_bitmap_block(',
    'static inline ext4_fsblk_t ext4_r_blocks_count(');
assert.match(locationCheck, /block < first_data_block/,
    'reject bitmap blocks before the filesystem data area');
assert.match(locationCheck, /block >= ext4_blocks_count\(/,
    'reject bitmap blocks beyond the filesystem');
assert.match(locationCheck, /block - group_first_block >= EXT4_BLOCKS_PER_GROUP/,
    'keep non-flex bitmap blocks in their descriptor group');

const blockRead = body(balloc, 'ext4_read_block_bitmap(', 'ext4_add_groupblocks(');
const blockLocationGuard = blockRead.indexOf('ext4_valid_bitmap_block(');
assert.ok(blockLocationGuard >= 0 && blockLocationGuard < blockRead.indexOf('sb_getblk('),
    'validate the block bitmap location before reading it');
const inodeRead = body(ialloc, 'ext4_read_inode_bitmap(', '/*\n * NOTE! When we get the inode');
const inodeLocationGuard = inodeRead.indexOf('ext4_valid_bitmap_block(');
assert.ok(inodeLocationGuard >= 0 && inodeLocationGuard < inodeRead.indexOf('sb_getblk('),
    'validate the inode bitmap location before reading it');

const validBitmap = body(balloc, 'static int ext4_valid_block_bitmap(',
    '/**\n * ext4_read_block_bitmap');
assert.equal((validBitmap.match(/bitmap_blk - group_first_block >= bitmap_bits/g) || []).length, 3,
    'bound block bitmap, inode bitmap, and inode table bit offsets');
assert.match(validBitmap, /s_itb_per_group > bitmap_bits - offset/,
    'bound the complete inode-table bit range to the bitmap buffer');
assert.match(validBitmap, /s_itb_per_group >\s*EXT4_BLOCKS_PER_GROUP\(sb\) - offset/,
    'bound the inode-table range to its group');
const firstBitRead = validBitmap.indexOf('ext4_test_bit(offset, bh->b_data)');
const secondBitRead = validBitmap.indexOf('ext4_test_bit(offset, bh->b_data)', firstBitRead + 1);
const tableBitRead = validBitmap.indexOf('ext4_find_next_zero_bit(bh->b_data');
assert.ok(validBitmap.indexOf('bitmap_blk - group_first_block >= bitmap_bits') < firstBitRead &&
    validBitmap.indexOf('bitmap_blk - group_first_block >= bitmap_bits', firstBitRead + 1) < secondBitRead,
    'validate wide bitmap offsets before bit tests');
assert.ok(validBitmap.indexOf('s_itb_per_group > bitmap_bits - offset') < tableBitRead,
    'validate inode-table capacity before scanning its bit range');

const mount = body(superSource, 'static int ext4_fill_super(', 'static journal_t *ext4_get_journal(');
const descriptorCheck = body(superSource, 'static int ext4_check_descriptors(',
    'static ext4_fsblk_t descriptor_loc(');
assert.match(descriptorCheck, /if \(!flexbg_flag && ext4_bg_has_super\(sb, i\)\)/,
    'check reserved metadata for non-flex groups without rejecting flex_bg layouts');
assert.match(descriptorCheck, /metadata for group %u overlaps superblock\/GDT/,
    'reject descriptor metadata that overlaps the superblock or GDT');
assert.match(mount, /sbi->s_gdb_count = db_count;\s*if \(!ext4_check_descriptors\(sb\)\)/,
    'initialize the GDT block count before descriptor validation');
const recovery = mount.indexOf('ext4_load_journal(sb, es, journal_devnum)');
const postRecoveryCheck = mount.indexOf('if (!ext4_check_descriptors(sb))', recovery);
assert.ok(recovery >= 0 && postRecoveryCheck > recovery &&
    postRecoveryCheck < mount.indexOf('no_journal:', recovery),
    'revalidate group descriptors after journal replay and before filesystem use');

const bitmapOffsetValid = (offset, span, groupBlocks, bitmapBits) =>
    offset >= 0 && offset < groupBlocks && offset < bitmapBits &&
    span <= groupBlocks - offset && span <= bitmapBits - offset;
const overlaps = (start, length, zoneStart, zoneLength) =>
    start < zoneStart + zoneLength && zoneStart < start + length;
assert.equal(bitmapOffsetValid(17, 1, 8192, 8192), true,
    'accept a valid metadata bit offset');
assert.equal(bitmapOffsetValid(2 ** 31, 1, 8192, 8192), false,
    'reject the reported far-away bitmap offset');
assert.equal(bitmapOffsetValid(8191, 2, 8192, 8192), false,
    'reject an inode table range extending past the bitmap');
assert.equal(bitmapOffsetValid(8191, 1, 8192, 8192), true,
    'allow a final in-range metadata bit');
assert.equal(overlaps(4, 1, 2, 3), true,
    'reject metadata inside the reserved superblock/GDT range');
assert.equal(overlaps(5, 2, 2, 3), false,
    'allow metadata immediately after the reserved superblock/GDT range');

console.log('PASS: ext4 bitmap bounds and journal-replay validation contracts (not kernel execution)');