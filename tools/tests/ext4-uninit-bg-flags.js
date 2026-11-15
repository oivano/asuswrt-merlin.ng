const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const ext4 = path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext4');
const balloc = fs.readFileSync(path.join(ext4, 'balloc.c'), 'utf8');
const ialloc = fs.readFileSync(path.join(ext4, 'ialloc.c'), 'utf8');
const mballoc = fs.readFileSync(path.join(ext4, 'mballoc.c'), 'utf8');

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing function ${signature}`);
    const end = source.indexOf('\n}\n', start);
    assert(end >= 0, `unterminated function ${signature}`);
    return source.slice(start, end + 3);
}

function assertFeatureGated(body, flags, message) {
    assert.match(body, new RegExp(
        `EXT4_HAS_RO_COMPAT_FEATURE\\(sb,\\s*EXT4_FEATURE_RO_COMPAT_GDT_CSUM\\)\\s*&&\\s*\\(${flags}\\)`),
        message);
}

const blockRead = functionBody(balloc, 'ext4_read_block_bitmap(struct super_block');
assertFeatureGated(blockRead,
    'desc->bg_flags & cpu_to_le16\\(EXT4_BG_BLOCK_UNINIT\\)',
    'block bitmap uninit flag must require GDT_CSUM');
assert.match(blockRead,
    /if \(block_group == 0\) \{[\s\S]*?unlock_buffer\(bh\);[\s\S]*?ext4_error\(sb, "Block bitmap for bg 0 marked "\s*"uninitialized"\);[\s\S]*?return NULL;/,
    'group 0 block bitmap must fail closed');
assert.match(blockRead, /if \(block_group == 0\)[\s\S]*?put_bh\(bh\);/,
    'failed block bitmap read must release its buffer');

const inodeRead = functionBody(ialloc, 'ext4_read_inode_bitmap(struct super_block');
assertFeatureGated(inodeRead,
    'desc->bg_flags & cpu_to_le16\\(EXT4_BG_INODE_UNINIT\\)',
    'inode bitmap uninit flag must require GDT_CSUM');
assert.match(inodeRead,
    /if \(block_group == 0\) \{[\s\S]*?unlock_buffer\(bh\);[\s\S]*?ext4_error\(sb, "Inode bitmap for bg 0 marked "\s*"uninitialized"\);[\s\S]*?return NULL;/,
    'group 0 inode bitmap must fail closed');
assert.match(inodeRead, /if \(block_group == 0\)[\s\S]*?put_bh\(bh\);/,
    'failed inode bitmap read must release its buffer');

const buddyRead = functionBody(mballoc, 'static int ext4_mb_init_cache(');
assertFeatureGated(buddyRead,
    'desc->bg_flags & cpu_to_le16\\(EXT4_BG_BLOCK_UNINIT\\)',
    'buddy cache uninit flag must require GDT_CSUM');
assert.match(buddyRead,
    /if \(first_group \+ i == 0\) \{[\s\S]*?unlock_buffer\(bh\[i\]\);[\s\S]*?ext4_error\(sb, "Block bitmap for bg 0 marked "\s*"uninitialized"\);[\s\S]*?err = -EIO;[\s\S]*?goto out;/,
    'group 0 buddy bitmap must fail and release its locks');

const groupInfo = functionBody(mballoc, 'int ext4_mb_add_groupinfo(');
assertFeatureGated(groupInfo,
    'desc->bg_flags & cpu_to_le16\\(EXT4_BG_BLOCK_UNINIT\\)',
    'group-info free count must require GDT_CSUM');

const markUsed = functionBody(mballoc, 'ext4_mb_mark_diskspace_used(');
assertFeatureGated(markUsed,
    'gdp->bg_flags & cpu_to_le16\\(EXT4_BG_BLOCK_UNINIT\\)',
    'disk allocation must only clear a valid uninit flag');

const claimInode = functionBody(ialloc, 'static int ext4_claim_inode(');
assert.match(claimInode,
    /EXT4_HAS_RO_COMPAT_FEATURE\(sb, EXT4_FEATURE_RO_COMPAT_GDT_CSUM\)[\s\S]*?gdp->bg_flags & cpu_to_le16\(EXT4_BG_INODE_UNINIT\)/,
    'inode claim must only use the flag when GDT_CSUM is enabled');

const newInode = functionBody(ialloc, 'struct inode *ext4_new_inode(');
assert.match(newInode,
    /if \(EXT4_HAS_RO_COMPAT_FEATURE\(sb, EXT4_FEATURE_RO_COMPAT_GDT_CSUM\) &&\s*gdp->bg_flags & cpu_to_le16\(EXT4_BG_BLOCK_UNINIT\)\)/,
    'new inode allocation must only use the block flag when GDT_CSUM is enabled');

console.log('ext4 uninitialized-group flag checks passed');