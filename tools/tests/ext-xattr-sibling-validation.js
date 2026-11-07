const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const base = path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/fs');
const sources = Object.fromEntries(['ext2', 'ext3', 'ext4'].map((fsName) => [
    fsName,
    fs.readFileSync(path.join(base, fsName, 'xattr.c'), 'utf8')
]));

function functionBody(source, signature, nextSignature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing ${signature}`);
    const end = source.indexOf(nextSignature, start + signature.length);
    assert(end > start, `missing end marker for ${signature}`);
    return source.slice(start, end);
}

const ext4Validator = functionBody(sources.ext4,
    'static int ext4_xattr_free_space(', '\nstruct ext4_xattr_info');
assert.match(ext4Validator, /if \(last->e_value_block\)\s*return -EIO;/);
assert.match(ext4Validator,
    /offs < table_size \|\| offs > area_size \|\|\s*value_size > area_size - offs \|\|\s*EXT4_XATTR_SIZE\(value_size\) > area_size - offs/);

const ext4Set = functionBody(sources.ext4,
    'ext4_xattr_set_entry(struct ext4_xattr_info *i, struct ext4_xattr_search *s)',
    '\nstruct ext4_xattr_block_find');
const validate = ext4Set.indexOf('ext4_xattr_free_space(');
const scan = ext4Set.indexOf('/* Compute min_offs and last. */');
const tableGuard = ext4Set.indexOf('if (min_offs < (char *)last - (char *)s->base + sizeof(__u32))');
const firstMutation = ext4Set.indexOf('memmove(');
assert(validate >= 0 && validate < scan,
    'ext4 must validate every xattr value before deriving min_offs');
assert(tableGuard > scan && tableGuard < firstMutation,
    'ext4 must reject min_offs below the entry table before mutation');
assert.match(ext4Set.slice(tableGuard, firstMutation), /return -EIO;/);

const ext2Set = sources.ext2.slice(sources.ext2.indexOf('ext2_xattr_set(struct inode'));
const ext2Validate = ext2Set.indexOf(
    'ext2_xattr_check_entries(FIRST_ENTRY(bh), header, end)');
const ext2Mutation = ext2Set.indexOf('memmove(');
assert(ext2Validate >= 0 && ext2Validate < ext2Mutation,
    'ext2 set path must validate all sibling entries before mutation');

const ext3Set = functionBody(sources.ext3,
    'ext3_xattr_set_entry(struct ext3_xattr_info *i, struct ext3_xattr_search *s)',
    '\nstruct ext3_xattr_block_find');
const ext3Validate = ext3Set.indexOf('ext3_xattr_check_entries(');
const ext3Mutation = ext3Set.indexOf('memmove(');
assert(ext3Validate >= 0 && ext3Validate < ext3Mutation,
    'ext3 set path must validate all sibling entries before mutation');

function validateValue({ tableEnd, areaSize, offset, valueSize }) {
    const paddedSize = (valueSize + 3) & ~3;
    if (offset < tableEnd || offset > areaSize ||
        valueSize > areaSize - offset || paddedSize > areaSize - offset)
        return -5;
    return 0;
}

assert.equal(validateValue({
    tableEnd: 80,
    areaSize: 128,
    offset: 0,
    valueSize: 1
}), -5, 'a zero sibling offset must be rejected');
assert.equal(validateValue({
    tableEnd: 80,
    areaSize: 128,
    offset: 124,
    valueSize: 8
}), -5, 'a sibling value extending past the area must be rejected');
assert.equal(validateValue({
    tableEnd: 80,
    areaSize: 128,
    offset: 120,
    valueSize: 4
}), 0, 'a fully in-bounds sibling value remains valid');

console.log('ext-xattr-sibling-validation: ok');