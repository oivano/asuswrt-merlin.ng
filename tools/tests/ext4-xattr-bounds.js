const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = 'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext4/';
const xattr = fs.readFileSync(path.join(root, kernel, 'xattr.c'), 'utf8');
const inode = fs.readFileSync(path.join(root, kernel, 'inode.c'), 'utf8');
const body = (source, start, end) => {
    const offset = source.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = source.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return source.slice(offset, limit);
};

const checkNames = body(xattr, 'ext4_xattr_check_names(', 'static inline int\next4_xattr_check_block(');
assert.match(checkNames, /endp - entryp < sizeof\(__u32\)/,
    'require room for the sentinel before reading it');
assert.match(checkNames, /entry_size > remaining - sizeof\(__u32\)/,
    'keep a complete sentinel after each entry');

const freeSpace = body(xattr, 'static int ext4_xattr_free_space(', 'struct ext4_xattr_info {');
assert.match(freeSpace, /entry_size > remaining - sizeof\(__u32\)/,
    'bound the in-inode entry walk and sentinel');
assert.match(freeSpace, /if \(min_offs < \(size_t\)\(table_end - basep\)\)\s*return -EIO;/,
    'reject overlapping value and entry areas before subtraction');
const valueGuard = freeSpace.match(/if \((offs < table_size \|\| offs > area_size \|\|[\s\S]*?)\)\s*return -EIO;/);
assert.ok(valueGuard, 'validate value offsets and sizes against the attribute area');
const rejectsValue = new Function('offs', 'table_size', 'area_size', 'value_size',
    'EXT4_XATTR_SIZE', `return Boolean(${valueGuard[1]});`);
const paddedSize = size => (size + 3) & ~3;
const tableSize = 24; // One 20-byte entry plus the four-byte sentinel.
assert.equal(rejectsValue(0, tableSize, 1912, 4, paddedSize), true,
    'reject the report offset 0 with a nonempty value');
assert.equal(rejectsValue(20, tableSize, 1912, 4, paddedSize), true,
    'reject a value overlapping the entry table');
assert.equal(rejectsValue(1910, tableSize, 1912, 4, paddedSize), true,
    'reject a value whose padded extent exceeds the inode');
assert.equal(rejectsValue(1904, tableSize, 1912, 8, paddedSize), false,
    'accept an aligned value fully inside the attribute area');
const checkedFreeSpace = (minimumOffset, tableEnd) =>
    minimumOffset < tableEnd ? null : minimumOffset - tableEnd;
assert.equal(checkedFreeSpace(0, tableSize), null,
    'reject malformed offsets instead of wrapping free-space arithmetic');
assert.equal(checkedFreeSpace(1912, tableSize), 1888,
    'compute valid free space without unsigned underflow');

const shift = body(xattr, 'static int ext4_xattr_shift_entries(', '/*\n * Expand an inode by new_extra_isize');
assert.match(shift, /endp - \(top \+ n\) < sizeof\(__u32\)/,
    'bound the shifted sentinel as well as the copied bytes');
assert.ok(shift.indexOf('memmove(to, from, n)') < shift.indexOf('memset(top + n, 0, sizeof(__u32))'),
    'write a fresh sentinel only after the bounded move');
const shiftFits = (from, to, length, end) =>
    from <= end && length <= end - from && end - (from + length) >= 4 &&
    to <= end && length <= end - to && end - (to + length) >= 4;
assert.equal(shiftFits(132, 2048, 1912, 2048), false,
    'reject the reported shift past a 2048-byte inode');
assert.equal(shiftFits(160, 192, 28, 2048), true,
    'allow a bounded in-inode shift');

assert.match(xattr, /new_extra_isize < 0 \|\| \(new_extra_isize & 3\)/,
    'require aligned, nonnegative requested extra-isize');
assert.match(xattr, /\(s_min_extra_isize & 3\)/,
    'validate the on-disk minimum before retrying with it');
assert.match(inode, /\(ei->i_extra_isize & 3\)/,
    'reject unaligned on-disk i_extra_isize');
assert.match(inode, /EXT4_GOOD_OLD_INODE_SIZE \+ ei->i_extra_isize \+\s*sizeof\(__le32\) <= EXT4_INODE_SIZE/,
    'bound the in-inode xattr magic read');

console.log('PASS: ext4 xattr bounds source contracts/models (not kernel execution)');