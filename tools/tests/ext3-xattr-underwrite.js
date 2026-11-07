#!/usr/bin/env node
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const xattr = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext3/xattr.c'), 'utf8');
const inode = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext3/inode.c'), 'utf8');

const checkNamesStart = xattr.indexOf('ext3_xattr_check_names(');
const checkNamesEnd = xattr.indexOf('\nstatic inline int\next3_xattr_check_block', checkNamesStart);
const checkNames = xattr.slice(checkNamesStart, checkNamesEnd);
const checkEntriesStart = xattr.indexOf('ext3_xattr_check_entries(');
const checkEntriesEnd = xattr.indexOf('\nstatic int\next3_xattr_find_entry', checkEntriesStart);
const checkEntries = xattr.slice(checkEntriesStart, checkEntriesEnd);
const setEntryStart = xattr.indexOf('ext3_xattr_set_entry(');
const setEntryEnd = xattr.indexOf('\nstruct ext3_xattr_block_find', setEntryStart);
const setEntry = xattr.slice(setEntryStart, setEntryEnd);
const ibodySetStart = xattr.indexOf('ext3_xattr_ibody_set(');
const ibodySetEnd = xattr.indexOf('\n/*\n * ext3_xattr_set_handle', ibodySetStart);
const ibodySet = xattr.slice(ibodySetStart, ibodySetEnd);

assert.ok(checkNamesEnd > checkNamesStart, 'bounded name walker must exist');
assert.ok(checkEntriesEnd > checkEntriesStart, 'sibling validator must exist');
assert.ok(setEntryEnd > setEntryStart, 'bounded setter must exist');
assert.match(checkNames, /\(char \*\)end - \(char \*\)entry < sizeof\(__u32\)/,
    'entry and terminator reads must stay within the xattr area');
assert.match(checkEntries, /ext3_xattr_check_entry\(entry, size\)/,
    'validate every sibling entry');
assert.match(checkEntries, /e_value_offs\) < table_end/,
    'nonempty values must start after the complete entry table');
assert.match(xattr, /EXT3_XATTR_SIZE\(value_size\) > size - value_offs/,
    'validate padded value extents using subtraction-safe bounds');
assert.match(xattr, /ext3_xattr_check_entries\(BFIRST\(bh\), BHDR\(bh\),/,
    'block xattrs use the block-header offset base');
assert.match(xattr, /ext3_xattr_check_entries\(IFIRST\(header\), IFIRST\(header\),/,
    'in-inode xattrs use the first-entry offset base');
assert.match(setEntry, /\(char \*\)last <= \(char \*\)s->end - sizeof\(__u32\)/,
    'the setter walk must stop at the bounded end marker');
assert.match(setEntry, /min_offs < table_end/,
    'reject wrapped free-space calculations before mutation');
assert.match(ibodySet, /memset\(s->first, 0, sizeof\(__u32\)\)/,
    'a missing in-inode magic starts from an empty entry table');
assert.match(inode, /ei->i_extra_isize \+\s*sizeof\(__le32\) > EXT3_INODE_SIZE/,
    'the inode magic read must fit inside the inode');

function validate(areaSize, tableEnd, entries) {
    for (const entry of entries) {
        if (entry.valueBlock !== 0 || entry.offset > areaSize
            || entry.valueSize > areaSize)
            return false;
        if (entry.valueSize) {
            const paddedSize = (entry.valueSize + 3) & ~3;
            if (entry.offset < tableEnd
                || paddedSize > areaSize - entry.offset)
                return false;
        }
    }
    return true;
}

for (const format of ['in-inode', 'block']) {
    assert.equal(validate(128, 40, [
        { offset: 0, valueSize: 4, valueBlock: 0 }
    ]), false, `${format}: reject a sibling value overlapping the table`);
    assert.equal(validate(128, 40, [
        { offset: 124, valueSize: 8, valueBlock: 0 }
    ]), false, `${format}: reject a padded value extending past the area`);
    assert.equal(validate(128, 40, [
        { offset: 40, valueSize: 8, valueBlock: 0 }
    ]), true, `${format}: retain valid sibling values`);
    assert.equal(validate(128, 40, [
        { offset: 0, valueSize: 0, valueBlock: 0 }
    ]), true, `${format}: retain empty values with the canonical zero offset`);
    assert.equal(validate(128, 40, [
        { offset: 40, valueSize: 8, valueBlock: 1 }
    ]), false, `${format}: reject external value blocks`);
}

console.log('PASS: ext3 xattr sibling bounds (source contracts/model; not kernel execution)');