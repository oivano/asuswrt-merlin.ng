const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const ext4 = 'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext4';
const namei = fs.readFileSync(path.join(root, ext4, 'namei.c'), 'utf8');
const dir = fs.readFileSync(path.join(root, ext4, 'dir.c'), 'utf8');

const body = (source, name, next) => {
    const start = source.lastIndexOf(name);
    assert.ok(start >= 0, `${name} exists`);
    const end = source.indexOf(next, start);
    assert.ok(end > start, `${name} has a bounded function body`);
    return source.slice(start, end);
};

const mapBuilder = body(namei,
    'static int dx_make_map(struct inode *dir, struct buffer_head *bh,',
    '/* Sort map by hash value */');
assert.ok(mapBuilder.indexOf('!ext4_check_dir_entry') < mapBuilder.indexOf('de->name_len'),
    'validate each entry before hashing or mapping it');
assert.match(mapBuilder, /return -EIO;/, 'map builder fails closed on malformed entries');

const checker = body(namei, 'static int dx_check_dirents(', '/* Sort map by hash value */');
assert.match(checker, /if \(\(char \*\) de != top\)/,
    'preflight rejects walks that do not end at the block boundary');

const splitter = body(namei, 'static struct ext4_dir_entry_2 *do_split(', '/*\n * Add a new entry');
assert.ok(splitter.indexOf('dx_check_dirents') < splitter.indexOf('ext4_append'),
    'preflight source entries before allocating the destination block');
assert.match(splitter, /if \(!split \|\| split >= count\)/,
    'reject split indices that would access outside the map');

const indexer = body(namei, 'static int make_indexed_dir(', 'static int ext4_add_entry(');
assert.ok(indexer.indexOf('dx_check_dirents') < indexer.indexOf('ext4_append'),
    'validate the unindexed source before appending or copying');
assert.match(indexer, /root->dot_name\[0\] != '\.'/,
    'validate the dot dirent before deriving the source range');
assert.match(indexer, /memcmp\(root->dotdot_name, "\.\.", 2\)/,
    'validate the dotdot dirent before deriving the source range');

assert.match(dir, /directory entry too close to block end/,
    'shared dirent validator rejects entries too close to block end');

const isInvalid = (offset, recordLength, blockSize) => {
    const end = offset + recordLength;
    return recordLength < 12 || recordLength % 4 !== 0 || end > blockSize ||
        (end > blockSize - 12 && end !== blockSize);
};
assert.equal(isInvalid(0, 0, 1024), true, 'reject zero rec_len');
assert.equal(isInvalid(0, 4, 1024), true, 'reject 4-byte pseudo-entry');
assert.equal(isInvalid(1008, 8, 1024), true, 'reject entries ending within the final 12 bytes');
assert.equal(isInvalid(0, 1024, 1024), false, 'accept a valid entry ending at the block boundary');

console.log('PASS: ext4 dirent validation and split bounds (source contract/model; not kernel execution)');