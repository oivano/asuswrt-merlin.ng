const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const squashfs = path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/squashfs');
const namei = fs.readFileSync(path.join(squashfs, 'namei.c'), 'utf8');
const cache = fs.readFileSync(path.join(squashfs, 'cache.c'), 'utf8');

const indexReader = namei.slice(namei.indexOf('static int get_dir_index_using_name('),
    namei.indexOf('\nstatic struct dentry *squashfs_lookup'));
const nameBound = indexReader.match(
    /size = le32_to_cpu\(index->size\);\s*if \(size >= SQUASHFS_NAME_LEN\)\s*break;\s*size\+\+;/
);
assert.ok(nameBound, 'bound the raw index name size before incrementing it');
assert.ok(indexReader.indexOf(nameBound[0]) < indexReader.indexOf(
    'squashfs_read_metadata(sb, index->name'),
    'stop on an oversized index record before reading its name');

function indexNameLength(rawSize) {
    const size = rawSize >>> 0;
    if (size >= 256)
        return null;
    return size + 1;
}

assert.equal(indexNameLength(0), 1, 'accept an empty on-disk size');
assert.equal(indexNameLength(255), 256, 'accept the maximum valid name payload');
for (const rawSize of [256, 0x400, 0x7fffffff, 0xffffffff])
    assert.equal(indexNameLength(rawSize), null, `reject index size 0x${rawSize.toString(16)}`);

const metadataReader = cache.slice(cache.indexOf('int squashfs_read_metadata('),
    cache.indexOf('\n\n/*', cache.indexOf('int squashfs_read_metadata(')));
const negativeLengthGuard = metadataReader.match(/if \(length < 0\)\s*return -EIO;/);
assert.ok(negativeLengthGuard, 'reject negative metadata lengths with -EIO');
assert.ok(metadataReader.indexOf(negativeLengthGuard[0]) < metadataReader.indexOf('squashfs_cache_get'),
    'reject negative lengths before accessing the metadata cache');

console.log('PASS: Squashfs directory-index and metadata length bounds (source contract/model; not kernel execution)');
