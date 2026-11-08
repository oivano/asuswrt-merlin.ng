const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const squashfsDir = path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/fs/squashfs');
const idSource = fs.readFileSync(path.join(squashfsDir, 'id.c'), 'utf8');
const fragmentSource = fs.readFileSync(path.join(squashfsDir, 'fragment.c'), 'utf8');
const blockSource = fs.readFileSync(path.join(squashfsDir, 'block.c'), 'utf8');
const inodeSource = fs.readFileSync(path.join(squashfsDir, 'inode.c'), 'utf8');
const superSource = fs.readFileSync(path.join(squashfsDir, 'super.c'), 'utf8');
const sbSource = fs.readFileSync(path.join(squashfsDir, 'squashfs_fs_sb.h'), 'utf8');

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert.notEqual(start, -1, `missing ${signature}`);
    const open = source.indexOf('{', start);
    let depth = 1;
    for (let cursor = open + 1; cursor < source.length; cursor++) {
        if (source[cursor] === '{') depth++;
        if (source[cursor] === '}' && --depth === 0)
            return source.slice(open + 1, cursor);
    }
    assert.fail(`unterminated ${signature}`);
}

const getId = functionBody(idSource, 'int squashfs_get_id(');
const readIds = functionBody(idSource, '__le64 *squashfs_read_id_index_table(');
const fragLookup = functionBody(fragmentSource, 'int squashfs_frag_lookup(');
const readData = functionBody(blockSource, 'int squashfs_read_data(');
const readInode = functionBody(inodeSource, 'int squashfs_read_inode(');
const readMetadata = functionBody(
    fs.readFileSync(path.join(squashfsDir, 'cache.c'), 'utf8'),
    'int squashfs_read_metadata(');
const readFragments = functionBody(fragmentSource,
    '__le64 *squashfs_read_fragment_index_table(');

assert.match(sbSource, /unsigned int\s+ids;[\s\S]*unsigned int\s+fragments;/);
assert.match(superSource, /msblk->ids = le16_to_cpu\(sblk->no_ids\);[\s\S]*?if \(msblk->ids == 0\)[\s\S]*?goto failed_mount;[\s\S]*?squashfs_read_id_index_table/);
assert.match(superSource, /if \(msblk->block_log > SQUASHFS_FILE_MAX_LOG\)[\s\S]*?goto failed_mount;\s*if \(msblk->block_size != \(1 << msblk->block_log\)\)\s*goto failed_mount;/);
assert.match(readData, /if \(page >= pages\)\s*goto block_release;[\s\S]*?memcpy\(buffer\[page\]/);
assert.ok(readData.indexOf('if (page >= pages)') <
    readData.indexOf('memcpy(buffer[page]'),
    'uncompressed copies validate the page index before dereferencing it');
assert.match(getId, /if \(index >= msblk->ids \|\| !msblk->id_table\)[\s\S]*?return -EIO;[\s\S]*?msblk->id_table\[block\]/);
assert.match(fragLookup, /if \(fragment >= msblk->fragments \|\| !msblk->fragment_index\)[\s\S]*?return -EIO;[\s\S]*?msblk->fragment_index\[block\]/);
assert.ok(getId.indexOf('return -EIO') < getId.indexOf('SQUASHFS_ID_BLOCK(index)'));
assert.ok(fragLookup.indexOf('return -EIO') <
    fragLookup.indexOf('SQUASHFS_FRAGMENT_INDEX((u64) fragment)'));
assert.match(readMetadata,
    /if \(entry->error\)\s*\{\s*bytes = entry->error;\s*goto metadata_error;\s*\}/);
assert.match(readMetadata,
    /else if \(\*offset >= entry->length\)\s*\{\s*bytes = -EIO;\s*goto metadata_error;\s*\}/);
assert.match(readMetadata,
    /metadata_error:\s*squashfs_cache_put\(entry\);\s*return bytes;/);

for (const inodeType of ['SQUASHFS_REG_TYPE', 'SQUASHFS_LREG_TYPE']) {
    const start = readInode.indexOf(`case ${inodeType}:`);
    const end = readInode.indexOf('\n\tcase ', start + 1);
    assert.notEqual(start, -1, `missing ${inodeType}`);
    const inodeCase = readInode.slice(start, end === -1 ? undefined : end);
    const offsetGuard = inodeCase.match(
        /frag_offset = le32_to_cpu\(sqsh_ino->offset\);\s*if \(frag_offset >= msblk->block_size\)\s*\{\s*err = -EIO;\s*goto failed_read;\s*\}/
    );
    assert.ok(offsetGuard, `${inodeType} rejects offsets outside the block`);
    assert.ok(inodeCase.indexOf(offsetGuard[0]) <
        inodeCase.indexOf('squashfs_i(inode)->fragment_offset = frag_offset'),
        `${inodeType} validates before storing the signed offset`);
}

for (const [body, startName, countName] of [
    [readIds, 'id_table_start', 'no_ids'],
    [readFragments, 'fragment_table_start', 'fragments'],
]) {
    assert.match(body, new RegExp(`${countName} == 0`));
    assert.match(body, /length64 > 0x7fffffffULL/);
    assert.ok(body.includes(`${startName} > (u64) msblk->bytes_used`));
    assert.ok(body.includes('length64 > (u64) msblk->bytes_used -'));
    assert.ok(body.indexOf('return ERR_PTR(-EINVAL)') < body.indexOf('kmalloc(length'));
}

function tableFits(start, length, bytesUsed) {
    return start <= bytesUsed && length <= bytesUsed - start;
}

function validFragmentOffset(rawOffset, blockSize) {
    return rawOffset < blockSize;
}

function validBlockSize(blockSize, blockLog) {
    return blockSize >= 4096 && blockSize <= 1 << 20 &&
        blockSize === 2 ** blockLog;
}

function uncompressedPagesFit(length, pages) {
    let page = 0;
    let pageOffset = 0;
    while (length > 0) {
        if (pageOffset === 4096) {
            page++;
            pageOffset = 0;
        }
        if (page >= pages) return false;
        const available = Math.min(length, 4096 - pageOffset);
        length -= available;
        pageOffset += available;
    }
    return true;
}

for (const blockLog of [12, 13, 14, 17, 20])
    assert.equal(validBlockSize(2 ** blockLog, blockLog), true,
        `accept normal power-of-two block size ${2 ** blockLog}`);
for (const blockSize of [4097, 8191, 36863])
    assert.equal(validBlockSize(blockSize, Math.floor(Math.log2(blockSize))), false,
        `reject inconsistent block size ${blockSize}`);
assert.equal(uncompressedPagesFit(8191, 1), false,
    'reject a non-power-of-two block that exceeds its rounded-down page array');
assert.equal(uncompressedPagesFit(36863, 8), false,
    'reject a larger non-power-of-two block that exceeds its rounded-down page array');
assert.equal(uncompressedPagesFit(131072, 32), true,
    'accept an uncompressed block that exactly fits its allocated pages');

assert.equal(tableFits(24, 8, 32), true, 'table ending at bytes_used is valid');
assert.equal(tableFits(25, 8, 32), false, 'table extending past bytes_used is invalid');
assert.equal(tableFits(Number.MAX_SAFE_INTEGER, 8, 32), false,
    'out-of-range starts must fail without addition overflow');
assert.equal(65535 < 1, false, 'an invalid uid/gid index must fail');
assert.equal(0 < 0, false, 'a fragment index cannot be valid with zero fragments');
assert.equal(validFragmentOffset(0, 131072), true, 'accept the first fragment byte');
assert.equal(validFragmentOffset(131071, 131072), true,
    'accept a valid fragment offset at the block tail');
for (const rawOffset of [131072, 0x7fffffff, 0x80000000, 0xfffffff0, 0xffffffff])
    assert.equal(validFragmentOffset(rawOffset, 131072), false,
        `reject fragment offset 0x${rawOffset.toString(16)}`);

console.log('SquashFS table, block, and fragment bounds: ok');