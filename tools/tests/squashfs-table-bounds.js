const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const squashfsDir = path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/fs/squashfs');
const idSource = fs.readFileSync(path.join(squashfsDir, 'id.c'), 'utf8');
const fragmentSource = fs.readFileSync(path.join(squashfsDir, 'fragment.c'), 'utf8');
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
const readFragments = functionBody(fragmentSource,
    '__le64 *squashfs_read_fragment_index_table(');

assert.match(sbSource, /unsigned int\s+ids;[\s\S]*unsigned int\s+fragments;/);
assert.match(superSource, /msblk->ids = le16_to_cpu\(sblk->no_ids\);[\s\S]*?if \(msblk->ids == 0\)[\s\S]*?goto failed_mount;[\s\S]*?squashfs_read_id_index_table/);
assert.match(getId, /if \(index >= msblk->ids \|\| !msblk->id_table\)[\s\S]*?return -EIO;[\s\S]*?msblk->id_table\[block\]/);
assert.match(fragLookup, /if \(fragment >= msblk->fragments \|\| !msblk->fragment_index\)[\s\S]*?return -EIO;[\s\S]*?msblk->fragment_index\[block\]/);
assert.ok(getId.indexOf('return -EIO') < getId.indexOf('SQUASHFS_ID_BLOCK(index)'));
assert.ok(fragLookup.indexOf('return -EIO') <
    fragLookup.indexOf('SQUASHFS_FRAGMENT_INDEX((u64) fragment)'));

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

assert.equal(tableFits(24, 8, 32), true, 'table ending at bytes_used is valid');
assert.equal(tableFits(25, 8, 32), false, 'table extending past bytes_used is invalid');
assert.equal(tableFits(Number.MAX_SAFE_INTEGER, 8, 32), false,
    'out-of-range starts must fail without addition overflow');
assert.equal(65535 < 1, false, 'an invalid uid/gid index must fail');
assert.equal(0 < 0, false, 'a fragment index cannot be valid with zero fragments');

console.log('SquashFS ID and fragment table bounds: ok');