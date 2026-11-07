const assert = require('assert');
const fs = require('fs');
const path = require('path');

const sourcePath = path.join(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext3/namei.c');
const source = fs.readFileSync(sourcePath, 'utf8');

function functionBody(name) {
    const signature = new RegExp(`\\b${name}\\s*\\([^;]*?\\)\\s*\\{`, 'm');
    const match = signature.exec(source);
    assert(match, `missing function ${name}`);
    const open = source.indexOf('{', match.index);
    let depth = 1;
    for (let cursor = open + 1; cursor < source.length; cursor++) {
        if (source[cursor] === '{') depth++;
        if (source[cursor] === '}' && --depth === 0)
            return source.slice(open + 1, cursor);
    }
    assert.fail(`unterminated function ${name}`);
}

const validate = functionBody('dx_check_dirents');
assert.match(validate, /offset >= blocksize \|\| \(offset & 3\)/);
assert.match(validate, /ext3_check_dir_entry\(__func__, dir, de, bh, offset\)/);
assert.ok(validate.indexOf('ext3_check_dir_entry') < validate.indexOf('offset +='),
    'validate each record before advancing by its on-disk rec_len');
assert.match(validate, /return -EIO;/);

const split = functionBody('do_split');
assert.ok(split.indexOf('dx_check_dirents(dir, *bh, 0)') < split.indexOf('ext3_append'),
    'validate the leaf before allocating or mapping it');
assert.match(split, /if \(!count\)/);
assert.ok(split.indexOf('if (!count)') < split.indexOf('dx_sort_map'),
    'reject an empty map before sorting');
assert.match(split, /if \(count > 1\)\s*dx_sort_map/);
assert.match(split, /if \(split == count\)\s*\{\s*split--;/);
assert.match(split, /continued = split && hash2 == map\[split - 1\]\.hash;/);
assert.match(split, /if \(!de2\)\s*\{\s*err = -EIO;/);

const move = functionBody('dx_move_dirents');
assert.match(move, /if \(rec_len > blocksize - size\)\s*return NULL;/);
assert.match(move, /if \(rec_len > blocksize - moved\)\s*return NULL;\s*memcpy/);

const makeIndexed = functionBody('make_indexed_dir');
const dotdotCheck = makeIndexed.indexOf('ext3_check_dir_entry');
const suffixCheck = makeIndexed.indexOf('dx_check_dirents');
const firstCopy = makeIndexed.indexOf('memcpy (data1, de, len)');
assert.ok(dotdotCheck >= 0 && dotdotCheck < suffixCheck && suffixCheck < firstCopy,
    'validate dotdot and every copied suffix entry before memcpy');

function safeSplit(count, moveCount) {
    let splitIndex = count - moveCount;
    if (splitIndex === count)
        splitIndex--;
    return splitIndex;
}

assert.strictEqual(safeSplit(4, 4), 0,
    'all entries may move without looking before map[0]');
assert.strictEqual(safeSplit(4, 0), 3,
    'a split with no naturally selected moved entries still has a valid hash');
console.log('ext3 dx split source contracts passed');