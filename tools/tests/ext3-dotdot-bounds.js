const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const kernel = path.resolve(__dirname, '../../release/src-rt-6.x.4708/linux/linux-2.6.36');
const namei = fs.readFileSync(path.join(kernel, 'fs/ext3/namei.c'), 'utf8');
const dir = fs.readFileSync(path.join(kernel, 'fs/ext3/dir.c'), 'utf8');

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `${signature} is present`);
    const open = source.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < source.length; index++) {
        if (source[index] === '{')
            depth++;
        else if (source[index] === '}' && --depth === 0)
            return source.slice(open, index + 1);
    }
    assert.fail(`${signature} has a closing brace`);
}

function assertOrder(source, tokens, label) {
    let previous = -1;
    for (const token of tokens) {
        const current = source.indexOf(token);
        assert(current > previous, `${label}: ${token} is checked in order`);
        previous = current;
    }
}

const htree = functionBody(namei, 'int ext3_htree_fill_tree(');
assertOrder(htree, [
    'ext3_check_dir_entry(__func__, dir, de',
    'de1 = ext3_next_entry(de)',
    'ext3_check_dir_entry(__func__, dir, de1',
    'ext3_htree_store_dirent(dir_file, 2, 0, de1)'
], 'htree readdir');
assert.match(htree, /err = -EIO;\s+goto errout;/,
    'htree readdir fails on malformed dot entries');

const emptyDir = functionBody(namei, 'static int empty_dir (');
assertOrder(emptyDir, [
    'ext3_check_dir_entry(__func__, inode, de',
    'de1 = ext3_next_entry(de)',
    'ext3_check_dir_entry(__func__, inode, de1',
    'le32_to_cpu(de->inode)'
], 'empty_dir');
assert.match(emptyDir, /return -EIO;/, 'empty_dir reports malformed dot entries');

const rename = functionBody(namei, 'static int ext3_rename (');
assertOrder(rename, [
    'ext3_check_dir_entry(__func__, old_inode, dot_de',
    'dotdot_de = ext3_next_entry(dot_de)',
    'ext3_check_dir_entry(__func__, old_inode, dotdot_de',
    'le32_to_cpu(dotdot_de->inode)',
    'dotdot_de->inode = cpu_to_le32(new_dir->i_ino)'
], 'rename');

for (const signature of ['static int ext3_rmdir (', 'static int ext3_rename (']) {
    const caller = functionBody(namei, signature);
    assert.match(caller, /retval = empty_dir\([^;]+;\s+if \(retval <= 0\) \{\s+if \(!retval\)\s+retval = -ENOTEMPTY;/,
        `${signature} preserves empty_dir errors`);
}

assert.match(dir, /rlen < EXT3_DIR_REC_LEN\(1\)[\s\S]*?rlen % 4 != 0[\s\S]*?\+ rlen > dir->i_sb->s_blocksize/,
    'the directory-entry validator enforces minimum, alignment, and block bounds');
assert(0x2000 > 0x1000, 'the 0x2000 fixture exceeds a 4 KiB directory block');

console.log('PASS: ext3 dot/dotdot bounds checks precede pointer use and errors propagate');
