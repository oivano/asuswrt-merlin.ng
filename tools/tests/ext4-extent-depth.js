const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const ext4Dir = path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext4');
const header = fs.readFileSync(path.join(ext4Dir, 'ext4_extents.h'), 'utf8');
const extents = fs.readFileSync(path.join(ext4Dir, 'extents.c'), 'utf8');
const inode = fs.readFileSync(path.join(ext4Dir, 'inode.c'), 'utf8');

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert.notStrictEqual(start, -1, `missing ${signature}`);
    const open = source.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < source.length; index++) {
        if (source[index] === '{')
            depth++;
        else if (source[index] === '}' && --depth === 0)
            return source.slice(open + 1, index);
    }
    assert.fail(`unterminated ${signature}`);
}

const check = functionBody(extents, 'static int __ext4_ext_check(');
const find = functionBody(extents, 'ext4_ext_find_extent(struct inode *inode');
const checkDepth = check.indexOf('depth < 0 || depth > EXT4_MAX_EXTENT_DEPTH');
const checkHeaderDepth = check.indexOf('le16_to_cpu(eh->eh_depth) != depth');
const findDepth = find.indexOf('depth < 0 || depth > EXT4_MAX_EXTENT_DEPTH');
const allocatePath = find.indexOf('kzalloc(sizeof(struct ext4_ext_path)');
const walkTree = find.indexOf('while (i)');

assert.match(header, /^#define EXT4_MAX_EXTENT_DEPTH\s+5$/m);
assert(checkDepth >= 0 && checkDepth < checkHeaderDepth,
    'inode extent validation must reject an impossible depth before comparing the header');
assert.match(check, /error_msg = "eh_depth out of bounds";/);
assert.match(inode, /ret = ext4_ext_check_inode\(inode\);/);
assert(findDepth >= 0 && findDepth < allocatePath && findDepth < walkTree,
    'extent lookup must reject an impossible depth before allocation or traversal');
assert.match(find, /if \(!path\)\s*return ERR_PTR\(-EIO\);\s*goto err;/);

const validDepth = depth => depth >= 0 && depth <= 5;
assert(validDepth(0));
assert(validDepth(5));
for (const depth of [6, 0xfffe, 0xffff])
    assert(!validDepth(depth), `depth ${depth} must be rejected`);

console.log('ext4 extent depth checks passed');