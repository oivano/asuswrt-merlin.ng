const assert = require("assert");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../..");
const ext4 = path.join(root, "release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext4");

function read(name) {
    return fs.readFileSync(path.join(ext4, name), "utf8");
}

function body(source, signature) {
    const start = source.lastIndexOf(signature);
    assert.notStrictEqual(start, -1, `missing ${signature}`);
    const open = source.indexOf("{", start);
    let depth = 1;
    for (let cursor = open + 1; cursor < source.length; cursor++) {
        if (source[cursor] === "{") depth++;
        if (source[cursor] === "}" && --depth === 0)
            return source.slice(open + 1, cursor);
    }
    assert.fail(`unterminated ${signature}`);
}

const header = read("ext4.h");
const inode = read("inode.c");
const namei = read("namei.c");
const ialloc = read("ialloc.c");
const resize = read("resize.c");
const superblock = read("super.c");

const validInum = body(header, "static inline int ext4_valid_inum");
assert.match(validInum, /ino == EXT4_ROOT_INO/);
assert.match(validInum, /ino >= EXT4_FIRST_INO\(sb\)/);
assert.doesNotMatch(validInum, /EXT4_(?:JOURNAL|RESIZE)_INO/);

const iget = body(inode, "struct inode *ext4_iget(");
assert.match(iget, /ino < EXT4_ROOT_INO/);
assert.match(iget, /EXT4_IGET_SPECIAL/);
assert.match(iget, /ino < EXT4_FIRST_INO\(sb\)/);
assert.ok(iget.indexOf("EXT4_FIRST_INO(sb)") < iget.indexOf("iget_locked(sb, ino)"));
const orphanGet = body(ialloc, "struct inode *ext4_orphan_get(");
assert.match(orphanGet, /ext4_valid_inum\(sb, ino\)/);
assert.ok(orphanGet.indexOf("ext4_valid_inum(sb, ino)") < orphanGet.indexOf("ext4_read_inode_bitmap(sb, block_group)"));
assert.match(orphanGet, /ext4_iget\(sb, ino, 0\)/);
assert.match(body(namei, "static struct dentry *ext4_lookup("), /ext4_iget\(dir->i_sb, ino, 0\)/);
assert.match(body(namei, "struct dentry *ext4_get_parent("), /ext4_iget\(child->d_inode->i_sb, ino, 0\)/);
assert.match(body(resize, "int ext4_group_add("), /ext4_iget\(sb, EXT4_RESIZE_INO, EXT4_IGET_SPECIAL\)/);

const fillSuper = body(superblock, "static int ext4_fill_super(");
assert.match(fillSuper, /s_first_ino < EXT4_GOOD_OLD_FIRST_INO/);
const loadJournal = body(superblock, "static int ext4_load_journal(");
assert.match(loadJournal, /journal_inum >= EXT4_FIRST_INO\(sb\)/);
assert.match(body(superblock, "static journal_t *ext4_get_journal("),
    /ext4_iget\(sb, journal_inum, EXT4_IGET_SPECIAL\)/);

console.log("ext4 inode validation source contracts passed");