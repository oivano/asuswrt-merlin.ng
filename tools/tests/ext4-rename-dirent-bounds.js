const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const nameiPath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext4/namei.c';
const dirPath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext4/dir.c';
const namei = fs.readFileSync(path.join(root, nameiPath), 'utf8');
const dir = fs.readFileSync(path.join(root, dirPath), 'utf8');
const emptyDir = namei.match(/static int empty_dir\(struct inode \*inode\)\s*\{([\s\S]*?)\n\}/);
const rename = namei.match(/static int ext4_rename\(struct inode \*old_dir,[\s\S]*?\n\}\n/);
assert.ok(emptyDir && rename, 'ext4 directory routines are present');

const emptyBody = emptyDir[1];
const renameBody = rename[0];
assert.ok(dir.includes('rlen < EXT4_DIR_REC_LEN(1)'), 'entry validator checks minimum record length');
assert.ok(dir.includes('rlen % 4 != 0'), 'entry validator checks record alignment');
assert.ok(dir.includes('((char *) de - bh->b_data) + rlen > dir->i_sb->s_blocksize'),
    'entry validator checks the block boundary');

assert.ok(emptyBody.indexOf('ext4_check_dir_entry(inode, de, bh, 0)') <
    emptyBody.indexOf('ext4_next_entry(de,'), 'empty_dir validates dot before forming dotdot');
assert.ok(emptyBody.indexOf('dot_len > sb->s_blocksize - EXT4_DIR_REC_LEN(2)') <
    emptyBody.indexOf('ext4_next_entry(de,'), 'empty_dir bounds the dotdot header before forming its pointer');
assert.ok(emptyBody.indexOf('ext4_check_dir_entry(inode, de1, bh, dot_len)') <
    emptyBody.indexOf('le32_to_cpu(de1->inode)'), 'empty_dir validates dotdot before reading its inode');
assert.equal([...emptyBody.matchAll(/return 1;/g)].length, 1,
    'only a fully scanned directory can be reported empty');
const dotdotCheck = emptyBody.indexOf('if (!ext4_check_dir_entry(inode, de1, bh, dot_len)');
const dotdotReject = emptyBody.indexOf('return 0;', dotdotCheck);
const continueScan = emptyBody.indexOf('offset =', dotdotCheck);
assert.ok(dotdotCheck >= 0 && dotdotReject > dotdotCheck && continueScan > dotdotReject,
    'invalid dotdot entries are rejected before the empty-directory scan');
assert.ok(emptyBody.includes('le32_to_cpu(de->inode) != inode->i_ino') &&
    emptyBody.includes('de->name_len != 1') && emptyBody.includes('de->name[0]'),
    'empty_dir validates dot inode and name');
assert.ok(emptyBody.includes('de1->name_len != 2') && emptyBody.includes('memcmp("..", de1->name, 2)'),
    'empty_dir validates dotdot name');

assert.ok(renameBody.indexOf('ext4_check_dir_entry(old_inode, dir_de, dir_bh, 0)') <
    renameBody.indexOf('ext4_next_entry(dir_de,'), 'rename validates dot before forming dotdot');
assert.ok(renameBody.indexOf('dot_len > old_dir->i_sb->s_blocksize - EXT4_DIR_REC_LEN(2)') <
    renameBody.indexOf('ext4_next_entry(dir_de,'), 'rename bounds the dotdot header before forming its pointer');
assert.ok(renameBody.indexOf('ext4_check_dir_entry(old_inode, parent_de, dir_bh, dot_len)') <
    renameBody.indexOf('le32_to_cpu(parent_de->inode)'), 'rename validates dotdot before reading its inode');
assert.ok(renameBody.includes('le32_to_cpu(dir_de->inode) != old_inode->i_ino') &&
    renameBody.includes('dir_de->name_len != 1') && renameBody.includes('dir_de->name[0]'),
    'rename validates dot inode and name');
assert.ok(renameBody.indexOf('ext4_check_dir_entry(old_inode, parent_de, dir_bh, dot_len)') <
    renameBody.indexOf('parent_de->inode = cpu_to_le32(new_dir->i_ino)'),
    'rename updates only the validated dotdot entry');
assert.ok(!renameBody.includes('PARENT_INO('), 'unchecked parent-entry access is removed');

function validDirEntry(blockSize, offset, recLen, nameLen) {
    const minNameLen = (nameLen + 8 + 3) & ~3;
    return recLen >= 12 && recLen % 4 === 0 && recLen >= minNameLen &&
        offset + recLen <= blockSize;
}

assert.equal(validDirEntry(4096, 0, 0xfff0, 1), false,
    'reject a dot record extending beyond a 4 KiB directory block');
assert.equal(validDirEntry(4096, 12, 4084, 2), true,
    'accept a valid dotdot record filling the remainder of a 4 KiB block');

console.log('PASS: ext4 rename/empty_dir dot-entry bounds (source contract/model; not kernel execution)');