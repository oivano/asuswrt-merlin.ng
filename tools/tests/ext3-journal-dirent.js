const fs = require('fs');
const assert = require('assert');

const namei = fs.readFileSync('release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext3/namei.c', 'utf8');
const superSource = fs.readFileSync('release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext3/super.c', 'utf8');
const ext3Header = fs.readFileSync('release/src-rt-6.x.4708/linux/linux-2.6.36/include/linux/ext3_fs.h', 'utf8');

const validator = namei.match(/static int ext3_valid_dirent\([\s\S]*?\n\}/);
assert(validator, 'directory-entry inode validator is missing');
assert(/ino == EXT3_ROOT_INO/.test(validator[0]), 'root inode exception is missing');
assert(/ino < EXT3_FIRST_INO\(sb\)/.test(validator[0]), 'reserved inode range is not rejected');
assert(/sbi->s_journal && sbi->s_journal->j_inode/.test(validator[0]), 'live journal inode is not checked');
assert(/ino == sbi->s_journal->j_inode->i_ino/.test(validator[0]), 'active journal inode alias is not rejected');
assert.strictEqual((namei.match(/ext3_valid_dirent\(/g) || []).length, 3,
    'both lookup and parent lookup must use the strict validator');
assert(/ext3_error\(dir->i_sb, "ext3_lookup"[\s\S]*?return ERR_PTR\(-EIO\)/.test(namei),
    'invalid directory entry lookup must fail with -EIO');
assert(/ext3_error\(child->d_inode->i_sb, "ext3_get_parent"[\s\S]*?return ERR_PTR\(-EIO\)/.test(namei),
    'invalid parent directory entry must fail with -EIO');
assert(/s_first_ino < EXT3_GOOD_OLD_FIRST_INO[\s\S]*?goto failed_mount;/.test(superSource),
    'mount must reject s_first_ino below the ext3 minimum');
assert(/static inline int ext3_valid_inum/.test(ext3Header),
    'internal inode validation must remain available for journal and resize inodes');

function validDirent(ino, firstIno, inodeCount, journalIno) {
    return ino === 2 || (ino >= firstIno && ino <= inodeCount && ino !== journalIno);
}

assert.strictEqual(validDirent(2, 11, 100, 12), true, 'root inode remains valid');
assert.strictEqual(validDirent(7, 11, 100, 12), false, 'reserved resize inode is rejected');
assert.strictEqual(validDirent(8, 11, 100, 12), false, 'reserved journal inode is rejected');
assert.strictEqual(validDirent(11, 11, 100, 12), true, 'first ordinary inode remains valid');
assert.strictEqual(validDirent(12, 11, 100, 12), false, 'ordinary-numbered journal inode is rejected');
assert.strictEqual(validDirent(101, 11, 100, 12), false, 'out-of-range inode is rejected');

console.log('ext3 journal directory-entry checks passed');