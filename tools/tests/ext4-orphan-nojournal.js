const assert = require('assert');
const fs = require('fs');

const base = 'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/ext4/';
const namei = fs.readFileSync(base + 'namei.c', 'utf8');
const superSource = fs.readFileSync(base + 'super.c', 'utf8');

const orphanAdd = namei.match(/int ext4_orphan_add\([\s\S]*?\n}\n/);
const orphanDel = namei.match(/int ext4_orphan_del\([\s\S]*?\n}\n/);
const cleanup = superSource.match(/static int ext4_orphan_cleanup\([\s\S]*?\n}\n/);

assert(orphanAdd, 'orphan-add body exists');
assert(orphanDel, 'orphan-delete body exists');
assert(cleanup, 'orphan-cleanup body exists');
assert(/if \(!ext4_handle_valid\(handle\)\)\s*return 0;/.test(orphanAdd[0]),
    'normal no-journal orphan additions remain disabled');
assert(/handle && !ext4_handle_valid\(handle\)\s*&&\s*\n\s*!\(EXT4_SB\(inode->i_sb\)->s_mount_state & EXT4_ORPHAN_FS\)/
    .test(orphanDel[0]),
    'pseudo-handles are allowed to remove orphans only during recovery');
assert(/list_del_init\(&ei->i_orphan\)/.test(orphanDel[0]),
    'orphan removal unlinks the in-memory list entry');
assert(/sbi->s_es->s_last_orphan = cpu_to_le32\(ino_next\)/
    .test(orphanDel[0]),
    'orphan removal updates the on-disk list head');
assert(/nr_seen >= max_orphans/.test(cleanup[0]),
    'orphan traversal has an inode-count bound');
assert(/le32_to_cpu\(es->s_last_orphan\) == ino/.test(cleanup[0]),
    'orphan traversal rejects a head that did not advance');
assert(/list_for_each_safe\(pos, next, &EXT4_SB\(sb\)->s_orphan\)\s*list_del_init\(pos\)/
    .test(cleanup[0]),
    'failed recovery detaches in-memory orphan entries');
assert(/err = ext4_orphan_cleanup\(sb, es\);[\s\S]*?if \(err\)[\s\S]*?goto failed_mount4;/.test(superSource),
    'failed orphan recovery aborts the mount');

function recover(head, inodeCount, nextInode) {
    let seen = 0;
    while (head !== 0) {
        if (seen >= inodeCount)
            return { failed: true, seen };
        const current = head;
        seen++;
        head = nextInode[current] === undefined ? current : nextInode[current];
        if (head === current)
            return { failed: true, seen };
    }
    return { failed: false, seen };
}

assert.deepStrictEqual(recover(1, 8, { 1: 0 }),
    { failed: false, seen: 1 }, 'a valid orphan chain completes');
assert.deepStrictEqual(recover(1, 8, { 1: 1 }),
    { failed: true, seen: 1 }, 'a self-linked orphan fails immediately');
assert.deepStrictEqual(recover(1, 2, { 1: 2, 2: 1 }),
    { failed: true, seen: 2 }, 'a cyclic orphan chain is bounded by inode count');

console.log('ext4 no-journal orphan recovery checks passed');