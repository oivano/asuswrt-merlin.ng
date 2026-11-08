const assert = require('assert');
const fs = require('fs');

const source = fs.readFileSync(
    'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/notify/fsnotify.c',
    'utf8'
);
const start = source.indexOf('void __fsnotify_parent(');
const end = source.indexOf('EXPORT_SYMBOL_GPL(__fsnotify_parent);', start);
assert(start >= 0 && end > start, '__fsnotify_parent() must exist');
const body = source.slice(start, end);
const lock = body.indexOf('spin_lock(&dentry->d_lock);');
const allocation = body.indexOf('name = kmalloc(dentry->d_name.len + 1, GFP_ATOMIC);');
const copy = body.indexOf('memcpy(name, dentry->d_name.name,');
const unlock = body.indexOf('spin_unlock(&dentry->d_lock);');
const notifyCalls = [...body.matchAll(/fsnotify\(p_inode,[\s\S]*?\);/g)];
const release = body.indexOf('kfree(name);');

assert(allocation >= 0, 'long names must use a non-blocking allocation');
assert(copy >= 0, 'the dentry name must be copied');
assert(lock < allocation && allocation < copy && copy < unlock,
    'name allocation and copy must happen while d_lock is held');
assert(body.includes('dentry->d_name.len < sizeof(inline_name)'),
    'short names should use the stable inline snapshot');
assert.strictEqual(notifyCalls.length, 2, 'both child-notification variants must remain');
for (const call of notifyCalls)
    assert(/FSNOTIFY_EVENT_(?:PATH|INODE),\s*name,\s*0/.test(call[0]),
        'child notifications must use the stable snapshot');
assert(release > notifyCalls[1].index, 'allocated snapshot must outlive fsnotify()');
assert(!/dentry->d_name\.name/.test(body.slice(unlock)),
    'the raw dentry name must not be dereferenced after unlocking');

console.log('fsnotify child-name snapshot checks passed');