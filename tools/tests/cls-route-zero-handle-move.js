const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const sourcePath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/sched/cls_route.c';
const source = fs.readFileSync(path.join(root, sourcePath), 'utf8');
const start = source.indexOf('static int route4_change(');
const end = source.indexOf('static void route4_walk(', start);
assert.ok(start >= 0 && end > start, 'route4_change implementation exists');

const change = source.slice(start, end);
assert.match(change, /old_bkt = f->bkt;\s*old_handle = f->handle;\s*old_filter = 1;/,
    'track an existing filter separately from its handle value');
assert.match(change, /if \(old_filter && f->handle != old_handle\)/,
    'decide whether to unlink based on filter existence, not a nonzero handle');
assert.doesNotMatch(change, /if \(old_handle &&/,
    'do not treat a zero handle as an unhashed filter');

const unlink = change.indexOf('*fp = f->next;');
const insert = change.indexOf('f->next = f1;');
assert.ok(unlink >= 0 && insert > unlink,
    'unlink from the old chain before replacing next for the new chain');
assert.match(change, /if \(old_bkt && head->table\[th\] == old_bkt\)/,
    'unlink from the bucket that owned the filter before the change');

console.log('PASS: cls_route zero-handle move (source contract; not kernel execution)');