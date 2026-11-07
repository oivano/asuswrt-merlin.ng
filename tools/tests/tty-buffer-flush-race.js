const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/drivers/char/tty_buffer.c'), 'utf8');
const start = source.indexOf('static void __tty_buffer_flush(');
const end = source.indexOf('\n}\n', start);
assert.notEqual(start, -1);
assert.notEqual(end, -1);
const flush = source.slice(start, end + 2);

assert.match(flush, /if \(tty->buf\.head == NULL\)\s*return;/);
assert.match(flush, /while \(\(thead = tty->buf\.head->next\) != NULL\)/);
const freeHead = flush.indexOf('tty_buffer_free(tty, tty->buf.head)');
const advanceHead = flush.indexOf('tty->buf.head = thead');
assert.ok(freeHead >= 0 && advanceHead > freeHead);
assert.match(flush, /WARN_ON\(tty->buf\.head != tty->buf\.tail\)/);
assert.match(flush, /tty->buf\.head->read = tty->buf\.head->commit/);
assert.doesNotMatch(flush, /tty->buf\.tail\s*=/);

console.log('PASS: flush frees only buffers before the active tail; not compiled or race-stress-tested');