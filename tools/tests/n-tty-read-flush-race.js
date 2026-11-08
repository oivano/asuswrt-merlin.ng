#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const sourcePath = path.join(__dirname, '../../release/src-rt-6.x.4708/linux/linux-2.6.36/drivers/char/n_tty.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const readCopy = source.match(/static int copy_from_read_buf\([\s\S]*?\n}\n/);
assert(readCopy, 'copy_from_read_buf must exist');

assert(source.includes('N_TTY_BUF_SIZE + sizeof(unsigned int)'), 'read buffer must reserve generation metadata');
assert(source.includes('(*n_tty_read_buf_generation(tty))++;'), 'flush must advance the generation under read_lock');
assert(readCopy[0].includes('tail = tty->read_tail;'), 'copy source offset must be snapshotted under read_lock');
assert(readCopy[0].includes('generation == *n_tty_read_buf_generation(tty)'), 'consumption must reject a flushed snapshot');
assert(readCopy[0].includes('int count;') && readCopy[0].includes('if (count < 0)'), 'negative read counts must clamp before size_t conversion');
assert(readCopy[0].includes('N_TTY_BUF_SIZE - tail'), 'copy length must stay within the ring buffer');
assert(readCopy[0].includes('tty->read_cnt >= 0') && readCopy[0].includes('(size_t)tty->read_cnt >= n'), 'consumption must not underflow read_cnt');

function copySnapshot(state, requested, flushDuringCopy) {
    let tail = state.tail;
    const generation = state.generation;
    let count = state.count;
    if (count < 0) {
        state.tail = state.head;
        state.count = 0;
        tail = state.tail;
        count = 0;
    }
    const n = Math.min(requested, Math.min(count, 4096 - tail));

    if (flushDuringCopy) {
        state.head = 0;
        state.tail = 0;
        state.count = 0;
        state.generation++;
        state.count = 3;
        state.head = 3;
    }

    if (generation === state.generation && state.tail === tail && state.count >= n) {
        state.tail = (tail + n) & 4095;
        state.count -= n;
    }
    return n;
}

const raced = { head: 8, tail: 0, count: 8, generation: 1 };
assert.strictEqual(copySnapshot(raced, 8, true), 8, 'a completed copy may return only its bounded snapshot');
assert.strictEqual(raced.count, 3, 'a flush race must not consume post-flush input');
assert.strictEqual(raced.tail, 0, 'a flush race must not advance the reset tail');

const negative = { head: 0, tail: 0, count: -8, generation: 2 };
assert.strictEqual(copySnapshot(negative, 0xffffffff, false), 0, 'negative counts must not become huge copies');
assert.strictEqual(negative.count, 0, 'an invalid negative count must be normalized');

const wrapped = { head: 4095, tail: 4094, count: 8, generation: 3 };
assert.strictEqual(copySnapshot(wrapped, 0xffffffff, false), 2, 'copy size must stop at the physical ring boundary');

console.log('N_TTY read/flush race regression checks passed');