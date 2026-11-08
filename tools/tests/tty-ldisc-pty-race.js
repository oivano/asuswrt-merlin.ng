'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const ttyHeader = read('release/src-rt-6.x.4708/linux/linux-2.6.36/include/linux/tty.h');
const ttyIo = read('release/src-rt-6.x.4708/linux/linux-2.6.36/drivers/char/tty_io.c');
const ldisc = read('release/src-rt-6.x.4708/linux/linux-2.6.36/drivers/char/tty_ldisc.c');

assert.match(ttyHeader, /struct mutex ldisc_change_mutex;/);
assert.match(ttyIo, /mutex_init\(&tty->ldisc_change_mutex\);/);

const lockHelper = ldisc.match(/static void tty_ldisc_change_lock\([\s\S]*?\n}\n/);
const unlockHelper = ldisc.match(/static void tty_ldisc_change_unlock\([\s\S]*?\n}\n/);
assert.ok(lockHelper, 'pair lock helper exists');
assert.ok(unlockHelper, 'pair unlock helper exists');
assert.match(lockHelper[0], /mutex_lock\(&tty->ldisc_change_mutex\)/);
assert.match(lockHelper[0], /mutex_lock\(&o_tty->ldisc_change_mutex\)/);
assert.match(lockHelper[0], /\(unsigned long\)tty < \(unsigned long\)o_tty/);
assert.match(unlockHelper[0], /mutex_unlock\(&tty->ldisc_change_mutex\)/);
assert.match(unlockHelper[0], /mutex_unlock\(&o_tty->ldisc_change_mutex\)/);

const setLdisc = ldisc.match(/int tty_set_ldisc\([\s\S]*?\n}\n/);
assert.ok(setLdisc, 'tty_set_ldisc exists');
const body = setLdisc[0];
assert.ok(body.indexOf('tty_ldisc_change_lock(tty, o_tty)') < body.indexOf('tty_wait_until_sent(tty, 0)'));
assert.match(body, /o_ldisc = get_ldisc\(tty->ldisc\)/);
assert.match(body, /tty_ldisc_wait_idle\(o_ldisc, 2\)/);
assert.match(body, /if \(tty->ldisc != o_ldisc\)/);
assert.match(body, /set_bit\(TTY_LDISC, &o_tty->flags\);\s*wake_up\(&tty_ldisc_wait\);/);
assert.doesNotMatch(body, /tty_ldisc_enable\(o_tty\)/);
assert.match(body, /tty_ldisc_put\(o_ldisc\);\s*tty_ldisc_put\(o_ldisc\);/);

console.log('tty pty line-discipline race contracts passed');