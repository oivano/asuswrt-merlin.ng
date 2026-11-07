const assert = require('assert');
const fs = require('fs');

const kernelRoot = 'release/src-rt-6.x.4708/linux/linux-2.6.36';
const ttySource = fs.readFileSync(`${kernelRoot}/drivers/char/tty_io.c`, 'utf8');
const ptySource = fs.readFileSync(`${kernelRoot}/drivers/char/pty.c`, 'utf8');
const fsnotifySource = fs.readFileSync(`${kernelRoot}/include/linux/fsnotify.h`, 'utf8');

function section(source, start, end) {
    const startIndex = source.indexOf(start);
    assert.notStrictEqual(startIndex, -1, `missing section: ${start}`);
    const endIndex = source.indexOf(end, startIndex + start.length);
    assert.notStrictEqual(endIndex, -1, `missing section end: ${end}`);
    return source.slice(startIndex, endIndex);
}

const timestampHelper = section(ttySource, 'static void tty_update_time', 'static ssize_t tty_read');
assert.match(timestampHelper, /now\.tv_sec - time->tv_sec >= 8/);
assert.match(timestampHelper, /time->tv_sec = now\.tv_sec/);
assert.doesNotMatch(timestampHelper, /tv_nsec/);

const readPath = section(ttySource, 'static ssize_t tty_read', 'void tty_write_unlock');
assert.match(readPath, /tty_update_time\(inode, &inode->i_atime\)/);
assert.doesNotMatch(readPath, /inode->i_atime\s*=/);

const writePath = section(ttySource, 'static inline ssize_t do_tty_write', 'void tty_write_message');
assert.match(writePath, /tty_update_time\(inode, &inode->i_mtime\)/);
assert.doesNotMatch(writePath, /inode->i_mtime\s*=/);

const ptyOpen = section(ptySource, 'static int pty_open', 'static void pty_set_termios');
assert.match(ptyOpen, /filp->f_mode\s*\|=\s*FMODE_NONOTIFY/);

for (const eventPath of ['fsnotify_access', 'fsnotify_modify']) {
    const event = section(fsnotifySource, `static inline void ${eventPath}`, '/*');
    assert.match(event, /file->f_mode & FMODE_NONOTIFY/);
}

function updateSeconds(timestamp, nowSeconds) {
    if (nowSeconds - timestamp.seconds >= 8)
        timestamp.seconds = nowSeconds;
}

const recent = { seconds: 100, nanoseconds: 123456789 };
updateSeconds(recent, 107);
assert.deepStrictEqual(recent, { seconds: 100, nanoseconds: 123456789 });
updateSeconds(recent, 108);
assert.deepStrictEqual(recent, { seconds: 108, nanoseconds: 123456789 });

console.log('tty I/O timing protections: PASS');