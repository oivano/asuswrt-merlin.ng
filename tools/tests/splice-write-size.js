const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const kernel = path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36');

function functionBody(source, start, end) {
    const first = source.indexOf(start);
    assert(first >= 0, `missing ${start}`);
    const last = source.indexOf(end, first + start.length);
    assert(last > first, `missing ${end}`);
    return source.slice(first, last);
}

const spliceSource = fs.readFileSync(path.join(kernel, 'fs/splice.c'), 'utf8');
const spliceWrite = functionBody(spliceSource,
    'generic_file_splice_write(struct pipe_inode_info *pipe',
    'EXPORT_SYMBOL(generic_file_splice_write);');
const check = spliceWrite.indexOf(
    'generic_write_checks(out, ppos, &len, S_ISBLK(inode->i_mode))');
const pipeLock = spliceWrite.indexOf('pipe_lock(pipe)');
const pipeFeed = spliceWrite.indexOf('splice_from_pipe_feed(pipe, &sd, pipe_to_file)');

assert(check >= 0, 'splice write must apply generic write checks');
assert(pipeLock > check, 'range check must precede pipe locking and consumption');
assert(pipeFeed > check, 'range check must precede writing file pages');
assert.match(spliceWrite, /if \(ret\)\s*return ret;/);
assert.match(spliceWrite, /if \(!len\)\s*return 0;/);
assert(spliceWrite.indexOf('sd.total_len = len;') > check,
    'splice descriptor must use the validated length');

const filemapSource = fs.readFileSync(path.join(kernel, 'mm/filemap.c'), 'utf8');
const writeChecks = functionBody(filemapSource,
    'inline int generic_write_checks(',
    'EXPORT_SYMBOL(generic_write_checks);');
assert.match(writeChecks, /rlimit\(RLIMIT_FSIZE\)/);
assert.match(writeChecks, /MAX_NON_LFS/);
assert.match(writeChecks, /i_sb->s_maxbytes/);

console.log('splice-write-size: source contracts ok');
