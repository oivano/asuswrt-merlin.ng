const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const sourcePath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/splice.c';
const source = fs.readFileSync(path.join(root, sourcePath), 'utf8');
const guard = source.match(/if \((count > MAX_PAGES_PER_RECVFILE \* PAGE_CACHE_SIZE -\s*\(pos & \(PAGE_CACHE_SIZE - 1\)\))\)\s*\{\s*err = -EINVAL;\s*goto done;\s*\}/);

assert.ok(guard, 'reject a byte range that spans more pages than the recvfile arrays hold');
const guardOffset = source.indexOf(guard[0]);
assert.ok(guardOffset > source.indexOf('generic_write_checks(file, &pos, &count'),
    'check the position and count after generic write validation');
assert.ok(guardOffset < source.indexOf('file_remove_suid(file)', guardOffset),
    'reject before changing file metadata or writing page-cache data');
assert.match(source, /rv_cb = kmalloc\(MAX_PAGES_PER_RECVFILE \* sizeof\(struct recvfile_ctl_blk\)/);
assert.match(source, /iov = kmalloc\(MAX_PAGES_PER_RECVFILE \* sizeof\(struct kvec\)/);

const rejects = new Function('count', 'pos', 'MAX_PAGES_PER_RECVFILE', 'PAGE_CACHE_SIZE',
    `return ${guard[1]};`);
const pageSize = 4096;
const maxPages = 32;
const maxBytes = maxPages * pageSize;

for (let offset = 0; offset < pageSize; offset++) {
    const boundary = maxBytes - offset;
    for (const count of [1, boundary - 1, boundary, boundary + 1, maxBytes]) {
        const expected = Math.ceil((offset + count) / pageSize) > maxPages;
        assert.equal(rejects(count, offset, maxPages, pageSize), expected,
            `offset ${offset}, count ${count}`);
    }
}

assert.equal(rejects(131072, 1, maxPages, pageSize), true,
    'reject the reported unaligned 32-page request');
assert.equal(rejects(131071, 1, maxPages, pageSize), false,
    'accept the largest unaligned range contained in 32 pages');
assert.equal(rejects(131072, 0, maxPages, pageSize), false,
    'accept an aligned 32-page range');

console.log('PASS: recvfile page-span bounds source contract and boundary model (not kernel execution)');