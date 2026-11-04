'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(
  path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/pipe.c'),
  'utf8'
);

for (const name of ['pipe_iov_copy_from_user', 'pipe_iov_copy_to_user']) {
  const helper = source.match(new RegExp(`static int\\s+${name}\\([\\s\\S]*?\\n}\\n`));
  assert(helper, `${name} helper exists`);
  assert.match(helper[0], /const struct iovec \*\*iovp/);
  assert.match(helper[0], /unsigned long \*iov_offsetp/);
  assert.match(helper[0], /iov->iov_base \+ iov_offset/);
  assert.doesNotMatch(helper[0], /iov->iov_base\s*\+=|iov->iov_len\s*[-+]=/,
    `${name} does not mutate the caller's iovec`);
  assert.match(helper[0], /return -EFAULT;/);
  assert.match(helper[0], /\*iovp = iov;\s*\*iov_offsetp = iov_offset;\s*return 0;/,
    `${name} commits its cursor only after the copy completes`);
}

assert.match(source, /iov_fault_in_pages_write\(iov, iov_offset, chars\)/);
assert.equal((source.match(/iov_fault_in_pages_read\(iov, iov_offset, chars\)/g) || []).length, 2);
assert.match(source, /pipe_iov_copy_to_user\(&iov, &iov_offset,/);
assert.equal((source.match(/pipe_iov_copy_from_user\([^;]*?&iov,\s*&iov_offset/g) || []).length, 2);

console.log('pipe iovec retry cursor checks passed');