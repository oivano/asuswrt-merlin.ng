const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/nfsd/nfs3xdr.c'), 'utf8');
const proc = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/nfsd/nfs3proc.c'), 'utf8');
const start = source.indexOf('encode_entry(struct readdir_cd *ccd');
const end = source.indexOf('\n}\n', start);
assert.notEqual(start, -1, 'encode_entry must exist');
assert.notEqual(end, -1, 'encode_entry must have a body');
const encoder = source.slice(start, end);
const pendingCookie = encoder.indexOf('if (cd->offset) {');
const clearConsumedPointer = encoder.indexOf('cd->offset = NULL;', pendingCookie);
const tooSmall = encoder.indexOf('if (cd->buflen < elen)');

assert.ok(pendingCookie !== -1 && clearConsumedPointer > pendingCookie,
    'clear the deferred cookie pointer after writing it');
assert.ok(clearConsumedPointer < tooSmall,
    'clear the consumed pointer before a too-small entry can return');
assert.match(source,
    /cd->offset = p;\s*\/\* remember pointer \*\//,
    'a successfully encoded entry must establish its own cookie pointer');
assert.match(proc,
    /if \(resp->offset\) \{[\s\S]*?xdr_encode_hyper\(resp->offset, offset\);/,
    'the final handler must remain guarded by the current cookie pointer');

console.log('PASS: consumed READDIRPLUS cookie pointer is cleared before too-small return; source-contract check only, not compiled-kernel execution');