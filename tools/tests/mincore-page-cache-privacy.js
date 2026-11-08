const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/mm/mincore.c'), 'utf8');

const helperStart = source.indexOf('static inline int can_do_mincore(');
const helperEnd = source.indexOf('\n}', helperStart);
assert.notEqual(helperStart, -1, 'mincore permission helper exists');
assert.notEqual(helperEnd, -1, 'mincore permission helper is complete');
const helper = source.slice(helperStart, helperEnd);
assert.match(helper, /if \(!vma->vm_file\)\s*return 1;/,
    'anonymous mappings retain normal mincore processing');
assert.match(helper, /is_owner_or_cap\(inode\)/,
    'inode owners and CAP_FOWNER callers retain normal processing');
assert.match(helper, /inode_permission\(inode, MAY_WRITE\) == 0/,
    'callers able to write the file retain normal processing');

const doStart = source.indexOf('static long do_mincore(');
const doEnd = source.indexOf('\n}', doStart);
assert.notEqual(doStart, -1, 'do_mincore exists');
assert.notEqual(doEnd, -1, 'do_mincore is complete');
const doMincore = source.slice(doStart, doEnd);
const guard = doMincore.indexOf('if (!can_do_mincore(vma))');
const cacheWalk = doMincore.indexOf('mincore_page_range(vma, addr, end, vec)');
assert.ok(guard !== -1 && cacheWalk !== -1 && guard < cacheWalk,
    'permission gate precedes page-cache lookup');
assert.match(doMincore,
    /if \(!can_do_mincore\(vma\)\)\s*\{\s*unsigned long nr = \(end - addr\) >> PAGE_SHIFT;\s*memset\(vec, 1, nr\);\s*return nr;/,
    'unauthorized file-backed ranges return a cache-independent resident vector');

console.log('PASS: mincore cache disclosure gate and conservative result; source-contract check only, not compiled-kernel execution');