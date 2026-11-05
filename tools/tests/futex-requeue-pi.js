const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/kernel/futex.c'), 'utf8');

const waitPi = source.slice(source.indexOf('static int futex_wait_requeue_pi('),
    source.indexOf('\n/*\n * Support for robust futexes'));
assert.match(waitPi, /if \(uaddr == uaddr2\)\s*return -EINVAL;/,
    'WAIT_REQUEUE_PI rejects an identical address before key lookup');
const waitSetup = waitPi.indexOf('ret = futex_wait_setup(');
const keyCheck = waitPi.indexOf('if (match_futex(&q.key, &key2))');
const enqueue = waitPi.indexOf('futex_wait_queue_me(hb, &q, to)');
assert(waitSetup >= 0 && waitSetup < keyCheck && keyCheck < enqueue,
    'WAIT_REQUEUE_PI checks keys between setup and enqueue');
assert.match(waitPi.slice(keyCheck, enqueue),
    /queue_unlock\(&q, hb\);\s*ret = -EINVAL;\s*goto out_put_keys;/,
    'equal-key rejection releases the lock and both key references');
assert.match(waitPi, /WARN_ON\(!q\.pi_state\);/,
    'the invariant warning checks the field rather than its address');

const requeuePi = source.slice(source.indexOf('static int futex_requeue('),
    source.indexOf('\nstatic inline struct futex_hash_bucket *queue_lock'));
assert.match(requeuePi, /if \(requeue_pi\) \{\s*if \(uaddr1 == uaddr2\)\s*return -EINVAL;/,
    'CMP_REQUEUE_PI rejects an identical address before PI setup');
assert.match(requeuePi, /ret = get_futex_key\(uaddr2, fshared, &key2\);\s*if \(unlikely\(ret != 0\)\)\s*goto out_put_key1;\s*if \(requeue_pi && match_futex\(&key1, &key2\)\) \{\s*ret = -EINVAL;\s*goto out_put_keys;\s*\}/,
    'CMP_REQUEUE_PI rejects equal private/shared keys before locking');

const dispatch = source.slice(source.indexOf('long do_futex('),
    source.indexOf('\nSYSCALL_DEFINE6(futex'));
assert.match(dispatch, /case FUTEX_WAIT_REQUEUE_PI:\s*val3 = FUTEX_BITSET_MATCH_ANY;\s*if \(futex_cmpxchg_enabled\)\s*ret = futex_wait_requeue_pi\([\s\S]*?;\s*else\s*ret = -ENOSYS;/,
    'WAIT_REQUEUE_PI is unavailable without futex cmpxchg');
assert.match(dispatch, /case FUTEX_CMP_REQUEUE_PI:\s*if \(futex_cmpxchg_enabled\)\s*ret = futex_requeue\([\s\S]*?;\s*else\s*ret = -ENOSYS;/,
    'CMP_REQUEUE_PI is unavailable without futex cmpxchg');

console.log('futex requeue-PI source contracts passed');