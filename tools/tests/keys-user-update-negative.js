const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const keysDir = 'release/src-rt-6.x.4708/linux/linux-2.6.36/security/keys';
const read = (name) => fs.readFileSync(path.join(root, keysDir, name), 'utf8');

const userDefined = read('user_defined.c');
const start = userDefined.indexOf('int user_update(struct key *key');
const end = userDefined.indexOf('} /* end user_update() */', start);
assert.ok(start >= 0 && end > start, 'user_update() present');
const body = userDefined.slice(start, end);

const displace = body.indexOf('zap = key->payload.data;');
const guarded = body.search(/if \(zap\)\s*call_rcu\(&zap->rcu, user_update_rcu_disposal\);/);
assert.ok(displace >= 0, 'old payload captured for disposal');
assert.ok(guarded > displace, 'RCU free is only scheduled when an old payload exists');
assert.equal((body.match(/call_rcu\(/g) || []).length, 1, 'no unguarded call_rcu remains');

// Preconditions from the report: negative keys carry NULL payload and may be updated.
const key = read('key.c');
assert.match(key, /key->payload\.data = NULL;/, 'key_alloc starts with NULL payload');
assert.match(key, /updating a negative key instantiates it/, '__key_update allows negative keys');

// Model the update outcomes (ret==0 displaces the old payload; failure frees the new one).
const update = (oldPayload, reserveOk) => {
    const upayload = { id: 'new' };
    let zap = upayload, payload = oldPayload;
    if (reserveOk) { zap = payload; payload = upayload; }
    const freed = zap ? zap : null;
    return { payload, freed };
};
assert.deepEqual(update(null, true), { payload: { id: 'new' }, freed: null },
    'negative key becomes positive with no NULL free');
assert.deepEqual(update({ id: 'old' }, true), { payload: { id: 'new' }, freed: { id: 'old' } },
    'positive key frees displaced payload');
assert.deepEqual(update(null, false), { payload: null, freed: { id: 'new' } },
    'quota failure frees the unused replacement');

console.log('PASS: user key update on negative key (source contract/model; not kernel execution)');
