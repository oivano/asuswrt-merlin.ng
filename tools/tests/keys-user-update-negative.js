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

const keyctl = read('keyctl.c');
const readStart = keyctl.indexOf('long keyctl_read_key(');
const readEnd = keyctl.indexOf('} /* end keyctl_read_key() */', readStart);
assert.ok(readStart >= 0 && readEnd > readStart, 'keyctl_read_key() present');
const readBody = keyctl.slice(readStart, readEnd);
const readPath = readBody.slice(readBody.indexOf('can_read_key:'), readBody.indexOf('error2:'));
const lock = readPath.indexOf('down_read(&key->sem);');
const validate = readPath.indexOf('key_validate(key)');
const readCall = readPath.indexOf('key->type->read(key, buffer, buflen)');
const unlock = readPath.indexOf('up_read(&key->sem);');
assert.ok(lock >= 0 && lock < validate, 'key semaphore acquired before validation');
assert.ok(validate < readCall && readCall < unlock,
    'validation and type read share the read lock');
assert.match(readPath,
    /if \(ret == 0\) \{[\s\S]*?ret = key->type->read\(key, buffer, buflen\);/,
    'type read only runs after successful validation');

const permission = read('permission.c');
assert.match(permission, /ret = -EKEYREVOKED;[\s\S]*KEY_FLAG_REVOKED/,
    'revoked keys fail validation with -EKEYREVOKED');

console.log('PASS: user key payload lifecycle and revoke/read locking (source contract/model; not kernel execution)');
