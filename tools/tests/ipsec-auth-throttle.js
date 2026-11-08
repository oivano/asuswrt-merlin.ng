const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const manager = read('release/src/router/strongswan/src/libcharon/sa/ike_sa_manager.c');
const managerHeader = read('release/src/router/strongswan/src/libcharon/sa/ike_sa_manager.h');
const eap = read('release/src/router/strongswan/src/libcharon/plugins/eap_mschapv2/eap_mschapv2.c');
const xauth = read('release/src/router/strongswan/src/libcharon/plugins/xauth_generic/xauth_generic.c');

const constants = name => Number(manager.match(new RegExp(`#define ${name} (\\d+)`))[1]);
assert.equal(constants('AUTH_ATTEMPT_SOURCES'), 256);
assert.equal(constants('AUTH_ATTEMPT_LIMIT'), 5);
assert.equal(constants('AUTH_ATTEMPT_WINDOW'), 900);
assert.equal(constants('AUTH_ATTEMPT_COOLDOWN'), 300);
assert.match(manager, /auth_attempt_mutex = mutex_create\(MUTEX_TYPE_DEFAULT\)/);
assert.match(manager, /\.auth_attempt_allowed = _auth_attempt_allowed/);
assert.match(manager, /\.auth_attempt_failed = _auth_attempt_failed/);
assert.match(manager, /\.auth_attempt_succeeded = _auth_attempt_succeeded/);
assert.match(manager, /entry->source->ip_equals\(entry->source, source\)/);
assert.match(manager, /if \(entry->blocked_until > now\)\s*\{\s*continue;/,
    'active cooldowns must not be evicted under table pressure');
assert.match(manager, /allowed = entry != NULL;/,
    'new sources must fail closed when no non-blocked slot is available');
assert.match(manager, /time_monotonic\(NULL\)/);
assert.match(managerHeader, /auth_attempt_allowed/);

const bodyAfter = (source, marker) => {
    const start = source.indexOf(marker);
    assert.notEqual(start, -1, `missing ${marker}`);
    const open = source.indexOf('{', start);
    let depth = 0;
    for (let i = open; i < source.length; i++) {
        if (source[i] === '{') depth++;
        if (source[i] === '}' && --depth === 0) return source.slice(open + 1, i);
    }
    assert.fail(`unterminated function ${marker}`);
};

const eapCheck = bodyAfter(eap, 'static status_t process_server_response');
const xauthCheck = bodyAfter(xauth, 'METHOD(xauth_method_t, process_server, status_t');
for (const [name, body, credentialCheck] of [
    ['EAP-MSCHAPv2', eapCheck, 'get_nt_hash(this, this->server, userid, &nt_hash)'],
    ['XAuth', xauthCheck, 'create_shared_enumerator(lib->credmgr'],
]) {
    assert.ok(body.indexOf('auth_attempt_allowed') < body.indexOf(credentialCheck),
        `${name} gate must precede credential evaluation`);
    assert.match(body, /get_other_host\(ike_sa\)/, `${name} must key the remote source`);
    assert.match(body, /auth_attempt_failed/, `${name} must account for bad credentials`);
    assert.match(body, /auth_attempt_succeeded/, `${name} success must clear failures`);
}

const limit = constants('AUTH_ATTEMPT_LIMIT');
const windowSeconds = constants('AUTH_ATTEMPT_WINDOW');
const cooldownSeconds = constants('AUTH_ATTEMPT_COOLDOWN');
const records = new Map();
const allowed = (source, now) => (records.get(source)?.blockedUntil ?? 0) <= now;
const failed = (source, now) => {
    let record = records.get(source);
    if (!record || now - record.firstFailure >= windowSeconds) {
        record = { firstFailure: now, failures: 0, blockedUntil: 0 };
        records.set(source, record);
    }
    if (record.blockedUntil <= now && ++record.failures >= limit) {
        record.blockedUntil = now + cooldownSeconds;
    }
};
const succeeded = source => records.delete(source);

for (let attempt = 0; attempt < limit; attempt++) {
    assert.equal(allowed('198.51.100.10', 100), true, 'initial credential checks proceed');
    failed('198.51.100.10', 100 + attempt);
}
assert.equal(allowed('198.51.100.10', 110), false,
    'new IKE_SA from the same source is rejected before credential evaluation');
assert.equal(allowed('198.51.100.11', 110), true, 'another source remains independent');
assert.equal(allowed('198.51.100.10', 404), true, 'cooldown expiry allows attempts again');
succeeded('198.51.100.10');
assert.equal(allowed('198.51.100.10', 405), true, 'success clears the source record');

console.log('IPsec auth throttle source contracts and policy model passed (not compiled C or live IKE).');