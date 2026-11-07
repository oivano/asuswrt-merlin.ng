#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const sourcePath = path.join(__dirname, '../../release/src/router/openvpn/src/openvpn/multi.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const helperStart = source.indexOf('multi_float_identity_matches(');
const helperEnd = source.indexOf('\nstatic void\nmulti_process_float', helperStart);
assert(helperStart >= 0 && helperEnd > helperStart, 'float identity helper must exist');
const helper = source.slice(helperStart, helperEnd);
const floatStart = source.indexOf('multi_process_float(struct multi_context');
const floatEnd = source.indexOf('\nstatic ', floatStart);
assert(floatStart >= 0 && floatEnd > floatStart, 'float handler must exist');
const floatHandler = source.slice(floatStart, floatEnd);

assert.match(helper, /tls_username\(m1, true\)/);
assert.match(helper, /tls_username\(m2, true\)/);
assert.match(helper, /cert_hash_compare\(m1->locked_cert_hash_set, m2->locked_cert_hash_set\)/);
assert.match(helper, /strcmp\(username1, username2\) == 0/);
assert.match(helper, /if \(!m1->locked_cert_hash_set \|\| !m2->locked_cert_hash_set\)/);
assert.match(helper, /m1->locked_cert_hash_set->ch\[i\]/);
assert.match(floatHandler, /if \(!multi_float_identity_matches\(m1, m2\)\)/);
assert.match(floatHandler, /multi_close_instance\(m, ex_mi, false\)/);

function identityMatches({ cert1, cert2, username1, username2 }) {
    if (cert1 !== cert2) {
        return false;
    }
    if (username1 || username2) {
        return Boolean(username1 && username2 && username1 === username2);
    }
    return Boolean(cert1);
}

assert.strictEqual(identityMatches({ cert1: 'shared', cert2: 'shared', username1: 'alice', username2: 'bob' }),
    false, 'a shared certificate cannot make different usernames the same identity');
assert.strictEqual(identityMatches({ cert1: null, cert2: null, username1: 'alice', username2: 'bob' }),
    false, 'username-authenticated clients without certificates remain distinct');
assert.strictEqual(identityMatches({ cert1: null, cert2: null, username1: 'alice', username2: 'alice' }),
    true, 'the same username may float when client certificates are disabled');
assert.strictEqual(identityMatches({ cert1: 'same-cert', cert2: 'same-cert', username1: null, username2: null }),
    true, 'certificate-only clients retain same-certificate roaming');
assert.strictEqual(identityMatches({ cert1: null, cert2: null, username1: null, username2: null }),
    false, 'sessions with no certificate or authenticated username have no collision identity');
assert.strictEqual(identityMatches({ cert1: 'cert-a', cert2: 'cert-b', username1: 'alice', username2: 'alice' }),
    false, 'different certificates remain distinct even with the same username');