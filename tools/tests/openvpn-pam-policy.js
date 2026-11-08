#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const router = path.join(__dirname, '../../release/src/router');
const dispatch = fs.readFileSync(path.join(router, 'openpam/lib/libpam/openpam_dispatch.c'), 'utf8');
const services = fs.readFileSync(path.join(router, 'rc/services.c'), 'utf8');

function functionBody(source, signature, nextSignature) {
    const start = source.indexOf(signature);
    const end = source.indexOf(nextSignature, start);
    assert(start >= 0 && end > start, `expected function ${signature}`);
    return source.slice(start, end);
}

const dispatchBody = functionBody(dispatch, 'openpam_dispatch(pam_handle_t *pamh,', '\n#if !defined(OPENPAM_RELAX_CHECKS)');
const policyWriter = functionBody(services, 'write_openvpn_pam_policy(void)', '\nvoid create_passwd(void)');

assert.match(dispatchBody, /int success;/);
assert.match(dispatchBody, /for \(err = fail = success = 0;/);
assert.match(dispatchBody, /if \(r == PAM_SUCCESS\) \{\s*success = 1;/);
assert.match(dispatchBody, /\(primitive == PAM_SM_AUTHENTICATE \|\| primitive == PAM_SM_ACCT_MGMT\)[\s\S]*?!success && err == PAM_SUCCESS[\s\S]*?err = PAM_PERM_DENIED;/,
    'authentication and account checks deny when no module succeeds');

assert.match(policyWriter, /mkstemp\(temp_path\)/);
assert.match(policyWriter, /fchmod\(fd, 0644\)/);
assert.match(policyWriter, /while \(written < sizeof\(policy\) - 1\)/);
assert.match(policyWriter, /rename\(temp_path, "\/etc\/pam\.d\/openvpn"\)/);
assert.doesNotMatch(policyWriter, /f_write_excl|unlink\("\/etc\/pam\.d\/openvpn"\)/,
    'policy replacement does not remove the live file or contend on the global lock');
assert.match(services, /if \(write_openvpn_pam_policy\(\) != 0\)[\s\S]*?unable to atomically write/);

function evaluateAuthChain(results) {
    let error = 0;
    let failedRequired = false;
    let succeeded = false;
    for (const result of results) {
        if (result === 'ignore') continue;
        if (result === 'success') {
            succeeded = true;
            continue;
        }
        if (!error) error = 'module-error';
        if (result === 'required-failure') failedRequired = true;
    }
    if (!failedRequired) error = 0;
    if (!succeeded && error === 0) error = 'PAM_PERM_DENIED';
    return error || 'PAM_SUCCESS';
}

assert.strictEqual(evaluateAuthChain([]), 'PAM_PERM_DENIED', 'an empty policy is denied');
assert.strictEqual(evaluateAuthChain(['ignore']), 'PAM_PERM_DENIED', 'an all-ignored chain is denied');
assert.strictEqual(evaluateAuthChain(['optional-failure']), 'PAM_PERM_DENIED',
    'a chain with no successful module is denied');
assert.strictEqual(evaluateAuthChain(['success']), 'PAM_SUCCESS', 'a successful PAM module still authenticates');
assert.strictEqual(evaluateAuthChain(['required-failure', 'success']), 'module-error',
    'a later success does not erase an earlier required failure');

console.log('OpenVPN PAM fail-closed policy contracts and dispatch cases passed');