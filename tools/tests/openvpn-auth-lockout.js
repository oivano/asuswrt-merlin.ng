#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const sourcePath = path.join(__dirname, '../../release/src/router/openvpn/src/plugins/auth-pam/auth-pam.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const verifyStart = source.indexOf('case COMMAND_VERIFY:');
const verifyEnd = source.indexOf('case COMMAND_EXIT:', verifyStart);
assert(verifyStart >= 0 && verifyEnd > verifyStart, 'PAM verification event loop must exist');
const verifyCase = source.slice(verifyStart, verifyEnd);

assert.match(source, /#define AUTH_ATTEMPT_LIMIT 5/);
assert.match(source, /#define AUTH_ATTEMPT_WINDOW 300/);
assert.match(source, /#define AUTH_ATTEMPT_SOURCES 256/);
assert.match(source, /PLOG_WARN, MODULE/);
assert.match(source, /now - entry->last_attempt >= AUTH_ATTEMPT_WINDOW/);
assert.match(source, /available->last_attempt = now/);
assert.match(source, /inet_pton\(AF_INET, remote, &address4\)/);
assert.match(source, /inet_pton\(AF_INET6, remote, &address6\)/);
assert.match(source, /account && account->pw_uid == 0/);
assert(verifyCase.indexOf('remote_address_normalize') < verifyCase.indexOf('uid_zero_account'));
assert(verifyCase.indexOf('uid_zero_account') < verifyCase.indexOf('auth_attempt_blocked'));
assert(verifyCase.indexOf('auth_attempt_blocked') < verifyCase.indexOf('pam_auth(service, &up)'));
assert.match(verifyCase, /auth_attempt_failed\(up\.username, up\.remote\);\s*plugin_log\(PLOG_WARN, MODULE,\s*"OpenVPN password authentication failed from source %s"/);
assert.match(verifyCase, /auth_attempt_succeeded\(up\.username, up\.remote\)/);
assert.match(verifyCase, /auth_attempt_failed\(up\.username, up\.remote\);\s*do_deferred_pam_auth/);

class AttemptLimiter {
  constructor() {
    this.entries = new Map();
  }

  key(user, address) {
    return `${user}\n${address}`;
  }

  blocked(user, address, now) {
    const key = this.key(user, address);
    const entry = this.entries.get(key);
    if (entry && (now < entry.last || now - entry.last >= 300)) {
      this.entries.delete(key);
    }
    return (this.entries.get(key)?.attempts || 0) >= 5;
  }

  failed(user, address, now) {
    const key = this.key(user, address);
    const entry = this.entries.get(key) || { attempts: 0, last: now };
    entry.attempts = Math.min(5, entry.attempts + 1);
    entry.last = now;
    this.entries.set(key, entry);
  }

  succeeded(user, address) {
    this.entries.delete(this.key(user, address));
  }
}

const limiter = new AttemptLimiter();
for (let attempt = 0; attempt < 5; attempt++) {
  assert.strictEqual(limiter.blocked('vpn-user', '203.0.113.8', 100 + attempt), false);
  limiter.failed('vpn-user', '203.0.113.8', 100 + attempt);
}
assert.strictEqual(limiter.blocked('vpn-user', '203.0.113.8', 104), true, 'fifth failure starts cooldown');
assert.strictEqual(limiter.blocked('other-user', '203.0.113.8', 104), false, 'username is part of the key');
assert.strictEqual(limiter.blocked('vpn-user', '203.0.113.9', 104), false, 'source address is part of the key');
assert.strictEqual(limiter.blocked('vpn-user', '203.0.113.8', 404), false, 'cooldown expires after 300 seconds');
limiter.failed('vpn-user', '203.0.113.8', 405);
limiter.succeeded('vpn-user', '203.0.113.8');
assert.strictEqual(limiter.blocked('vpn-user', '203.0.113.8', 406), false, 'success clears the source/account state');

console.log('OpenVPN PAM source lockout contracts and policy model passed');