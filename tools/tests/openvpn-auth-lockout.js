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
assert.match(source, /#define AUTH_ATTEMPT_PER_SOURCE 4/);
assert.match(source, /PLOG_WARN, MODULE/);
assert.match(source, /now - entry->last_attempt >= AUTH_ATTEMPT_WINDOW/);
assert.match(source, /available->last_attempt = now/);
assert.match(source, /auth_attempt_get\(username, remote, 0\)/);
assert.match(source, /source_entries < AUTH_ATTEMPT_PER_SOURCE/);
assert.match(source, /inet_pton\(AF_INET, remote, &address4\)/);
assert.match(source, /inet_pton\(AF_INET6, remote, &address6\)/);
assert.match(source, /account && account->pw_uid == 0/);
assert(verifyCase.indexOf('remote_address_normalize') < verifyCase.indexOf('uid_zero_account'));
assert(verifyCase.indexOf('uid_zero_account') < verifyCase.indexOf('auth_attempt_blocked'));
assert(verifyCase.indexOf('auth_attempt_blocked') < verifyCase.indexOf('pam_auth(service, &up)'));
assert.match(verifyCase, /auth_attempt_failed\(up\.username, up\.remote\);\s*plugin_log\(PLOG_WARN, MODULE,\s*"OpenVPN password authentication failed from source %s"/);
assert.match(verifyCase, /auth_attempt_succeeded\(up\.username, up\.remote\)/);
assert.doesNotMatch(verifyCase, /auth_attempt_failed\(up\.username, up\.remote\);\s*do_deferred_pam_auth/,
  'deferred PAM requests do not count as failures before PAM returns');

class AttemptLimiter {
  constructor() {
    this.entries = new Map();
  }

  key(user, address) {
    return `${user}\n${address}`;
  }

  sourceKey(address) {
    return `source\n${address}`;
  }

  expire(key, now) {
    const entry = this.entries.get(key);
    if (entry && (now < entry.last || now - entry.last >= 300)) {
      this.entries.delete(key);
    }
  }

  blocked(user, address, now) {
    const key = this.key(user, address);
    const sourceKey = this.sourceKey(address);
    this.expire(key, now);
    this.expire(sourceKey, now);
    return (this.entries.get(key)?.attempts || this.entries.get(sourceKey)?.attempts || 0) >= 5;
  }

  failed(user, address, now) {
    const key = this.key(user, address);
    const sourceKey = this.sourceKey(address);
    let trackedKey = key;
    let entry = this.entries.get(key);
    if (!entry) {
      const sourceEntries = [...this.entries.keys()].filter((item) => item.endsWith(`\n${address}`)
        && item !== sourceKey).length;
      trackedKey = sourceEntries < 4 ? key : sourceKey;
      entry = this.entries.get(trackedKey);
    }
    if (!entry && this.entries.size >= 256) {
      return;
    }
    entry ||= { attempts: 0, last: now };
    entry.attempts = Math.min(5, entry.attempts + 1);
    entry.last = now;
    this.entries.set(trackedKey, entry);
  }

  succeeded(user, address) {
    const key = this.key(user, address);
    const sourceKey = this.sourceKey(address);
    if (this.entries.has(key)) {
      this.entries.delete(key);
    } else {
      this.entries.delete(sourceKey);
    }
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

const sourceFlood = new AttemptLimiter();
assert.strictEqual(sourceFlood.blocked('first-user', '203.0.113.10', 100), false);
assert.strictEqual(sourceFlood.entries.size, 0, 'checking a login does not reserve a slot');
for (let attempt = 0; attempt < 256; attempt++) {
  const user = `bogus-${attempt}`;
  if (!sourceFlood.blocked(user, '203.0.113.10', 100)) {
    sourceFlood.failed(user, '203.0.113.10', 100);
  }
}
assert(sourceFlood.entries.size <= 5, 'one source is limited to four account entries and one aggregate entry');
assert.strictEqual(sourceFlood.blocked('another-bogus-user', '203.0.113.10', 100), true,
  'the aggregate source bucket enforces its own failure limit');
assert.strictEqual(sourceFlood.blocked('another-bogus-user', '203.0.113.10', 400), false,
  'the aggregate source cooldown expires after 300 seconds');
assert.strictEqual(sourceFlood.blocked('valid-user', '203.0.113.11', 100), false,
  'a source flood does not block another address');

const fullTable = new AttemptLimiter();
for (let attempt = 0; attempt < 256; attempt++) {
  const address = `198.51.100.${attempt + 1}`;
  fullTable.failed(`user-${attempt}`, address, 100);
}
assert.strictEqual(fullTable.entries.size, 256, 'test fills the global tracking table');
assert.strictEqual(fullTable.blocked('legitimate-user', '203.0.113.20', 100), false,
  'table exhaustion alone does not block an untracked pair');

console.log('OpenVPN PAM source lockout contracts and policy model passed');