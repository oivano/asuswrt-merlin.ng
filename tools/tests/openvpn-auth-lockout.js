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
const failedStart = source.indexOf('auth_attempt_failed(const char *username, const char *remote)');
const failedEnd = source.indexOf('\nstatic void\nauth_attempt_succeeded', failedStart);
assert(failedStart >= 0 && failedEnd > failedStart, 'failed-attempt accounting function must exist');
const failedBody = source.slice(failedStart, failedEnd);

assert.match(source, /#define AUTH_ATTEMPT_LIMIT 5/);
assert.match(source, /#define AUTH_ATTEMPT_WINDOW 300/);
assert.match(source, /#define AUTH_ATTEMPT_SOURCES 256/);
assert.match(source, /#define AUTH_ATTEMPT_PER_SOURCE 4/);
assert.match(source, /PLOG_WARN, MODULE/);
assert.match(source, /now - entry->last_attempt >= AUTH_ATTEMPT_WINDOW/);
assert.match(source, /available->last_attempt = now/);
assert.match(source, /auth_attempt_get\(username, remote, 0\)/);
assert.match(source, /source_entries < AUTH_ATTEMPT_PER_SOURCE/);
assert.match(source, /memset\(&address6\.s6_addr\[8\], 0, 8\)/,
  'IPv6 attempt keys aggregate each /64');
assert.match(source, /IN6_IS_ADDR_V4MAPPED\(&address6\)/,
  'IPv4-mapped IPv6 addresses retain per-IPv4-source keys');
assert.match(source, /int in_use;/);
assert.match(source, /entry->in_use\s*&&/,
  'empty usernames still occupy and expire tracking slots');
assert.match(source, /auth_attempt_prepare\(const char \*username, const char \*remote, int \*created\)/);
assert.match(source, /auth_attempt_release_reservation\(const char \*username, const char \*remote, int created\)/);
assert.match(failedBody, /auth_attempt_source_key\(remote, source, sizeof\(source\)\)/);
assert.match(failedBody, /!strcmp\(auth_attempts\[i\]\.remote, source\)/,
  'failure accounting counts the canonical source key');
assert.match(source, /inet_pton\(AF_INET, remote, &address4\)/);
assert.match(source, /inet_pton\(AF_INET6, remote, &address6\)/);
assert.match(source, /account && account->pw_uid == 0/);
assert(verifyCase.indexOf('remote_address_normalize') < verifyCase.indexOf('uid_zero_account'));
assert(verifyCase.indexOf('uid_zero_account') < verifyCase.indexOf('auth_attempt_blocked'));
assert(verifyCase.indexOf('auth_attempt_blocked') < verifyCase.indexOf('auth_attempt_prepare'));
assert(verifyCase.indexOf('auth_attempt_prepare') < verifyCase.indexOf('pam_auth(service, &up)'));
assert(verifyCase.indexOf('auth_attempt_prepare') < verifyCase.indexOf('do_deferred_pam_auth'));
assert(verifyCase.indexOf('do_deferred_pam_auth(fd, ac_file_name, service, &up)')
  < verifyCase.indexOf('auth_attempt_release_reservation'),
  'deferred auth releases only its new empty reservation after dispatch');
assert.match(verifyCase, /if \(!auth_attempt_prepare\(up\.username, up\.remote, &attempt_reserved\)\)[\s\S]*?RESPONSE_VERIFY_FAILED/,
  'untrackable authentication is refused before PAM');
assert.match(verifyCase, /auth_attempt_failed\(up\.username, up\.remote\);\s*plugin_log\(PLOG_WARN, MODULE,\s*"OpenVPN password authentication failed from source %s"/);
assert.match(verifyCase, /auth_attempt_succeeded\(up\.username, up\.remote\)/);
assert.doesNotMatch(verifyCase, /auth_attempt_failed\(up\.username, up\.remote\);\s*do_deferred_pam_auth/,
  'deferred PAM requests do not count as failures before PAM returns');

class AttemptLimiter {
  constructor() {
    this.entries = new Map();
  }

  key(user, address) {
    return `${user}\n${this.sourceKey(address).slice(7)}`;
  }

  sourceKey(address) {
    const mapped = address.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (mapped) {
      address = mapped[1];
    } else if (address.includes(':')) {
      address = `${address.split(':').slice(0, 4).join(':')}::`;
    }
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

  prepare(user, address, now) {
    const key = this.key(user, address);
    const sourceKey = this.sourceKey(address);
    let entry = this.entries.get(key);
    this.expire(key, now);
    this.expire(sourceKey, now);
    entry = this.entries.get(key);
    if (entry || this.entries.has(sourceKey)) {
      return true;
    }
    if (!entry) {
      const sourceEntries = [...this.entries.keys()].filter((item) => item.endsWith(`\n${sourceKey.slice(7)}`)
        && item !== sourceKey).length;
      const trackedKey = sourceEntries < 4 ? key : sourceKey;
      if (!this.entries.has(trackedKey) && this.entries.size >= 256) {
        return false;
      }
      this.entries.set(trackedKey, { attempts: 0, last: now });
    }
    return true;
  }

  failed(user, address, now) {
    const key = this.key(user, address);
    const sourceKey = this.sourceKey(address);
    let trackedKey = this.entries.has(key) ? key : sourceKey;
    const entry = this.entries.get(trackedKey);
    assert(entry, 'failed PAM attempt must have a reserved tracking slot');
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
  assert.strictEqual(limiter.prepare('vpn-user', '203.0.113.8', 100 + attempt), true);
  limiter.failed('vpn-user', '203.0.113.8', 100 + attempt);
}
assert.strictEqual(limiter.blocked('vpn-user', '203.0.113.8', 104), true, 'fifth failure starts cooldown');
assert.strictEqual(limiter.blocked('other-user', '203.0.113.8', 104), false, 'username is part of the key');
assert.strictEqual(limiter.blocked('vpn-user', '203.0.113.9', 104), false, 'source address is part of the key');
assert.strictEqual(limiter.blocked('vpn-user', '203.0.113.8', 404), false, 'cooldown expires after 300 seconds');
assert.strictEqual(limiter.prepare('vpn-user', '203.0.113.8', 405), true);
limiter.failed('vpn-user', '203.0.113.8', 405);
limiter.succeeded('vpn-user', '203.0.113.8');
assert.strictEqual(limiter.blocked('vpn-user', '203.0.113.8', 406), false, 'success clears the source/account state');

const sourceFlood = new AttemptLimiter();
assert.strictEqual(sourceFlood.blocked('first-user', '203.0.113.10', 100), false);
assert.strictEqual(sourceFlood.entries.size, 0, 'checking a login does not reserve a slot');
for (let attempt = 0; attempt < 256; attempt++) {
  const user = `bogus-${attempt}`;
  if (!sourceFlood.blocked(user, '203.0.113.10', 100)) {
    assert.strictEqual(sourceFlood.prepare(user, '203.0.113.10', 100), true);
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
  const address = `198.51.${Math.floor(attempt / 254)}.${(attempt % 254) + 1}`;
  assert.strictEqual(fullTable.prepare(`user-${attempt}`, address, 100), true);
  fullTable.failed(`user-${attempt}`, address, 100);
}
assert.strictEqual(fullTable.entries.size, 256, 'test fills the global tracking table');
let pamCalls = 0;
const untrackedAccepted = fullTable.prepare('legitimate-user', '203.0.113.20', 100);
if (untrackedAccepted) {
  pamCalls++;
}
assert.strictEqual(untrackedAccepted, false, 'a full table refuses an untracked source');
assert.strictEqual(pamCalls, 0, 'a full table refuses before PAM is dispatched');

const ipv6Flood = new AttemptLimiter();
for (let host = 1; host <= 64; host++) {
  const address = `2001:db8:1234:5678:0:0:0:${host.toString(16)}`;
  if (!ipv6Flood.blocked('', address, 100)) {
    assert.strictEqual(ipv6Flood.prepare('', address, 100), true);
    ipv6Flood.failed('', address, 100);
  }
  for (let user = 0; user < 12; user++) {
    if (!ipv6Flood.blocked(`user-${user}`, address, 100)) {
      assert.strictEqual(ipv6Flood.prepare(`user-${user}`, address, 100), true);
      ipv6Flood.failed(`user-${user}`, address, 100);
    }
  }
}
assert.strictEqual(ipv6Flood.entries.size, 5, 'addresses across one IPv6 /64 share at most five slots');
assert.strictEqual(ipv6Flood.blocked('new-user', '2001:db8:1234:5678:ffff:ffff:ffff:1', 100), true,
  'a new address in the /64 inherits the source-wide lockout');
assert.strictEqual(ipv6Flood.prepare('other-user', '2001:db8:1234:5679:0:0:0:1', 100), true,
  'a /64 flood leaves another prefix able to reserve tracking');
assert.strictEqual(ipv6Flood.sourceKey('::ffff:198.51.100.1'), 'source\n198.51.100.1');
assert.notStrictEqual(ipv6Flood.sourceKey('::ffff:198.51.100.1'),
  ipv6Flood.sourceKey('::ffff:198.51.100.2'), 'mapped IPv4 clients remain distinct sources');

console.log('OpenVPN PAM source lockout contracts and policy model passed');