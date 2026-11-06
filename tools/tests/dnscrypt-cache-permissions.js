const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const helperStart = services.indexOf('static int prepare_writable_cache_dir(');
const helperEnd = services.indexOf('\n#ifdef RTCONFIG_QTN', helperStart);
const helper = services.slice(helperStart, helperEnd);
const start = services.slice(services.indexOf('void start_dnscrypt_proxy(void)'),
    services.indexOf('\nvoid stop_dnscrypt_proxy(void)'));

assert.ok(helperStart >= 0 && helperEnd > helperStart, 'cache directory helper exists');
assert.match(helper, /mkdir\(path, 0777\)/);
assert.match(helper, /open\(path, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(helper, /fchown\(fd, 0, 0\)/);
assert.match(helper, /fchmod\(fd, 0777\)/);

const postconf = start.indexOf('run_postconf("dnscrypt-proxy", DNSCRYPT_CONFIG)');
const defaultCache = start.indexOf('prepare_writable_cache_dir(DNSCRYPT_CACHE_DIR)');
const legacyCache = start.indexOf('prepare_writable_cache_dir(DNSCRYPT_LEGACY_CACHE_DIR)');
const launch = start.indexOf('_eval(argv, NULL, 0, &pid)');
assert.ok(postconf >= 0 && defaultCache > postconf && legacyCache > postconf,
    'postconf runs before both cache directories are repaired');
assert.ok(defaultCache < launch && legacyCache < launch,
    'both cache directories are repaired before dnscrypt-proxy starts');

console.log('dnscrypt-cache-permissions: startup ordering and writable-directory contracts passed');
