const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const helperStart = services.indexOf('static int prepare_root_cache_dir(');
const helperEnd = services.indexOf('\n#ifdef RTCONFIG_QTN', helperStart);
const helper = services.slice(helperStart, helperEnd);
const start = services.slice(services.indexOf('void start_dnscrypt_proxy(void)'),
    services.indexOf('\nvoid stop_dnscrypt_proxy(void)'));

assert.ok(helperStart >= 0 && helperEnd > helperStart, 'cache directory helper exists');
assert.match(helper, /mkdir\(path, 0755\)/);
assert.match(helper, /open\(path, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(helper, /fchown\(fd, 0, 0\)/);
assert.match(helper, /fchmod\(fd, mode\)/);
assert.match(helper, /st\.st_uid == 0 && st\.st_gid == 0 && \(st\.st_mode & 07777\) == mode/);
assert.ok(!helper.includes('mkdir(path, 0777)'),
    'cache directory creation must not grant world write access');

const ntpCheck = start.indexOf('if (!nvram_get_int("ntp_ready"))');
const configDir = start.indexOf('secure_root_config_dir("/etc/dnscrypt-proxy")');
const defaultCache = start.indexOf('prepare_root_cache_dir(DNSCRYPT_CACHE_DIR, 0755)');
const legacyCache = start.indexOf('prepare_root_cache_dir(DNSCRYPT_LEGACY_CACHE_DIR, 0755)');
const configMode = start.indexOf('set_root_config_file_mode("/etc/dnscrypt-proxy", "dnscrypt-proxy.toml", 0644)');
const writableCache = start.indexOf('prepare_root_cache_dir(DNSCRYPT_CACHE_DIR, 01777)');
const writableLegacyCache = start.indexOf('prepare_root_cache_dir(DNSCRYPT_LEGACY_CACHE_DIR, 01777)');
const launch = start.indexOf('_eval(argv, NULL, 0, &pid)');
assert.ok(configDir >= 0 && defaultCache > configDir && legacyCache > defaultCache && ntpCheck > legacyCache,
    'the config and restrictive cache directories are repaired before any NTP early return');
assert.ok(configMode >= 0 && writableCache > configMode && writableLegacyCache > writableCache && launch > writableLegacyCache,
    'both root-owned sticky cache directories are enabled only after config security checks and before launch');
assert.ok(configDir < start.indexOf('open_root_config_file("/etc/dnscrypt-proxy"'),
    'the config directory is secured before its root-owned config is opened');
assert.ok(configDir < start.indexOf('stop_dnscrypt_proxy()'),
    'the config directory is secured before other startup work');

console.log('dnscrypt-cache-permissions: sticky cache permissions and startup ordering passed');
