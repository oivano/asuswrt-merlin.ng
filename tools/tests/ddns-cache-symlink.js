const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const services = read('release/src/router/rc/services.c');
const watchdog = read('release/src/router/rc/watchdog.c');
const header = read('release/src/router/rc/rc.h');
const helpers = services.slice(services.indexOf('#define DDNS_CACHE_DIR'), services.indexOf('\nint\nddns_updated_main'));

assert.match(helpers, /#define DDNS_CACHE_DIR "\/tmp\/ddns-private"/);
assert.match(helpers, /mkdir\(DDNS_CACHE_DIR, 0700\)/);
assert.match(helpers, /open\(DDNS_CACHE_DIR, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(helpers, /S_ISDIR\(st\.st_mode\).*st\.st_uid != 0/);
assert.match(helpers, /st\.st_gid != 0.*fchmod\(fd, 0700\)/);
assert.match(helpers, /O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW \| O_NONBLOCK, 0600/);
assert.match(helpers, /O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK/);
assert.match(helpers, /S_ISREG\(st\.st_mode\).*st\.st_uid != 0/);
assert.match(helpers, /st\.st_nlink != 1/);
assert.match(services, /ddns_cache_open\(0\)/);
assert.match(services, /ddns_cache_open\(1\)/);
assert.match(services, /ddns_cache_clear\(\);/);
assert.match(services, /"%s", DDNS_CACHE_PATH/);
assert.match(header, /extern int ddns_cache_clear\(void\);/);
assert.doesNotMatch(services, /fopen\("\/tmp\/ddns\.cache"/);
assert.doesNotMatch(watchdog, /unlink\("\/tmp\/ddns\.cache"\)/);
assert.equal((watchdog.match(/ddns_cache_clear\(\);/g) || []).length, 2);

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ddns-cache-'));
const privateDirectory = path.join(directory, 'ddns-private');
const victim = path.join(directory, 'victim');
const cache = path.join(privateDirectory, 'ddns.cache');
try {
    fs.mkdirSync(privateDirectory, 0o700);
    fs.writeFileSync(victim, 'preserve');
    fs.symlinkSync(victim, cache);
    const descriptor = fs.openSync(cache, fs.constants.O_WRONLY | fs.constants.O_CREAT |
        fs.constants.O_EXCL | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
    assert.fail(`exclusive no-follow creation unexpectedly opened planted link: ${descriptor}`);
} catch (error) {
    assert.equal(error.code, 'EEXIST');
    assert.equal(fs.readFileSync(victim, 'utf8'), 'preserve');
} finally {
    fs.rmSync(directory, { recursive: true, force: true });
}

console.log('DDNS cache symlink containment checks passed');