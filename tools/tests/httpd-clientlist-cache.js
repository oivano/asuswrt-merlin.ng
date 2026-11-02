const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const httpd = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.c'), 'utf8');
const header = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.h'), 'utf8');

assert.match(web, /#define NMP_CACHE_FILE\s+"\/tmp\/httpd\/nmp_cache\.js"/);
assert.doesNotMatch(web, /#define NMP_CACHE_FILE\s+"\/tmp\/nmp_cache\.js"/);
assert.match(httpd, /int httpd_ensure_temp_dir\(void\)[\s\S]*?lstat\(directory, &st\)[\s\S]*?st\.st_uid != 0[\s\S]*?\(st\.st_mode & 0777\) != 0700/);
assert.match(header, /extern int httpd_ensure_temp_dir\(void\);/);

const hook = web.slice(web.indexOf('static int ej_get_clientlist('), web.indexOf('// for detect static IP'));
assert.match(hook, /httpd_ensure_temp_dir\(\) == 0[\s\S]*?open\(NMP_CACHE_FILE, O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK\)/);
assert.match(hook, /fstat\(fd, &st\) == 0 && S_ISREG\(st\.st_mode\) && st\.st_uid == 0 &&\s*st\.st_nlink == 1/);
assert.match(hook, /json_object_from_fd\(fd\)/);
assert.match(hook, /httpd_create_tempfile\(cache_tmp, sizeof\(cache_tmp\)\)[\s\S]*?json_object_to_file\(cache_tmp, clients\)[\s\S]*?rename\(cache_tmp, NMP_CACHE_FILE\)/);
assert.doesNotMatch(hook, /json_object_from_file\(NMP_CACHE_FILE\)|json_object_to_file\(NMP_CACHE_FILE/);

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'httpd-client-cache-'));
const privateDir = path.join(temp, 'httpd');
const cache = path.join(privateDir, 'nmp_cache.js');
const victim = path.join(temp, 'victim');
const planted = path.join(temp, 'nmp_cache.js');
try {
    fs.mkdirSync(privateDir, { mode: 0o700 });
    fs.writeFileSync(victim, 'untouched');
    fs.symlinkSync(victim, planted);
    const temporary = path.join(privateDir, 'output-random');
    const fd = fs.openSync(temporary, fs.constants.O_WRONLY | fs.constants.O_CREAT |
        fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
    fs.writeFileSync(fd, '{"maclist":[]}');
    fs.closeSync(fd);
    fs.renameSync(temporary, cache);
    assert.equal(fs.readFileSync(victim, 'utf8'), 'untouched');
    assert.deepEqual(JSON.parse(fs.readFileSync(cache, 'utf8')), { maclist: [] });
    assert.equal(fs.statSync(privateDir).mode & 0o777, 0o700);

    for (const kind of ['symlink', 'fifo', 'regular']) {
        fs.unlinkSync(cache);
        const outside = path.join(temp, `outside-${kind}`);
        fs.writeFileSync(outside, 'untouched');
        if (kind === 'symlink') fs.symlinkSync(outside, cache);
        else if (kind === 'fifo') execFileSync('mkfifo', [cache]);
        else fs.writeFileSync(cache, 'attacker data', { mode: 0o600 });
        let opened;
        let rejected = false;
        try {
            opened = fs.openSync(cache, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW |
                fs.constants.O_NONBLOCK);
            const stat = fs.fstatSync(opened);
            const owner = kind === 'regular' ? 65534 : (stat.uid === process.getuid() ? 0 : stat.uid);
            rejected = (stat.mode & 0o170000) !== 0o100000 || owner !== 0 || stat.nlink !== 1 ||
                (stat.mode & 0o077) !== 0;
        } catch (error) {
            assert.equal(error.code, 'ELOOP', `${kind}: ${error.code}`);
            rejected = true;
        } finally {
            if (opened !== undefined) fs.closeSync(opened);
        }
        assert(rejected, `${kind} cache entries are rejected`);
        assert.equal(fs.readFileSync(outside, 'utf8'), 'untouched');
    }
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}

console.log('httpd client-list cache containment checks passed');