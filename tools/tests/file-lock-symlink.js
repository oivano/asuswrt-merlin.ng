const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const files = read('release/src/router/shared/files.c');
const shared = read('release/src/router/shared/shared.h');
const init = read('release/src/router/rc/init.c');
const monitor = read('release/src/router/lighttpd-1.4.39/src/lighttpd-monitor.c');
const functionBody = (source, signature) => {
    const start = source.indexOf(signature);
    assert.notEqual(start, -1, `${signature} exists`);
    const open = source.indexOf('{', start);
    let depth = 1;
    for (let cursor = open + 1; cursor < source.length; cursor++) {
        if (source[cursor] === '{') depth++;
        if (source[cursor] === '}' && --depth === 0) return source.slice(open + 1, cursor);
    }
    assert.fail(`${signature} body is closed`);
};

const lock = functionBody(files, 'int _file_lock(');
assert.match(lock, /open\(path, O_CREAT \| O_RDWR \| O_NOFOLLOW, 0600\)/);
assert.match(lock, /fstat\(lockfd, &st\).*S_ISREG\(st\.st_mode\).*st\.st_uid != geteuid\(\).*st\.st_nlink != 1/s);
assert.ok(lock.indexOf('fstat(lockfd, &st)') < lock.indexOf('write(lockfd, &pid, sizeof(pid_t))'));

const actionDir = functionBody(files, 'static int action_lock_dir_open(void)\n{');
assert.match(actionDir, /mkdir\(ACTION_LOCK_DIR, 0700\)/);
assert.match(actionDir, /open\(ACTION_LOCK_DIR, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(actionDir, /S_ISDIR\(st\.st_mode\).*st\.st_uid != 0.*st\.st_mode & 0077/s);
const actionOpen = functionBody(files, 'static int action_file_open(int dirfd, int flags, mode_t mode)\n{');
assert.match(actionOpen, /openat\(dirfd, "action", flags \| O_NOFOLLOW \| O_NONBLOCK, mode\)/);
assert.match(actionOpen, /S_ISREG\(st\.st_mode\).*st\.st_uid != 0.*st\.st_nlink != 1/s);
const actionWrite = functionBody(files, 'static int action_write_excl(const char *path, const void *buffer, int len, unsigned flags, unsigned cmode)\n{');
assert.match(actionWrite, /openat\(dirfd, "a_w_l", O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW/);
assert.match(actionWrite, /action_file_open\(dirfd, O_WRONLY \| O_CREAT/);
assert.ok(actionWrite.indexOf('action_file_open(') < actionWrite.indexOf('ftruncate(f, 0)'));
assert.match(shared, /#define ACTION_LOCK_DIR\s+"\/var\/lock\/asuswrt"/);
assert.match(shared, /#define ACTION_LOCK\s+ACTION_LOCK_DIR "\/action"/);
assert.match(shared, /#define ACTION_LOCK_FILE ACTION_LOCK_DIR "\/a_w_l"/);
assert.match(init, /mkdir\("\/var\/lock", 01777\);\s*if \(file_lock_init\(\) < 0\)/);
assert.match(monitor, /\/var\/lock\/asuswrt\/action/);
assert.doesNotMatch(files, /open\(ACTION_LOCK_FILE, O_WRONLY\|O_CREAT\|O_EXCL\|O_TRUNC/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'file-lock-symlink-'));
try {
    const publicDir = path.join(temporary, 'lock');
    const privateDir = path.join(publicDir, 'asuswrt');
    const target = path.join(temporary, 'target');
    fs.mkdirSync(publicDir, { mode: 0o1777 });
    fs.chmodSync(publicDir, 0o1777);
    fs.writeFileSync(target, 'protected target');
    for (const name of ['nvramcommit.lock', 'resolv.lock', 'action'])
        fs.symlinkSync(target, path.join(publicDir, name));

    for (const name of ['nvramcommit.lock', 'resolv.lock', 'action']) {
        assert.throws(() => fs.openSync(path.join(publicDir, name), fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW),
            { code: 'ELOOP' }, `${name} symlink is rejected by O_NOFOLLOW`);
    }
    assert.equal(fs.readFileSync(target, 'utf8'), 'protected target');

    fs.mkdirSync(privateDir, { mode: 0o700 });
    fs.writeFileSync(path.join(privateDir, 'action'), 'private state');
    assert.equal(fs.readFileSync(path.join(privateDir, 'action'), 'utf8'), 'private state');
    assert.equal(fs.readFileSync(target, 'utf8'), 'protected target');

    if (process.getuid && process.getuid() === 0) {
        const denied = spawnSync(process.execPath, ['-e', `
            const fs = require('node:fs');
            try { fs.writeFileSync(${JSON.stringify(path.join(privateDir, 'planted'))}, 'x'); process.exit(1); }
            catch (error) { if (error.code !== 'EACCES' && error.code !== 'EPERM') throw error; }
        `], { uid: 65534, gid: 65534, encoding: 'utf8' });
        assert.ifError(denied.error);
        assert.equal(denied.status, 0, denied.stderr);
    }
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}

console.log('PASS: shared locks reject unsafe descriptors; action state uses a validated private directory');