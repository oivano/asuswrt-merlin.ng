const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const common = read('release/src/router/rc/common.c');
const init = read('release/src/router/rc/init.c');
const services = read('release/src/router/rc/services.c');
const checkWatchdog = read('release/src/router/rc/check_watchdog.c');
const watchdog = read('release/src/router/rc/watchdog.c');

assert.match(common, /open\("\/tmp\/ppp", O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(common, /S_ISDIR\(st\.st_mode\) \|\| st\.st_uid != 0 \|\|\s*\(st\.st_mode & 0022\)/);
assert.match(common, /openat\(dirfd, name, O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK\)/);
assert.match(common, /S_ISREG\(st\.st_mode\) && st\.st_uid == 0 &&\s*st\.st_nlink == 1 && !\(st\.st_mode & 0077\)/);
assert.match(common, /openat\(dirfd, name,[\s\S]*O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW \| O_NONBLOCK, 0600\)/);
assert.match(common, /rc_upgrade_flag_set\(void\)[\s\S]*rc_private_flag_set\("upgrade"\)/);
assert.match(common, /rc_upgrade_flag_is_set\(void\)[\s\S]*rc_private_flag_is_set\("upgrade"\)/);
assert.ok(init.includes('"/tmp/ppp"'));
assert.equal((services.match(/rc_upgrade_flag_set\(\)/g) || []).length, 2);
assert.equal((checkWatchdog.match(/rc_upgrade_flag_is_set\(\)/g) || []).length, 1);
assert.equal((watchdog.match(/rc_upgrade_flag_is_set\(\)/g) || []).length, 4);
for (const source of [services, checkWatchdog, watchdog])
    assert.doesNotMatch(source, /\/tmp\/upgrade/);

function privateFlagIsSet(directory, owner = process.getuid()) {
    let fd = -1;
    try {
        fd = fs.openSync(path.join(directory, 'upgrade'),
            fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
        const stat = fs.fstatSync(fd);
        if (!stat.isFile() || stat.uid !== owner || stat.nlink !== 1 || (stat.mode & 0o077))
            return false;
        const value = Buffer.alloc(2);
        return fs.readSync(fd, value, 0, value.length, 0) === 1 && value[0] === 0x31;
    } catch (error) {
        if (['ENOENT', 'ELOOP', 'ENXIO'].includes(error.code))
            return false;
        throw error;
    } finally {
        if (fd >= 0)
            fs.closeSync(fd);
    }
}

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'upgrade-watchdog-'));
const privateDirectory = path.join(temporary, 'ppp');
const attackerFlag = path.join(temporary, 'upgrade');
try {
    fs.chmodSync(temporary, 0o1777);
    fs.mkdirSync(privateDirectory, { mode: 0o755 });
    fs.chmodSync(privateDirectory, 0o755);
    if (process.getuid() === 0) {
        const createAsNobody = spawnSync(process.execPath, ['-e', `
            require('node:fs').writeFileSync(${JSON.stringify(attackerFlag)}, '1');
        `], { uid: 65534, gid: 65534, encoding: 'utf8' });
        assert.ifError(createAsNobody.error);
        assert.equal(createAsNobody.status, 0, createAsNobody.stderr);
        const createPrivateAsNobody = spawnSync(process.execPath, ['-e', `
            require('node:fs').writeFileSync(${JSON.stringify(path.join(privateDirectory, 'upgrade'))}, '1');
        `], { uid: 65534, gid: 65534, encoding: 'utf8' });
        assert.notEqual(createPrivateAsNobody.status, 0, 'nobody cannot create the private marker');
    } else {
        fs.writeFileSync(attackerFlag, '1');
    }
    assert.equal(privateFlagIsSet(privateDirectory), false,
        'an unprivileged /tmp/upgrade is outside the trusted flag directory');

    const marker = path.join(privateDirectory, 'upgrade');
    fs.writeFileSync(marker, '1', { mode: 0o600 });
    fs.chmodSync(marker, 0o600);
    assert.equal(privateFlagIsSet(privateDirectory), true, 'valid private marker is recognized');
    fs.unlinkSync(marker);
    fs.symlinkSync(attackerFlag, marker);
    assert.equal(privateFlagIsSet(privateDirectory), false, 'symlink marker is ignored');
    assert.throws(() => fs.openSync(marker,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600), { code: 'EEXIST' });
    assert.equal(fs.readFileSync(attackerFlag, 'utf8'), '1', 'writer flags preserve symlink target');
    fs.unlinkSync(marker);

    const fifo = spawnSync('mkfifo', [marker], { encoding: 'utf8' });
    assert.ifError(fifo.error);
    assert.equal(fifo.status, 0, fifo.stderr);
    assert.equal(privateFlagIsSet(privateDirectory), false, 'FIFO marker is ignored without blocking');
    if (process.getuid() === 0)
        console.log('PASS: nobody cannot create the marker; file, symlink, and FIFO are safely handled');
    else
        console.log('PASS: file, symlink, and FIFO are safely handled (nobody write denial requires root)');
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}