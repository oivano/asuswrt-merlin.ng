const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/rc/auth.c'), 'utf8');
const helperStart = source.indexOf('static FILE *\nwpa_supplicant_options_open(');
const helperEnd = source.indexOf('\nstatic int\nstart_wpa_supplicant', helperStart);
assert.ok(helperStart >= 0 && helperEnd > helperStart);
const helper = source.slice(helperStart, helperEnd);
const start = source.slice(helperEnd, source.indexOf('\nstatic int\nstop_wpa_supplicant', helperEnd));
assert.match(source, /#include <fcntl\.h>/);
assert.match(helper, /unlink\(path\)[\s\S]*O_CREAT \| O_EXCL \| O_NOFOLLOW, 0600/);
assert.ok(helper.indexOf('fchown(') < helper.indexOf('fchmod('));
assert.ok(helper.indexOf('fchmod(') < helper.indexOf('fdopen('));
assert.match(start, /wpa_supplicant_options_open\(options\)/);
assert.doesNotMatch(start, /fopen\(options,/);

const body = helper.slice(helper.indexOf('{') + 1, helper.lastIndexOf('}'))
    .replace('struct stat st;', 'let st = {};')
    .replace('int descriptor, saved_errno;', 'let descriptor, saved_errno;')
    .replace('FILE *stream;', 'let stream;')
    .replaceAll('NULL', 'null')
    .replaceAll('0600', '0o600')
    .replaceAll('&st', 'st');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'wan-auth-permissions-'));
const filename = path.join(temporary, 'wpa_supplicant-wan0.conf');
const sentinel = path.join(temporary, 'sentinel');
let failure = '';
let fallbackFailure = '';
let unlinkFailedOnce = false;
let race = false;
let checks = 0;
const context = {
    ...fs.constants,
    ENOENT: 'ENOENT',
    errno: null,
    S_ISREG: mode => (mode & fs.constants.S_IFMT) === fs.constants.S_IFREG,
    unlink: name => {
        if (failure === 'unlink' && !unlinkFailedOnce) {
            unlinkFailedOnce = true;
            context.errno = 'EACCES';
            return -1;
        }
        try { fs.unlinkSync(filename); return 0; }
        catch (error) { context.errno = error.code; return -1; }
    },
    open: (name, flags, mode) => {
        if (race) {
            race = false;
            fs.symlinkSync(sentinel, filename);
        }
        if (failure === 'open') return -1;
        try { return fs.openSync(filename, flags, mode); } catch { return -1; }
    },
    fchown: (descriptor, uid, gid) => {
        assert.equal(uid, 0);
        assert.equal(gid, 0);
        return failure === 'fchown' || fallbackFailure === 'fchown' ? -1 : 0;
    },
    fstat: (descriptor, st) => {
        try {
            const info = fs.fstatSync(descriptor);
            Object.assign(st, { st_mode: info.mode, st_nlink: info.nlink });
            return 0;
        } catch { return -1; }
    },
    fchmod: (descriptor, mode) => {
        if (failure === 'fchmod' || fallbackFailure === 'fchmod') return -1;
        fs.fchmodSync(descriptor, mode);
        return 0;
    },
    ftruncate: descriptor => fallbackFailure === 'ftruncate' ? -1 : (fs.ftruncateSync(descriptor, 0), 0),
    fdopen: descriptor => failure === 'fdopen' ? null : descriptor,
    close: descriptor => fs.closeSync(descriptor),
};
const openOptions = vm.runInNewContext(`(function(path) { ${body} })`, context);
const run = () => openOptions('/etc/wpa_supplicant-wan0.conf');

try {
    fs.writeFileSync(sentinel, 'outside data');
    for (const kind of ['new', 'legacy', 'symlink', 'dangling', 'hardlink']) {
        fs.rmSync(filename, { force: true });
        let previousInode;
        if (kind === 'legacy') {
            fs.writeFileSync(filename, 'old credentials');
            fs.chmodSync(filename, 0o644);
            previousInode = fs.statSync(filename).ino;
        } else if (kind === 'symlink' || kind === 'dangling') {
            fs.symlinkSync(kind === 'symlink' ? sentinel : path.join(temporary, 'missing'), filename);
        } else if (kind === 'hardlink') {
            fs.linkSync(sentinel, filename);
        }

        const oldMask = process.umask(0o777);
        let descriptor;
        try { descriptor = run(); }
        finally { assert.equal(process.umask(oldMask), 0o777); }
        assert.notEqual(descriptor, null);
        const info = fs.fstatSync(descriptor);
        assert.equal(info.mode & 0o777, 0o600);
        assert.equal(info.nlink, 1);
        if (previousInode !== undefined) assert.notEqual(info.ino, previousInode);
        fs.writeSync(descriptor, 'identity="fixture"\npassword="secret"\n');
        fs.closeSync(descriptor);
        assert.equal(fs.readFileSync(filename, 'utf8'), 'identity="fixture"\npassword="secret"\n');
        assert.equal(fs.readFileSync(sentinel, 'utf8'), 'outside data');
        checks++;
    }

    for (failure of ['unlink', 'open', 'fchown', 'fchmod', 'fdopen']) {
        fs.rmSync(filename, { force: true });
        fs.writeFileSync(filename, 'old credentials');
        fs.chmodSync(filename, 0o644);
        unlinkFailedOnce = false;
        if (failure === 'unlink') {
            const descriptor = run();
            assert.notEqual(descriptor, null);
            assert.equal(fs.fstatSync(descriptor).mode & 0o777, 0o600);
            assert.equal(fs.readFileSync(filename, 'utf8'), '');
            fs.closeSync(descriptor);
        } else {
            assert.equal(run(), null);
            assert.equal(fs.existsSync(filename), false);
        }
        checks++;
    }

    failure = 'unlink';
    unlinkFailedOnce = false;
    fallbackFailure = 'fchmod';
    fs.writeFileSync(filename, 'old credentials');
    fs.chmodSync(filename, 0o644);
    assert.equal(run(), null);
    assert.equal(fs.existsSync(filename), false);
    checks++;

    unlinkFailedOnce = false;
    fallbackFailure = 'ftruncate';
    fs.writeFileSync(filename, 'old credentials');
    fs.chmodSync(filename, 0o644);
    assert.equal(run(), null);
    assert.equal(fs.statSync(filename).mode & 0o777, 0o600);
    assert.equal(fs.readFileSync(filename, 'utf8'), 'old credentials');
    checks++;

    failure = '';
    fallbackFailure = '';
    race = true;
    fs.rmSync(filename, { force: true });
    assert.equal(run(), null);
    assert.equal(fs.readFileSync(sentinel, 'utf8'), 'outside data');
    checks++;
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}

console.log(`WAN auth permissions: ${checks} source-translated lifecycle/host filesystem checks passed (ownership operation mocked; not compiled C or router/UID 65534 testing)`);