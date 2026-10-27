const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const source = read('release/src/router/rc/pppd.c');
const helper = source.slice(source.indexOf('FILE *ppp_options_open('), source.indexOf('\nint\nstart_pppd('));
assert.match(read('release/src/router/rc/rc.h'), /extern FILE \*ppp_options_open\(const char \*path\);/);
for (const file of ['pppd.c', 'vpnc.c', 'vpnc_fusion.c']) {
    const writer = read(`release/src/router/rc/${file}`);
    assert.match(writer, /if \(!\(fp = ppp_options_open\(options\)\)\)\s*\{\s*perror\(options\);\s*return -1;/);
    assert.doesNotMatch(writer, /umask\(|fopen\(options,/);
}
assert.match(helper, /O_WRONLY \| O_CREAT \| O_EXCL, 0600/);
assert.ok(helper.indexOf('unlink(path)') < helper.indexOf('open(path,'));
assert.ok(helper.indexOf('fchmod(') < helper.indexOf('fdopen('));

const body = helper.slice(helper.indexOf('{') + 1, helper.lastIndexOf('}'))
    .replace('struct stat st;', 'let st = {};')
    .replace('int descriptor;', 'let descriptor;')
    .replace('FILE *stream;', 'let stream;')
    .replaceAll('NULL', 'null')
    .replaceAll('0600', '0o600').replaceAll('0022', '0o022')
    .replace('&st', 'st').replace('path[9]', 'path.charAt(9)')
    .replace('path + 9', 'path.slice(9)');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ppp-options-'));
let checks = 0;
let metadata = {};
let failure = '';
let race = false;
const context = {
    ...fs.constants, ENOENT: 'ENOENT', errno: null,
    geteuid: () => metadata.euid ?? 0,
    strncmp: (left, right, count) => left.slice(0, count) === right.slice(0, count) ? 0 : 1,
    strchr: (text, character) => text.includes(character),
    S_ISDIR: mode => (mode & fs.constants.S_IFMT) === fs.constants.S_IFDIR,
    lstat: (name, st) => {
        if (failure === 'lstat') return -1;
        Object.assign(st, { st_uid: 0, st_mode: fs.constants.S_IFDIR | 0o755 }, metadata);
        return 0;
    },
    unlink: name => {
        if (failure === 'unlink') { context.errno = 'EACCES'; return -1; }
        try { fs.unlinkSync(name); return 0; }
        catch (error) { context.errno = error.code; return -1; }
    },
    open: (name, flags, mode) => {
        if (race) fs.symlinkSync(path.join(temporary, 'sentinel'), name);
        if (failure === 'open') return -1;
        try { return fs.openSync(name, flags, mode); } catch { return -1; }
    },
    fchown: (descriptor, uid, gid) => {
        assert.equal(uid, 0); assert.equal(gid, 0);
        if (failure === 'fchown') return -1;
        if (process.getuid() === 0) fs.fchownSync(descriptor, uid, gid);
        return 0;
    },
    fchmod: (descriptor, mode) => {
        if (failure === 'fchmod') return -1;
        fs.fchmodSync(descriptor, mode); return 0;
    },
    fdopen: descriptor => failure === 'fdopen' ? null : descriptor,
    close: descriptor => fs.closeSync(descriptor),
};
const openOptions = vm.runInNewContext(`(function(path) { ${body} })`, context);
const filename = path.join(temporary, 'options.wan0');
// Only remap the fixed protected directory, retaining the actual helper control flow.
const run = () => openOptions('/tmp/ppp/options.wan0');
for (const name of ['unlink', 'open']) {
    const operation = context[name];
    context[name] = (name, ...args) => operation(name.replace('/tmp/ppp', temporary), ...args);
}
try {
    const sentinel = path.join(temporary, 'sentinel');
    fs.writeFileSync(sentinel, 'unchanged');
    for (const kind of ['new', 'legacy', 'symlink', 'dangling', 'hardlink']) {
        fs.rmSync(filename, { force: true });
        let held;
        if (kind === 'legacy') {
            fs.writeFileSync(filename, 'old injected options');
            fs.chmodSync(filename, 0o666);
            held = fs.openSync(filename, 'r+');
        } else if (kind === 'symlink' || kind === 'dangling') {
            fs.symlinkSync(kind === 'symlink' ? sentinel : path.join(temporary, 'absent'), filename);
        } else if (kind === 'hardlink') fs.linkSync(sentinel, filename);
        const oldMask = process.umask(0o777);
        let descriptor;
        try { descriptor = run(); } finally { assert.equal(process.umask(oldMask), 0o777); }
        assert.notEqual(descriptor, null);
        assert.equal(fs.fstatSync(descriptor).mode & 0o777, 0o600);
        assert.equal(fs.fstatSync(descriptor).nlink, 1);
        assert.equal(fs.fstatSync(descriptor).uid, process.getuid());
        fs.writeSync(descriptor, "user 'test'\npassword 'fixture'\n");
        if (held !== undefined) {
            fs.writeSync(held, 'untrusted overwrite', 0);
            fs.closeSync(held);
        }
        fs.closeSync(descriptor);
        assert.equal(fs.readFileSync(filename, 'utf8'), "user 'test'\npassword 'fixture'\n");
        assert.equal(fs.readFileSync(sentinel, 'utf8'), 'unchanged');
        checks++;
    }
    for (metadata of [{ euid: 65534 }, { st_uid: 65534 }, { st_mode: 0o40777 }, { st_mode: 0o120755 }]) {
        assert.equal(run(), null);
        assert.equal(fs.readFileSync(filename, 'utf8'), "user 'test'\npassword 'fixture'\n");
        checks++;
    }
    metadata = {};
    for (failure of ['lstat', 'unlink', 'open', 'fchown', 'fchmod', 'fdopen']) {
        assert.equal(run(), null);
        checks++;
    }
    failure = '';
    race = true;
    assert.equal(run(), null);
    assert.equal(fs.readFileSync(sentinel, 'utf8'), 'unchanged');
    checks++;
    for (const invalid of ['/tmp/other/file', '/tmp/ppp/', '/tmp/ppp/../file', '/tmp/ppp/nested/file']) {
        assert.equal(openOptions(invalid), null);
        checks++;
    }
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}
console.log(`PASS: ${checks} PPP options source-translated lifecycle/host filesystem checks (ownership mocked unless root; not compiled C or router tests)`);