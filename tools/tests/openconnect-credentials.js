const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/rc/rc_openconnect.c'), 'utf8');
const section = (start, end) => source.slice(source.indexOf(start), source.indexOf(end));
const secureDirectory = section('static int openconnect_secure_dir(', 'static int openconnect_config_dir(');
const configDirectory = section('static int openconnect_config_dir(', 'static int openconnect_write_all(');
const writer = section('int write_openconnect_config(', '/* Start OpenConnect client */');
const secretWriter = section('static int openconnect_write_secret(', 'static int openconnect_log_open(');
const start = section('int start_openconnect_client(', '/* Stop OpenConnect client */');

assert.match(source, /#define OPENCONNECT_CONF_DIR "\/tmp\/openconnect"/);
assert.match(configDirectory, /mkdir\(OPENCONNECT_CONF_DIR, 0700\)/);
assert.match(configDirectory, /O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW/);
assert.match(configDirectory, /mkdirat\(parentfd, dirname, 0700\)/);
assert.match(configDirectory, /openat\(parentfd, dirname, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(secureDirectory, /!S_ISDIR\(st\.st_mode\)/);
assert.match(secureDirectory, /st\.st_uid != 0/);
assert.match(secureDirectory, /st\.st_gid != 0/);
assert.match(secureDirectory, /st\.st_mode & 0022/);
assert.match(secureDirectory, /fchmod\(descriptor, 0700\)/);
assert.doesNotMatch(writer, /fopen\(|chmod\(/);
assert.match(writer, /openconnect_config_dir\(unit\)/);
assert.match(writer, /unlinkat\(dirfd, "auth\.txt", 0\)/);
assert.match(secretWriter, /O_CREAT \| O_EXCL/);
assert.match(secretWriter, /O_NOFOLLOW \| O_NONBLOCK/);
assert.match(secretWriter, /!S_ISREG\(st\.st_mode\)/);
assert.match(secretWriter, /st\.st_uid != 0/);
assert.match(secretWriter, /st\.st_gid != 0/);
assert.match(secretWriter, /st\.st_nlink != 1/);
assert.ok(writer.indexOf('openconnect_config_dir(unit)') < writer.indexOf('nvram_pf_safe_get'));
assert.match(start, /if \(write_openconnect_config\(unit\) != 0\)/);
assert.ok(start.indexOf('write_openconnect_config(unit)') < start.indexOf('pid = fork()'));

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'openconnect-credentials-'));
try {
    const attackerDirectory = path.join(temporary, 'openconnect');
    fs.mkdirSync(attackerDirectory, { mode: 0o700 });
    if (process.getuid() === 0)
        fs.chownSync(attackerDirectory, 65534, 65534);
    const outsideTarget = path.join(temporary, 'sentinel');
    fs.writeFileSync(outsideTarget, 'unchanged');

    for (const kind of ['regular', 'symlink']) {
        const clientDirectory = path.join(attackerDirectory, `client-${kind}`);
        fs.mkdirSync(clientDirectory, { mode: 0o700 });
        const authFile = path.join(clientDirectory, 'auth.txt');
        if (kind === 'regular')
            fs.writeFileSync(authFile, 'attacker data');
        else
            fs.symlinkSync(outsideTarget, authFile);

        const metadata = fs.lstatSync(attackerDirectory);
        assert.notEqual(metadata.uid, 0, 'fixture directory must model an unprivileged owner');
        assert.ok(metadata.isDirectory());
        assert.throws(() => fs.openSync(authFile, fs.constants.O_WRONLY |
            fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600));
        assert.equal(fs.readFileSync(outsideTarget, 'utf8'), 'unchanged');
        if (kind === 'regular')
            assert.equal(fs.readFileSync(authFile, 'utf8'), 'attacker data');
        else
            assert.equal(fs.readlinkSync(authFile), outsideTarget);
    }

    const directoryLink = path.join(temporary, 'directory-link');
    fs.symlinkSync(attackerDirectory, directoryLink);
    assert.throws(() => fs.openSync(directoryLink,
        fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW));
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}

console.log('PASS: OpenConnect directory/file source contracts and attacker-owned regular/symlink fixtures (not compiled C or router uid tests)');