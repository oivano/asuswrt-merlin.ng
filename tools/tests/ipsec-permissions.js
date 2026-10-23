const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const source = read('release/src/router/rc/rc_ipsec.c');
const header = read('release/src/router/rc/rc_ipsec.h');
const init = read('release/src/router/rc/init.c');
const services = read('release/src/router/rc/services.c');
const section = (start, end) => source.slice(source.indexOf(start), source.indexOf(end));

assert.match(header, /FILE_PATH_IPSEC_PRIVATE_DIR\s+"\/tmp\/ipsec-private"/);
for (const name of ['SH', 'IPTABLES_RULE', 'UPDOWN'])
    assert.match(header, new RegExp(`FILE_PATH_IPSEC_${name}\\s+FILE_PATH_IPSEC_PRIVATE_DIR`));
assert.doesNotMatch(source, /chmod\([^\n]*0777/);
assert.doesNotMatch(source, /fopen\(FILE_PATH_(?:IPSEC_(?:SH|IPTABLES_RULE)|CA_(?:CHECK_SH|GEN_SH|ETC"(?:generate|ca_init)\.sh"))/);
assert.doesNotMatch(source, /system\(FILE_PATH_CA_ETC/);
assert.match(init, /chmod\("\/tmp", 01777\)/);
assert.match(init, /^\s*umask\(022\);/m);

const directory = section('static int ipsec_private_dir(', 'static int ipsec_secure_ca_files(');
assert.match(directory, /mkdir\(path, 0700\)/);
assert.match(directory, /O_DIRECTORY \| O_NOFOLLOW/);
assert.match(directory, /st\.st_uid == 0 && st\.st_gid == 0/);
assert.match(directory, /fchmod\(descriptor, 0700\)/);
const parents = section('static int ipsec_secure_dirs(', 'static FILE *ipsec_script_open(');
assert.match(parents, /lstat\("\/tmp"/);
assert.match(parents, /S_ISVTX/);
assert.match(parents, /lstat\("\/jffs"/);
assert.match(parents, /st\.st_mode & 0022/);
assert.match(parents, /ipsec_private_dir\("\/jffs\/ca_files"\)/);
assert.doesNotMatch(parents, /ipsec_private_dir\(FILE_PATH_CA_ETC\)/);

const migration = section('static int ipsec_secure_ca_files(', 'static int ipsec_secure_dirs(');
for (const guard of ['!S_ISREG(st.st_mode)', 'st.st_uid != 0', 'st.st_gid != 0', 'st.st_nlink != 1'])
    assert.ok(migration.includes(guard), guard);
assert.match(migration, /unlink\(path\)/);
assert.match(migration, /O_NOFOLLOW \| O_NONBLOCK/);
assert.match(migration, /0700 : 0600/);
const startup = section('void rc_ipsec_config_init(', '#if 0\nstatic int cur_bitmap_en_scan');
assert.ok(startup.indexOf('ipsec_secure_dirs()') < startup.indexOf('rc_ipsec_conf_default_init()'));
const generation = section('void rc_ipsec_gen_cert(', 'void rc_ipsec_ca_init(');
assert.ok(generation.indexOf('ipsec_secure_dirs()') < generation.indexOf('check_if_file_exist('));
assert.match(generation, /umask 077/);

const creation = section('static FILE *ipsec_script_open(', 'static int ipsec_run_script(');
assert.match(creation, /unlink\(path\)/);
assert.match(creation, /O_WRONLY \| O_NOFOLLOW \| O_NONBLOCK/);
assert.match(creation, /append \? O_APPEND : O_CREAT \| O_EXCL/);
assert.ok(creation.indexOf('fstat(') < creation.indexOf('fdopen('));
assert.doesNotMatch(creation, /O_TRUNC/);
const execution = section('static int ipsec_run_script(', 'FILE *rc_ipsec_cert_open(');
for (const body of [creation, execution]) {
    for (const guard of ['!S_ISREG(st.st_mode)', 'st.st_uid != 0', 'st.st_gid != 0', 'st.st_nlink != 1', 'st.st_mode & 0077'])
        assert.ok(body.includes(guard), guard);
    assert.ok(body.indexOf('ipsec_secure_dirs()') < body.indexOf('open(path'));
}
assert.ok(execution.indexOf('fstat(') < execution.indexOf('_eval('));
assert.ok(execution.indexOf('umask(077)') < execution.indexOf('_eval('));
assert.ok(execution.indexOf('umask(saved_umask)') > execution.indexOf('_eval('));
assert.match(source, /void run_ipsec_firewall_scripts\(void\)\s*\{\s*ipsec_run_script\(FILE_PATH_IPSEC_IPTABLES_RULE\)/);
assert.match(source, /ipsec_script_open\(FILE_PATH_IPSEC_IPTABLES_RULE, 1\)/);
assert.match(source, /chmod 0600 \/tmp\/etc\/ipsec\.d\/private\/svrKey\.pem/);
assert.equal((services.match(/rc_ipsec_cert_open\(file_path\)/g) || []).length, 3);
const upload = section('FILE *rc_ipsec_cert_open(', '/*ike version');
assert.match(upload, /strchr\(name, '\/'\)/);
assert.match(upload, /fchmod\(fileno\(stream\), 0600\)/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ipsec-permissions-'));
try {
    const directoryPath = path.join(temporary, 'private');
    fs.mkdirSync(directoryPath, { mode: 0o700 });
    const target = path.join(temporary, 'unrelated');
    const script = path.join(directoryPath, 'helper.sh');
    fs.writeFileSync(target, 'unchanged');
    fs.symlinkSync(target, script);
    assert.throws(() => fs.openSync(script, fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW), { code: 'ELOOP' });
    assert.throws(() => fs.openSync(script, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o700), { code: 'EEXIST' });
    fs.unlinkSync(script);
    const descriptor = fs.openSync(script, fs.constants.O_WRONLY | fs.constants.O_CREAT |
        fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o700);
    fs.writeSync(descriptor, '#!/bin/sh\numask 077\n');
    fs.closeSync(descriptor);
    assert.equal(fs.readFileSync(target, 'utf8'), 'unchanged');
    assert.equal(fs.statSync(script).mode & 0o077, 0);
    assert.equal(fs.statSync(directoryPath).mode & 0o077, 0);
    const key = path.join(directoryPath, 'svrKey.pem');
    fs.writeFileSync(key, 'test key', { mode: 0o666 });
    fs.chmodSync(key, 0o666);
    const keyDescriptor = fs.openSync(key, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    fs.fchmodSync(keyDescriptor, 0o600);
    fs.closeSync(keyDescriptor);
    assert.equal(fs.statSync(key).mode & 0o777, 0o600);
    const accepted = metadata => metadata.regular && metadata.uid === 0 && metadata.gid === 0 &&
        metadata.links === 1 && !(metadata.mode & 0o077);
    const safe = { regular: true, uid: 0, gid: 0, links: 1, mode: 0o700 };
    assert.ok(accepted(safe));
    for (const mode of [0o777, 0o775, 0o722, 0o666, 0o755])
        assert.equal(accepted({ ...safe, mode }), false);
    for (const patch of [{ uid: 65534 }, { gid: 65534 }, { links: 2 }, { regular: false }])
        assert.equal(accepted({ ...safe, ...patch }), false);
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}
console.log('PASS: IPsec permission source contracts, rejection models and host no-follow/exclusive-open primitives (not compiled C or router uid tests)');