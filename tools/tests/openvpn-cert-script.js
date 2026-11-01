const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/libovpn/openvpn_setup.c'), 'utf8');
const match = source.match(/static void ovpn_generate_server_certificates\(int unit, int key_size\)\s*\{([\s\S]*?)\n\}/);
assert.ok(match, 'private certificate-script helper exists');
const helper = match[1];

assert.match(helper, /mkdtemp\(directory\)/);
assert.match(helper, /S_ISDIR\(st\.st_mode\).*st\.st_uid != 0/);
assert.match(helper, /st\.st_mode & 0777\) != 0700/);
assert.match(helper, /mkstemp\(script_path\)/);
assert.match(helper, /S_ISREG\(st\.st_mode\).*st\.st_uid != 0/);
assert.match(helper, /st\.st_nlink != 1/);
assert.match(helper, /fchmod\(fd, 0700\)/);
assert.match(helper, /fdopen\(fd, "w"\)/);
assert.match(helper, /ferror\(fp\)/);
assert.match(helper, /eval\(script_path\)/);
assert.ok(helper.indexOf('fclose(fp)') < helper.indexOf('eval(script_path)'), 'script closes before execution');
assert.match(helper, /unlink\(script_path\)/);
assert.match(helper, /rmdir\(directory\)/);
assert.doesNotMatch(source, /\/tmp\/genvpncert\.sh/);
assert.doesNotMatch(helper, /fopen|chmod\(script_path, 0700\)/);
assert.match(source, /ovpn_generate_server_certificates\(unit, sconf->tls_keysize \? 2048 : 1024\)/);
assert.match(helper, /pkitool --initca/);
assert.match(helper, /pkitool --server server/);
assert.match(helper, /pkitool client/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'openvpn-cert-script-'));
try {
    const target = path.join(temporary, 'target');
    const legacy = path.join(temporary, 'genvpncert.sh');
    const originalTarget = 'target sentinel\n';
    fs.writeFileSync(target, originalTarget);
    fs.symlinkSync(target, legacy);

    const writePrivateScript = () => {
        const directory = fs.mkdtempSync(path.join(temporary, 'private-'));
        assert.equal(fs.statSync(directory).mode & 0o777, 0o700);
        const filename = path.join(directory, 'genvpncert.XXXXXX');
        const descriptor = fs.openSync(filename,
            fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
            0o600);
        try {
            fs.fchmodSync(descriptor, 0o700);
            fs.writeSync(descriptor, '#!/bin/sh\n');
            const stat = fs.fstatSync(descriptor);
            assert.equal(stat.nlink, 1);
            assert.equal(stat.mode & 0o777, 0o700);
        } finally {
            fs.closeSync(descriptor);
        }
        return { directory, filename };
    };

    const first = writePrivateScript();
    assert.equal(fs.readFileSync(target, 'utf8'), originalTarget);
    assert.equal(fs.lstatSync(legacy).isSymbolicLink(), true);
    fs.rmSync(first.directory, { recursive: true });

    fs.unlinkSync(legacy);
    const attackerContent = 'attacker-owned file\n';
    fs.writeFileSync(legacy, attackerContent, { mode: 0o600 });
    const second = writePrivateScript();
    assert.equal(fs.readFileSync(legacy, 'utf8'), attackerContent);
    fs.rmSync(second.directory, { recursive: true });
    console.log('PASS: private exclusive script creation leaves legacy symlink targets and files unchanged');
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}