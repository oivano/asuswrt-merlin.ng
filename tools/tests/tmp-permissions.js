const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const init = read('release/src/router/rc/init.c');
const wan = read('release/src/router/rc/wan.c');
const dhcp = read('release/src/router/rc/udhcpc.c');
const install = read('release/src/router/rc/Makefile');
const applets = read('release/src/router/rc/rc.c');
const ppp = read('release/src/router/pppd/pppd/pathnames.h');

assert.match(init, /chmod\("\/tmp", 01777\)/);
assert.doesNotMatch(init, /chmod\("\/tmp", 0777\)/);
assert.match(init, /chmod\(POOL_MOUNT_ROOT, 01777\)/);
for (const directory of ['/var/state', '/var/state/parport', '/var/state/parport/svr_statue',
    '/var/lock', '/var/tmp/dhcp'])
    assert.ok(init.includes(`mkdir("${directory}", 01777)`), directory);
const bootDirectories = init.slice(init.indexOf('static const char *mkd[]'), init.indexOf('// LPRng support'));
for (const directory of ['/tmp/etc', '/tmp/var', '/tmp/ppp', '/tmp/ppp/peers'])
    assert.ok(bootDirectories.includes(`"${directory}"`), directory);
assert.match(bootDirectories, /mkdir\(mkd\[i\], 0755\)/);
assert.ok(init.indexOf('umask(022);') > init.indexOf('chmod("/tmp", 01777)'));
for (const directory of ['/tmp/ppp', '/tmp/ppp/peers']) {
    assert.ok(wan.includes(`mkdir("${directory}", 0755)`));
    assert.ok(!wan.includes(`rmdir("${directory}")`));
    assert.ok(!wan.includes(`mkdir("${directory}", 0777)`));
}
assert.match(ppp, /_PATH_SYSOPTIONS\s+_ROOT_PATH "\/ppp\/options"/);
assert.match(ppp, /_PATH_IPUP\s+_ROOT_PATH "\/ppp\/ip-up"/);
assert.match(install, /install -d -m 0755 \$\(INSTALLDIR\)\/usr\/libexec\/rc-hooks/);
for (const hook of ['udhcpc_wan', 'zcip', 'dhcp6c']) {
    assert.ok(dhcp.includes(`"/usr/libexec/rc-hooks/${hook}"`), hook);
    assert.ok(install.includes(`ln -sf /sbin/rc $(INSTALLDIR)/usr/libexec/rc-hooks/${hook}`), hook);
    assert.ok(applets.includes(`{ "${hook}"`), hook);
    assert.ok(!wan.includes(`"/tmp/${hook}"`), hook);
    assert.ok(!dhcp.includes(`"/tmp/${hook}"`), hook);
}

if (process.getuid() !== 0) {
    console.log('SKIP: real root/nobody filesystem tests require uid 0; source contracts passed');
} else {
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'tmp-permissions-'));
    const asNobody = code => {
        const result = spawnSync(process.execPath, ['-e', code], { uid: 65534, gid: 65534, encoding: 'utf8' });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);
    };
    try {
        fs.chmodSync(temporary, 0o755);
        const shared = path.join(temporary, 'tmp');
        fs.mkdirSync(shared);
        fs.chmodSync(shared, 0o1777);
        for (const directory of ['etc', 'var', 'ppp', 'mnt']) {
            fs.mkdirSync(path.join(shared, directory), { mode: 0o755 });
        }
        fs.chmodSync(path.join(shared, 'mnt'), 0o1777);
        const hook = path.join(shared, 'udhcpc_wan');
        fs.symlinkSync('/sbin/rc', hook);
        const ipup = path.join(shared, 'ppp/ip-up');
        fs.symlinkSync('/sbin/rc', ipup);
        const options = path.join(shared, 'ppp/options');
        fs.writeFileSync(options, 'test options\n', { mode: 0o644 });
        const mounted = path.join(shared, 'mnt/root-mount');
        fs.mkdirSync(mounted);
        const victims = [hook, ipup, options, mounted, path.join(shared, 'etc'), path.join(shared, 'var')];
        asNobody(`
            const fs = require('node:fs'), assert = require('node:assert/strict');
            for (const target of ${JSON.stringify(victims)}) {
                assert.throws(() => fs.renameSync(target, target + '.moved'), error =>
                    ['EPERM', 'EACCES'].includes(error.code));
            }
            for (const target of ${JSON.stringify([hook, ipup, options])}) {
                assert.throws(() => fs.unlinkSync(target), error => ['EPERM', 'EACCES'].includes(error.code));
                assert.throws(() => fs.writeFileSync(target, 'replacement', { flag: 'wx' }), { code: 'EEXIST' });
            }
            assert.throws(() => fs.writeFileSync(${JSON.stringify(options)}, 'replacement'), { code: 'EACCES' });
            assert.throws(() => fs.writeFileSync(${JSON.stringify(path.join(shared, 'ppp/ip-down'))}, 'replacement'), { code: 'EACCES' });
            const own = ${JSON.stringify(path.join(shared, 'user-file'))};
            fs.writeFileSync(own, 'allowed');
            fs.renameSync(own, own + '.moved');
            fs.unlinkSync(own + '.moved');
        `);
        fs.chmodSync(shared, 0o777);
        asNobody(`require('node:fs').unlinkSync(${JSON.stringify(hook)});`);
        assert.throws(() => fs.lstatSync(hook), { code: 'ENOENT' });
        console.log('PASS: real root/nobody denial tests, shared-file access and vulnerable-mode negative control');
    } finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
}
console.log('PASS: boot permissions, immutable DHCP hooks and reserved PPP path source contracts (not compiled firmware)');