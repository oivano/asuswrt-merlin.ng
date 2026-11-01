const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const init = read('release/src/router/rc/init.c');
const common = read('release/src/router/rc/common.c');
const services = read('release/src/router/rc/services.c');
const firewall = read('release/src/router/rc/firewall.c');
const qos = read('release/src/router/rc/qos.c');
const acme = read('release/src/router/acme.sh/acme.sh');
const checkWatchdog = read('release/src/router/rc/check_watchdog.c');
const watchdog = read('release/src/router/rc/watchdog.c');
const wan = read('release/src/router/rc/wan.c');
const dhcp = read('release/src/router/rc/udhcpc.c');
const install = read('release/src/router/rc/Makefile');
const applets = read('release/src/router/rc/rc.c');
const ppp = read('release/src/router/pppd/pppd/pathnames.h');
const cru = read('release/src/router/others/cru');

const envsave = common.match(/void envsave\(const char\* path\)\s*\{([\s\S]*?)\n\}/);
assert.ok(envsave, 'envsave compatibility function exists');
assert.match(envsave[1], /\(void\)path;/);
assert.doesNotMatch(envsave[1], /\b(?:fopen|open|fprintf|fwrite)\s*\(/);

assert.match(common, /open\("\/tmp\/ppp", O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(common, /openat\(dirfd, "reboot",\s*O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW \| O_NONBLOCK, 0600\)/);
assert.match(common, /openat\(dirfd, "reboot", O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK\)/);
assert.match(common, /S_ISREG\(st\.st_mode\).*st\.st_uid != 0/);
assert.match(common, /st\.st_nlink != 1[\s\S]*st\.st_mode & 0077/);
assert.equal((init.match(/rc_reboot_flag_set\(\)/g) || []).length, 1);
assert.equal((services.match(/rc_reboot_flag_set\(\)/g) || []).length, 2);
assert.equal((checkWatchdog.match(/rc_reboot_flag_is_set\(\)/g) || []).length, 1);
assert.equal((watchdog.match(/rc_reboot_flag_is_set\(\)/g) || []).length, 2);
for (const source of [init, services, checkWatchdog, watchdog])
    assert.doesNotMatch(source, /\/tmp\/reboot/);

const cronTemporary = fs.mkdtempSync(path.join(os.tmpdir(), 'cron-permissions-'));
try {
    fs.chmodSync(cronTemporary, 0o755);
    const directory = path.join(cronTemporary, 'crontabs');
    fs.mkdirSync(directory, { mode: 0o755 });
    const crontab = path.join(directory, 'admin');
    const observedMode = path.join(cronTemporary, 'mode');
    const script = cru.replace('D="/var/spool/cron/crontabs"', `D="${directory}"`)
        .replace('L="/var/lock/cron.lock"', `L="${cronTemporary}/cron.lock"`);
    const runCru = (...args) => {
        const result = spawnSync('/bin/bash', ['-c', `
            umask 000
            nvram() { printf '%s\\n' admin; }
            mv() {
                stat -c %a "$1" >"${observedMode}"
                command mv "$@"
            }
            ${script}
        `, 'cru', ...args], { encoding: 'utf8' });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);
    };
    const checkModes = () => {
        assert.equal(fs.readFileSync(observedMode, 'utf8').trim(), '600', 'temporary crontab');
        assert.equal(fs.statSync(crontab).mode & 0o777, 0o600, 'installed crontab');
        assert.equal(fs.existsSync(`${crontab}.new`), false);
    };
    runCru('d', 'dnsmasq_blocklist');
    checkModes();
    assert.equal(fs.readFileSync(crontab, 'utf8'), '');
    assert.equal(fs.statSync(path.join(directory, 'cron.update')).mode & 0o777, 0o600);
    runCru('a', 'first', '* * * * * echo first');
    checkModes();
    runCru('a', 'second', '0 * * * * echo second');
    checkModes();
    runCru('a', 'first', '* * * * * echo replaced');
    checkModes();
    assert.equal(fs.readFileSync(crontab, 'utf8'),
        '0 * * * * echo second #second#\n* * * * * echo replaced #first#\n');
    fs.chmodSync(crontab, 0o666);
    fs.writeFileSync(`${crontab}.new`, 'stale data');
    fs.chmodSync(`${crontab}.new`, 0o666);
    const staleDescriptor = fs.openSync(`${crontab}.new`, 'a');
    try {
        runCru('d', 'first');
        fs.writeSync(staleDescriptor, '* * * * * echo stale writer\n');
    } finally {
        fs.closeSync(staleDescriptor);
    }
    checkModes();
    assert.equal(fs.readFileSync(crontab, 'utf8'), '0 * * * * echo second #second#\n');
    if (process.getuid() === 0) {
        const result = spawnSync(process.execPath, ['-e', `
            const fs = require('node:fs'), assert = require('node:assert/strict');
            assert.throws(() => fs.openSync(${JSON.stringify(crontab)}, 'a'), { code: 'EACCES' });
        `], { uid: 65534, gid: 65534, encoding: 'utf8' });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);
    }
    console.log('PASS: actual cru add/delete under umask 000 creates private temporary and installed crontabs');
} finally {
    fs.rmSync(cronTemporary, { recursive: true, force: true });
}

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
assert.match(init, /^\s*umask\(022\);/m);
assert.ok(init.indexOf('umask(022);') > init.indexOf('chmod("/tmp", 01777)'));
assert.match(init, /var_nvram_init\(\);\s*chmod\("\/tmp\/var\/nvram", 0700\);/);

const leWorkdir = common.match(/int le_workdir_prepare\(void\)\s*\{([\s\S]*?)\n\}/);
const leHookCheck = common.match(/int le_fw_script_is_safe\(void\)\s*\{([\s\S]*?)\n\}/);
const leStartWrapper = common.match(/int start_letsencrypt_safe\(void\)\s*\{([\s\S]*?)\n\}/);
const leAcmeWrapper = common.match(/int le_acme_main_safe\(int argc, char \*\*argv\)\s*\{([\s\S]*?)\n\}/);
assert.ok(leWorkdir, 'Let\'s Encrypt protected-directory helper exists');
assert.ok(leHookCheck, 'Let\'s Encrypt firewall hook validator exists');
assert.ok(leStartWrapper, 'Let\'s Encrypt startup wrapper exists');
assert.ok(leAcmeWrapper, 'Let\'s Encrypt ACME applet wrapper exists');
assert.match(leWorkdir[1], /lstat\("\/", &st\)/);
assert.match(leWorkdir[1], /lstat\("\/tmp", &st\)/);
assert.match(leWorkdir[1], /mkdir\("\/tmp\/\.le", 0700\)/);
assert.match(leWorkdir[1], /open\("\/tmp\/\.le", O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(leWorkdir[1], /st\.st_uid == 0/);
assert.match(leWorkdir[1], /S_ISDIR\(st\.st_mode\) && st\.st_uid == 0 &&\s*!\(st\.st_mode & 0077\)/);
assert.match(leWorkdir[1], /fchmod\(fd, 0700\)/);
assert.match(leHookCheck[1], /nvram_match\("le_enable", "1"\)/);
assert.match(leHookCheck[1], /lstat\("\/tmp\/\.le\/le-fw\.sh", &st\)/);
assert.match(leHookCheck[1], /S_ISREG\(st\.st_mode\)/);
assert.match(leHookCheck[1], /st\.st_uid != 0/);
assert.match(leHookCheck[1], /st\.st_nlink != 1/);
assert.match(leHookCheck[1], /st\.st_mode & 0022/);
assert.match(leStartWrapper[1], /if \(!le_workdir_prepare\(\)\)\s*return -1;\s*return start_letsencrypt\(\);/);
assert.match(firewall, /if \(nvram_match\("le_enable", "1"\) && le_fw_script_is_safe\(\)\)\s*run_le_fw_script\(\);/);
assert.match(init, /chmod\("\/tmp", 01777\);\s*if \(!rc_qos_workdir_prepare\(\)\)/);
assert.match(init, /#ifdef RTCONFIG_LETSENCRYPT\s*if \(!le_workdir_prepare\(\)\)/);
assert.equal((services.match(/start_letsencrypt_safe\(\);/g) || []).length, 3);
assert.match(applets, /\{ "le_acme",\s*le_acme_main_safe\s*\}/);
assert.equal((leAcmeWrapper[1].match(/le_workdir_prepare\(\)/g) || []).length, 2,
    'work directory is protected before and restored after ACME cleanup');
const leAcmeCall = leAcmeWrapper[1].indexOf('result = le_acme_main(argc, argv);');
assert.ok(leAcmeCall > 0);
assert.ok(leAcmeWrapper[1].lastIndexOf('le_workdir_prepare()', leAcmeCall) < leAcmeCall,
    'work directory is validated before acme.sh runs');
assert.ok(leAcmeWrapper[1].indexOf('le_workdir_prepare()', leAcmeCall) > leAcmeCall,
    'work directory is restored after acme.sh cleanup');
assert.match(acme, /if \[ -z "\$LE_CONFIG_HOME" \]; then\s*LE_CONFIG_HOME="\$LE_WORKING_DIR"/);
assert.match(acme, /DEFAULT_CA_HOME="\$LE_CONFIG_HOME\/ca"/);
assert.match(acme, /if \[ -f "\$CA_CONF" \]; then\s*\. "\$CA_CONF"/);

const qosWorkdir = qos.match(/int rc_qos_workdir_prepare\(void\)\s*\{([\s\S]*?)\n\}/);
const qosWriter = qos.match(/static FILE \*qos_file_open\(const char \*path\)\s*\{([\s\S]*?)\n\}/);
const qosFileCheck = qos.match(/static int qos_file_is_safe\(const char \*path, int executable\)\s*\{([\s\S]*?)\n\}/);
const stopQos = qos.match(/void stop_iQos\(void\)\s*\{([\s\S]*?)\n\}/);
assert.ok(qosWorkdir, 'QoS protected-directory helper exists');
assert.ok(qosWriter, 'QoS exclusive file writer exists');
assert.ok(qosFileCheck, 'QoS file validator exists');
assert.ok(stopQos, 'QoS stop handler exists');
assert.match(qos, /#define QOS_PRIVATE_DIR "\/tmp\/ppp\/qos"/);
assert.match(qosWorkdir[1], /lstat\("\/tmp\/ppp", &st\)/);
assert.match(qosWorkdir[1], /mkdir\(QOS_PRIVATE_DIR, 0700\)/);
assert.match(qosWorkdir[1], /open\(QOS_PRIVATE_DIR, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(qosWorkdir[1], /st\.st_uid == 0/);
assert.match(qosWriter[1], /unlinkat\(dirfd, name, 0\)/);
assert.match(qosWriter[1], /openat\(dirfd, name, O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW/);
assert.match(qosWriter[1], /S_ISREG\(st\.st_mode\)/);
assert.match(qosWriter[1], /st\.st_uid != 0/);
assert.match(qosWriter[1], /st\.st_nlink != 1/);
assert.match(qosFileCheck[1], /O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK/);
assert.match(qosFileCheck[1], /st\.st_nlink == 1/);
assert.match(qosFileCheck[1], /!executable \|\| \(st\.st_mode & 0100\)/);
assert.match(stopQos[1], /qos_script_eval\(qosfn, "stop"\)/);
assert.doesNotMatch(qos, /eval\(\(char \*\)qosfn/);
assert.doesNotMatch(qos, /fopen\((?:qosfn|mangle_fn|mangle_fn_ipv6), "w"\)/);
assert.doesNotMatch(qos, /"\/tmp\/(?:qos|mangle_rules(?:_ipv6)?)"/);
assert.equal((qos.match(/qos_rules_restore\("iptables-restore"/g) || []).length, 2);
assert.equal((qos.match(/qos_rules_restore\("ip6tables-restore"/g) || []).length, 1);
assert.equal((qos.match(/qos_rules_restore_noflush\("iptables-restore"/g) || []).length, 1);
assert.match(init, /chmod\("\/tmp", 01777\);\s*if \(!rc_qos_workdir_prepare\(\)\)/);

if (process.getuid() === 0) {
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'letsencrypt-hook-'));
    try {
        fs.chmodSync(temporary, 0o1777);
        const directory = path.join(temporary, '.le');
        const script = path.join(directory, 'le-fw.sh');
        const safeHook = (candidate = directory, enabled = true) => {
            if (!enabled) return false;
            try {
                const rootStat = fs.lstatSync('/');
            const parentStat = fs.lstatSync(path.dirname(candidate));
            const directoryStat = fs.lstatSync(candidate);
            const scriptStat = fs.lstatSync(path.join(candidate, 'le-fw.sh'));
                return rootStat.isDirectory() && rootStat.uid === 0 && !(rootStat.mode & 0o022) &&
                    parentStat.isDirectory() && parentStat.uid === 0 &&
                    (!(parentStat.mode & 0o022) || (parentStat.mode & 0o1000)) &&
                    directoryStat.isDirectory() && directoryStat.uid === 0 && !(directoryStat.mode & 0o077) &&
                    scriptStat.isFile() && scriptStat.uid === 0 && scriptStat.nlink === 1 &&
                    !(scriptStat.mode & 0o022) && (scriptStat.mode & 0o111);
            } catch (error) {
                if (error.code === 'ENOENT' || error.code === 'ELOOP') return false;
                throw error;
            }
        };

        fs.mkdirSync(directory, { mode: 0o700 });
        fs.chmodSync(directory, 0o700);
        fs.writeFileSync(script, '#!/bin/sh\n', { mode: 0o700 });
        fs.chmodSync(script, 0o700);
        assert.equal(safeHook(true), true);
        assert.equal(safeHook(directory, false), false, 'disabled Let\'s Encrypt never executes a hook');
        fs.chmodSync(directory, 0o755);
        assert.equal(safeHook(true), false, 'permissive work directory is rejected');
        fs.chmodSync(directory, 0o700);
        fs.chmodSync(script, 0o777);
        assert.equal(safeHook(true), false, 'group/other-writable hook is rejected');
        fs.unlinkSync(script);
        fs.symlinkSync('/bin/sh', script);
        assert.equal(safeHook(true), false, 'symlink hook is rejected');
        fs.unlinkSync(script);

        const attackerDir = path.join(temporary, '.le-attacker');
        const createAsNobody = spawnSync(process.execPath, ['-e', `
            const fs = require('node:fs');
            const directory = ${JSON.stringify(attackerDir)};
            fs.mkdirSync(directory, { mode: 0o700 });
            fs.writeFileSync(directory + '/le-fw.sh', '#!/bin/sh\\n', { mode: 0o700 });
        `], { uid: 65534, gid: 65534, encoding: 'utf8' });
        assert.ifError(createAsNobody.error);
        assert.equal(createAsNobody.status, 0, createAsNobody.stderr);
        assert.equal(safeHook(attackerDir), false, 'attacker-owned directory and hook are rejected');
        fs.symlinkSync(attackerDir, path.join(temporary, '.le-link'));
        assert.equal(safeHook(path.join(temporary, '.le-link')), false, 'symlink directory is rejected');
        console.log('PASS: Let\'s Encrypt hook metadata rejects disabled, writable, symlink and attacker-owned paths');
    } finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
} else {
    console.log('SKIP: Let\'s Encrypt root/nobody fixtures require uid 0; source contracts passed');
}

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
        const nvram = path.join(shared, 'var/nvram');
        fs.mkdirSync(nvram);
        fs.writeFileSync(path.join(nvram, 'rc_service'), 'restart_upgrade', { mode: 0o666 });
        fs.chmodSync(nvram, 0o700);
        asNobody(`
            const fs = require('node:fs'), assert = require('node:assert/strict');
            const directory = ${JSON.stringify(nvram)};
            const service = directory + '/rc_service';
            assert.throws(() => fs.openSync(service, 'w'), { code: 'EACCES' });
            assert.throws(() => fs.writeFileSync(directory + '/forged', 'value'), { code: 'EACCES' });
            assert.throws(() => fs.unlinkSync(service), { code: 'EACCES' });
        `);
        console.log('PASS: real root/nobody denial tests, shared-file access and vulnerable-mode negative control');
    } finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
}
console.log('PASS: boot, DHCP, PPP, QoS and Let\'s Encrypt temporary-path source contracts (not compiled firmware)');