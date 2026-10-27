const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const script = path.join(root, 'release/src/router/rom/apps_scripts/usb_swap.sh');
const defaults = fs.readFileSync(path.join(root, 'release/src/router/shared/defaults.c'), 'utf8');
const defaultSwapEnable = defaults.match(/#if defined \(RTCONFIG_DSL\)[^\n]*\n\s*\{ "apps_swap_enable", "([01])"/)[1];
assert.equal(defaultSwapEnable, '1');
const samba = fs.readFileSync(path.join(root, 'release/src/router/libdisk/write_smb_conf.c'), 'utf8');
assert.equal(spawnSync('/bin/sh', ['-n', script]).status, 0);
assert.equal((samba.match(/veto files = \//g) || []).length, 1);
assert.match(samba, /veto files = \/\.__\*\.txt\*\/asusware\*\/asus_lighttpdpasswd\/\.swap\//);
assert.match(samba, /strspn\(swap_file, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\._-"\) == strlen\(swap_file\)/);
assert.match(samba, /fprintf\(fp, "%s\/", swap_file\)/);
assert.match(samba, /delete veto files = no/);
assert.match(samba, /follow symlinks = no/);
assert.ok(samba.includes('/.asus-swap/'));
assert.ok(samba.indexOf('veto files = /') < samba.indexOf('/* share */'));
const helper = fs.readFileSync(script, 'utf8');
assert.match(helper, /exec 9< \.\s*flock -x 9/);
assert.equal((helper.match(/^swapon /gm) || []).length, 1);
for (const name of ['asusrouter', 'app_install.sh', 'app_stop.sh', 'app_switch.sh']) {
    const filename = path.join(root, 'release/src/router/rom/apps_scripts', name);
    const source = fs.readFileSync(filename, 'utf8');
    assert.equal(spawnSync('/bin/sh', ['-n', filename]).status, 0, name);
    assert.doesNotMatch(source, /\b(?:swapon|swapoff|mkswap)\b/);
    if (['asusrouter', 'app_install.sh'].includes(name))
        assert.ok(source.includes('/usr/sbin/usb_swap.sh "$APPS_MOUNTED_PATH"'), name);
}
const usb = fs.readFileSync(path.join(root, 'release/src/router/rc/usb.c'), 'utf8');
assert.doesNotMatch(usb, /"swapon", "-a"/);
assert.match(usb, /activate_devices && S_ISBLK\(st\.st_mode\)/);
assert.match(usb, /else if \(S_ISREG\(st\.st_mode\) &&\s*eval\("\/usr\/sbin\/usb_swap\.sh", "--activate", entry->mnt_fsname\)/);
assert.match(usb, /hasmntopt\(entry, "noauto"\)/);
assert.match(usb, /if \(stop_usb_swap\(mnt->mnt_dir\)\) \{[\s\S]*?return -1;/);
const install = fs.readFileSync(path.join(root, 'release/src/router/rom/Makefile'), 'utf8');
assert.ok(install.indexOf('install -m 0755 apps_scripts/usb_swap.sh') < install.indexOf('ifneq ($(APP),none)'));

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'usb-swap-'));
const bin = path.join(temporary, 'bin');
const log = path.join(temporary, 'calls');
fs.mkdirSync(bin);
const shim = path.join(bin, 'shim');
fs.writeFileSync(shim, `#!${process.execPath}
const fs = require('node:fs'), path = require('node:path');
const { spawnSync } = require('node:child_process');
const command = path.basename(process.argv[1]), args = process.argv.slice(2);
const env = process.env;
if (command === 'nvram') {
    const values = { apps_swap_file: env.SWAP_NAME || '.swap', apps_swap_enable: env.SWAP_ENABLE || '1',
        apps_swap_threshold: env.THRESHOLD || '', apps_swap_size: env.SWAP_SIZE || '2000',
        apps_install_folder: 'asusware.arm', rc_support: 'bcmhnd' };
    console.log(values[args[1]] || '');
} else if (command === 'ls') {
    const result = spawnSync('/bin/ls', args, { encoding: 'utf8' });
    if (result.status !== 0) process.exit(1);
    const fields = result.stdout.trim().split(/\\s+/);
    fields[2] = fields[3] = '0';
    if (args[1] === '.' && process.cwd() === env.PARENT_PATH) {
        if (env.PARENT_MODE) fields[0] = env.PARENT_MODE;
        if (env.PARENT_OWNER) fields[2] = '65534';
    }
    if (env.BAD_OWNER && args[1] !== '.') fields[2] = '65534';
    if (env.BAD_MODE && args[1] !== '.') fields[0] = '-rwxrwxrwx';
    if (args[1] === '.' && process.cwd().endsWith('/.asus-swap')) {
        if (env.PRIVATE_OWNER) fields[2] = '65534';
        if (env.PRIVATE_MODE) fields[0] = 'drwxrwxrwx';
    }
    console.log(fields.join(' '));
} else if (command === 'free') {
    console.log('header\\nmem\\nbuffers\\nswap 0 0 0');
} else if (command === 'df') {
    console.log('Filesystem 1K-blocks Used Available Use% Mounted\\ndisk 10000 0 ' + (env.SPACE || '9000') + ' 0% .');
} else if (command === 'awk') {
    if (args.at(-1) === '/proc/swaps') {
        const active = env.STATE_FILE && fs.existsSync(env.STATE_FILE)
            ? fs.readFileSync(env.STATE_FILE, 'utf8') : env.ACTIVE_SWAP;
        process.exit(active === env.SWAP_CHECK_PATH ? 0 : 1);
    }
    const result = spawnSync('/usr/bin/awk', args, { stdio: 'inherit' });
    process.exit(result.status);
} else {
    fs.appendFileSync(env.CALL_LOG, JSON.stringify([command, ...args]) + '\\n');
    if (env.FAIL_COMMAND === command) process.exit(1);
    if (command === 'rm') process.exit(spawnSync('/bin/rm', args).status);
    if (command === 'chmod' && !(args[0] === '+t' && env.NO_STICKY))
        fs.chmodSync(args[1], args[0] === '+t' ? fs.statSync(args[1]).mode | 0o1000 : parseInt(args[0], 8));
    if (command === 'dd') {
        if (env.BLOCK_DD) { fs.writeSync(1, 'ALLOCATING\\n'); fs.readFileSync(0); }
        fs.appendFileSync(args.find(arg => arg.startsWith('of=')).slice(3), 'swap-data');
    }
    if (command === 'swapon' && env.STATE_FILE) fs.writeFileSync(env.STATE_FILE, args[0]);
}
`, { mode: 0o755 });
for (const command of ['nvram', 'ls', 'free', 'df', 'awk', 'chown', 'chmod', 'dd', 'mkswap', 'swapon', 'swapoff', 'rm'])
    fs.symlinkSync(shim, path.join(bin, command));

let cases = 0;
function run(name, { mode = 0o755, setup = () => {}, env = {}, success = false, disable = false,
    fstab = false, privateDirectoryExists = true, reuse = false, useDefault = false } = {}) {
    const disabled = disable || (useDefault && defaultSwapEnable !== '1');
    const directory = path.join(temporary, name);
    const privateDirectory = path.join(directory, '.asus-swap');
    if (!reuse) {
        fs.mkdirSync(directory, { mode });
        fs.chmodSync(directory, mode);
        if (privateDirectoryExists) fs.mkdirSync(privateDirectory, { mode: 0o700 });
    }
    const target = path.join(privateDirectory, env.SWAP_NAME || '.swap');
    setup(target, directory);
    fs.writeFileSync(log, '');
    const result = spawnSync('/bin/sh', [script, ...(fstab ? ['--activate', env.FSTAB_PATH || target]
        : useDefault ? [directory] : [directory, disable ? '0' : '1'])], {
        encoding: 'utf8', env: { ...process.env, PATH: bin + ':' + process.env.PATH,
            CALL_LOG: log, PARENT_PATH: temporary, SWAP_ENABLE: defaultSwapEnable,
            ACTIVE_SWAP: env.ACTIVE_LEGACY ? path.join(directory,
                env.ACTIVE_LEGACY === 'app' ? 'asusware.arm/.swap' : '.swap')
                : disabled || env.ALREADY_ACTIVE ? target : '', ...env }
    });
    assert.ifError(result.error);
    assert.equal(result.status === 0, success, name + ': ' + result.stderr);
    const calls = fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(line => JSON.parse(line));
    const activates = success && !disabled && !env.ALREADY_ACTIVE && !env.THRESHOLD;
    assert.equal(calls.some(call => call[0] === 'swapon'), activates, name);
    if (activates) {
        assert.equal(fs.statSync(target).mode & 0o777, 0o600, name);
        const activation = calls.findIndex(call => call[0] === 'swapon');
        assert.ok(calls.slice(0, activation).some(call => call[0] === 'chown' && call[1] === '0:0'));
        assert.ok(calls.slice(0, activation).some(call => call[0] === 'chmod' && call[1] === '0600'));
        assert.equal(calls[activation][1], target);
    }
    if (success && !disabled && !env.THRESHOLD) {
        assert.equal(fs.statSync(privateDirectory).mode & 0o777, 0o700, name);
        assert.equal(fs.statSync(target).mode & 0o777, 0o600, name);
    }
    cases++;
    return { target, calls, directory };
}

try {
    const parser = helper.match(/SWAP_CHECK_PATH="\$1" awk '([\s\S]*?)' \/proc\/swaps/)[1];
    const swaps = path.join(temporary, 'proc-swaps');
    for (const activePath of ['/tmp/mnt/disk/.asus-swap/.swap', '/tmp/mnt/a b/.asus-swap/.swap',
        '/tmp/mnt/a\tb/.asus-swap/.swap', '/tmp/mnt/a\nb/.asus-swap/.swap',
        '/tmp/mnt/a\\b/.asus-swap/.swap']) {
        const encoded = activePath.replace(/\\/g, '\\134').replace(/ /g, '\\040')
            .replace(/\t/g, '\\011').replace(/\n/g, '\\012');
        fs.writeFileSync(swaps, 'Filename Type Size Used Priority\n' + encoded + ' file 1024 0 -1\n');
        for (const candidate of [activePath, activePath + '-not-active']) {
            const parsed = spawnSync('/usr/bin/awk', [parser, swaps], {
                env: { ...process.env, SWAP_CHECK_PATH: candidate }, encoding: 'utf8'
            });
            assert.equal(parsed.status, candidate === activePath ? 0 : 1, parsed.stderr);
        }
    }
    run('normal path with spaces', { success: true });
    const defaultMount = run('default-mount', { success: true, useDefault: true,
        privateDirectoryExists: false, mode: 0o777 });
    assert.ok(defaultMount.calls.some(call => call[0] === 'dd'));
    assert.ok(defaultMount.calls.some(call => call[0] === 'mkswap'));
    assert.ok(defaultMount.calls.some(call => call[0] === 'swapon'));
    assert.equal(fs.statSync(defaultMount.directory).mode & 0o7777, 0o1777);
    run('first-boot', { success: true, privateDirectoryExists: false, mode: 0o777 });
    run('custom', { success: true, env: { SWAP_NAME: 'private.swap' } });
    run('small-pool', { success: true, env: { SWAP_SIZE: '20000', SPACE: '15000' } });
    run('unsafe-parent', { env: { PARENT_MODE: 'drwxrwxrwx' } });
    run('sticky-parent', { success: true, env: { PARENT_MODE: 'drwxrwxrwt' } });
    run('untrusted-parent', { env: { PARENT_OWNER: '1' } });
    run('no-space', { env: { SPACE: '1' } });
    run('bad-size', { env: { SWAP_SIZE: 'invalid' } });
    run('bad-threshold', { env: { THRESHOLD: 'invalid' } });
    run('threshold-skip', { success: true, env: { THRESHOLD: '0' } });
    for (const mode of [0o777, 0o775, 0o757, 0o1777]) run('writable-root-' + mode, { mode, success: true });
    run('existing', { success: true, setup: target => fs.writeFileSync(target, 'existing', { mode: 0o666 }) });
    run('symlink', { setup: target => fs.symlinkSync('/nonexistent', target) });
    run('directory', { setup: target => fs.mkdirSync(target) });
    run('hardlink', { setup: target => {
        fs.writeFileSync(target + '.original', 'do not alter');
        fs.linkSync(target + '.original', target);
    } });
    run('wrong-owner', { env: { BAD_OWNER: '1' } });
    run('unenforced-mode', { env: { BAD_MODE: '1' } });
    run('unenforced-sticky', { mode: 0o777, env: { NO_STICKY: '1' } });
    run('untrusted-private-directory', { env: { PRIVATE_OWNER: '1' } });
    run('unenforced-private-mode', { env: { PRIVATE_MODE: '1' } });
    run('private-symlink', { privateDirectoryExists: false, setup: (target, directory) =>
        fs.symlinkSync(temporary, path.join(directory, '.asus-swap')) });
    for (const command of ['chown', 'chmod', 'dd', 'mkswap']) {
        const failed = run('failed-' + command, { env: { FAIL_COMMAND: command } });
        assert.ok(!fs.existsSync(failed.target));
        assert.ok(!fs.existsSync(failed.target + '.pending'));
    }
    run('failed-dd', { reuse: true, success: true });
    const existing = run('repeated', { success: true });
    const repeated = run('repeated', { reuse: true, success: true, env: { ALREADY_ACTIVE: '1' } });
    assert.ok(!repeated.calls.some(call => ['dd', 'mkswap', 'swapoff'].includes(call[0])));
    assert.equal(fs.readFileSync(existing.target, 'utf8'), 'swap-data');
    run('fstab-private', { success: true, fstab: true, setup: target => fs.writeFileSync(target, 'existing') });
    run('fstab-outside', { fstab: true, env: { FSTAB_PATH: '/tmp/.swap' } });
    run('fstab-missing', { fstab: true });
    run('pending-leftover', { setup: target => fs.writeFileSync(target + '.pending', 'interrupted') });
    for (const location of ['root', 'app']) {
        for (const dangling of [false, true]) {
            let outside, link;
            const rejected = run('legacy-link-' + location + '-' + dangling, {
                setup: (target, directory) => {
                    outside = path.join(temporary, path.basename(directory) + '-outside');
                    if (!dangling) fs.writeFileSync(outside, 'untouched');
                    const folder = location === 'app' ? path.join(directory, 'asusware.arm') : directory;
                    if (location === 'app') fs.mkdirSync(folder);
                    link = path.join(folder, '.swap');
                    fs.symlinkSync(outside, link);
                }
            });
            assert.ok(fs.lstatSync(link).isSymbolicLink());
            assert.equal(fs.existsSync(outside), !dangling);
            if (!dangling) assert.equal(fs.readFileSync(outside, 'utf8'), 'untouched');
            assert.ok(!rejected.calls.some(call => ['dd', 'mkswap', 'swapon', 'rm', 'swapoff'].includes(call[0])));
        }
        const migrated = run('legacy-' + location, { success: true, mode: 0o777,
            env: { ACTIVE_LEGACY: location }, setup: (target, directory) => {
                if (location === 'app') fs.mkdirSync(path.join(directory, 'asusware.arm'), { mode: 0o777 });
                fs.writeFileSync(path.join(directory, location === 'app' ? 'asusware.arm/.swap' : '.swap'),
                    'old swap', { mode: 0o666 });
            } });
        assert.ok(migrated.calls.some(call => call[0] === 'swapoff'));
        assert.ok(!fs.existsSync(path.join(migrated.directory, location === 'app' ? 'asusware.arm/.swap' : '.swap')));
    }
    const legacyFailure = run('legacy-stop-failure', { mode: 0o777,
        env: { ACTIVE_LEGACY: 'root', FAIL_COMMAND: 'swapoff' },
        setup: (target, directory) => fs.writeFileSync(path.join(directory, '.swap'), 'active', { mode: 0o666 }) });
    assert.equal(fs.readFileSync(path.join(legacyFailure.directory, '.swap'), 'utf8'), 'active');
    assert.equal(fs.statSync(path.join(legacyFailure.directory, '.swap')).mode & 0o777, 0o600);
    const removalFailure = run('legacy-remove-failure', { env: { FAIL_COMMAND: 'rm' },
        setup: (target, directory) => fs.writeFileSync(path.join(directory, '.swap'), 'keep') });
    assert.equal(fs.readFileSync(path.join(removalFailure.directory, '.swap'), 'utf8'), 'keep');
    assert.ok(removalFailure.calls.some(call => call[0] === 'rm'));
    assert.ok(!removalFailure.calls.some(call => ['dd', 'mkswap', 'swapon'].includes(call[0])));
    for (const filename of ['../escape', '-option', 'bad/name', 'bad\nname', '*'])
        run('invalid-' + cases, { env: { SWAP_NAME: filename } });
    const stopped = run('disable', { disable: true, success: true,
        setup: target => fs.writeFileSync(target, 'existing') });
    assert.ok(!fs.existsSync(stopped.target));
    const failedStop = run('failed-swapoff', { disable: true, env: { FAIL_COMMAND: 'swapoff' },
        setup: target => fs.writeFileSync(target, 'existing') });
    assert.ok(fs.existsSync(failedStop.target));
    run('disable-empty', { disable: true, success: true, privateDirectoryExists: false,
        mode: 0o777, env: { NO_STICKY: '1' } });

    const concurrentDirectory = path.join(temporary, 'concurrent');
    fs.mkdirSync(concurrentDirectory, { mode: 0o755 });
    fs.writeFileSync(log, '');
    const concurrent = spawnSync(process.execPath, ['-e', `
        const assert = require('node:assert/strict'), { spawn } = require('node:child_process');
        const options = { env: { ...process.env, BLOCK_DD: '1' }, stdio: ['pipe', 'pipe', 'pipe'] };
        const first = spawn('/bin/sh', [${JSON.stringify(script)}, ${JSON.stringify(concurrentDirectory)}, '1'], options);
        let second;
        const timer = setTimeout(() => { first.kill('SIGKILL'); if (second) second.kill('SIGKILL');
            process.exit(1); }, 15000);
        first.stdout.once('data', () => {
            second = spawn('/bin/sh', [${JSON.stringify(script)}, ${JSON.stringify(concurrentDirectory)}, '1'], options);
            second.stdin.end();
            first.stdin.end();
            second.on('exit', code => { assert.equal(code, 0); clearTimeout(timer); });
        });
        first.on('exit', code => assert.equal(code, 0));
    `], { encoding: 'utf8', env: { ...process.env, PATH: bin + ':' + process.env.PATH,
        CALL_LOG: log, PARENT_PATH: temporary, STATE_FILE: path.join(temporary, 'active-state') } });
    assert.equal(concurrent.status, 0, concurrent.stderr);
    const concurrentCalls = fs.readFileSync(log, 'utf8').trim().split('\n').map(line => JSON.parse(line));
    assert.equal(concurrentCalls.filter(call => call[0] === 'dd').length, 1);
    assert.equal(concurrentCalls.filter(call => call[0] === 'swapon').length, 1);
    cases++;

    if (process.getuid() === 0) {
        fs.chmodSync(temporary, 0o755);
        const directory = path.join(temporary, 'actual-root');
        fs.mkdirSync(directory, { mode: 0o755 });
        const target = path.join(directory, '.swap');
        fs.writeFileSync(target, 'private memory', { mode: 0o600 });
        const result = spawnSync(process.execPath, ['-e', `
            const fs = require('node:fs'), assert = require('node:assert/strict');
            for (const flags of ['r', 'r+'])
                assert.throws(() => fs.openSync(${JSON.stringify(target)}, flags), { code: 'EACCES' });
        `], { uid: 65534, gid: 65534, encoding: 'utf8' });
        assert.equal(result.status, 0, result.stderr);
    } else {
        console.log('SKIP: actual root/nobody EACCES checks require uid 0');
    }
    console.log('PASS: ' + cases + ' actual shell cases with mocked ownership/swap commands; Samba source contracts (not compiled C or SMB sessions)');
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}