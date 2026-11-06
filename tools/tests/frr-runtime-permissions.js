const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const base = 'release/src/router/frr-8.1/';
const common = read(base + 'files/frrcommon.sh');
const vty = read(base + 'lib/vty.c');
const staticMain = read(base + 'staticd/static_main.c');
const pidWriter = read(base + 'lib/pid_output.c');
const privs = read(base + 'lib/privs.c');
const watch = read(base + 'watchfrr/watchfrr.c');
const rc = read('release/src/router/rc/frr.c');
const ntpd = read('release/src/router/rc/ntpd.c');
const web = read('release/src/router/httpd/frr_web.c');
const services = read('release/src/router/rc/services.c');
const makefile = read('release/src/router/Makefile');
const functions = common.slice(common.indexOf('daemon_inst()'), common.indexOf('stop_watchfrr_first()'));
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'frr-runtime-'));
let cases = 0;
let captureCases = 0;

function shell(body, prefix = '') {
    const result = spawnSync('/bin/sh', ['-c', `
${functions}
ROOT_RUN_PATH=${JSON.stringify(temporary)}
V_PATH="$ROOT_RUN_PATH/daemons"
D_PATH=/usr/sbin
STOP_GRACE_TIMEOUT=0
STOP_TERM_TIMEOUT=0
STOP_KILL_TIMEOUT=0
MAX_FDS=1024
log_success_msg() { :; }
log_warning_msg() { :; }
log_failure_msg() { :; }
debug() { :; }
kill() { printf '%s\\n' "$*" >> "$ROOT_RUN_PATH/signals"; return 0; }
sleep() { echo 'unexpected wait' >&2; return 1; }
${prefix}
${body}
`], { encoding: 'utf8' });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr || result.stdout);
    cases++;
    return result.stdout.trim();
}

function stderrCaptureChecks() {
    const body = name => {
        const start = rc.indexOf(name + '(');
        assert.ok(start >= 0, name);
        const open = rc.indexOf('\n{', start);
        return rc.slice(open + 2, rc.indexOf('\n}', open));
    };
    const capture = body('frr_open_stderr_capture');
    const execute = body('frr_exec_script_capture_stderr');
    const log = body('frr_log_captured_stderr');
    assert.doesNotMatch(rc, /FRR_STDERR_LOG_FILE|frr-start\.stderr\.log/);
    assert.match(capture, /mkstemp\(path\)/);
    assert.match(capture, /!S_ISREG\(st.st_mode\).*st.st_uid != 0/);
    assert.match(capture, /st.st_nlink != 1.*st.st_mode & 0077/);
    assert.ok(capture.indexOf('unlink(path) < 0') < capture.indexOf('fdopen(fd'));
    assert.match(execute, /fd = fileno\(stderr_log\)/);
    assert.doesNotMatch(execute, /\bopen\(|\bfclose\(/);
    assert.doesNotMatch(execute.slice(execute.indexOf('\n\tif (waitpid')), /close\(fd\)/);
    assert.match(log, /rewind\(fp\)/);
    assert.doesNotMatch(log, /fopen\(|f_exists\(|fclose\(/);
    for (const name of ['start_frr', 'stop_frr', 'restart_frr']) {
        const lifecycle = body(name);
        assert.equal((lifecycle.match(/frr_open_stderr_capture\(\)/g) || []).length, 1, name);
        assert.match(lifecycle, /fclose\(stderr_log\)/, name);
        assert.doesNotMatch(lifecycle, /frr_invoke_script_capture\([^\n]*,\s*1\)/, name);
    }
    assert.match(body('restart_frr'), /if \(!is_frr_enabled\(\)\)[\s\S]*?stop_frr\(\);\s*return;/);

    const translated = capture
        .replace(/char path\[\] = "[^"]+";/, 'let path = template;')
        .replace(/struct stat st;/, 'let st = {};')
        .replace(/FILE \*fp;/, 'let fp;')
        .replace(/int fd;/, 'let fd;')
        .replace(/&st/g, 'st')
        .replace(/\bNULL\b/g, 'null')
        .replace(/\b0077\b/g, '0o77');
    const run = new Function('template', 'mkstemp', 'fstat', 'S_ISREG', 'fcntl',
        'F_SETFL', 'O_APPEND', 'unlink', 'close', 'fdopen', translated);
    const old = path.join(temporary, 'frr-start.stderr.log');
    const target = path.join(temporary, 'stderr-target');
    const formerName = path.join(temporary, 'frr-stderr-fixture');
    let attempts = 0;
    function openCapture(fault = '') {
        const descriptors = new Set();
        const stream = run(formerName, name => {
            attempts++;
            if (fault === 'mkstemp') return -1;
            try {
                const fd = fs.openSync(name, fs.constants.O_RDWR | fs.constants.O_CREAT |
                    fs.constants.O_EXCL | fs.constants.O_APPEND, 0o600);
                descriptors.add(fd);
                return fd;
            } catch { return -1; }
        }, (fd, st) => {
            const actual = fs.fstatSync(fd);
            Object.assign(st, {
                st_mode: actual.mode, st_uid: actual.uid === process.getuid() ? 0 : actual.uid,
                st_nlink: actual.nlink
            });
            if (fault === 'owner') st.st_uid = 65534;
            if (fault === 'type') st.st_mode = 0o010600;
            if (fault === 'links') st.st_nlink = 2;
            if (fault === 'mode') st.st_mode |= 0o044;
            return fault === 'fstat' ? -1 : 0;
        }, mode => (mode & 0o170000) === 0o100000,
            () => fault === 'fcntl' ? -1 : 0, 0, fs.constants.O_APPEND,
            name => {
                if (fault === 'unlink') return -1;
                fs.unlinkSync(name);
                return 0;
            }, fd => {
                descriptors.delete(fd);
                fs.closeSync(fd);
            }, (fd, mode) => {
                assert.equal(mode, 'r+');
                return fault === 'fdopen' ? null : fd;
            });
        assert.equal(descriptors.size, stream === null ? 0 : 1, fault);
        return stream;
    }

    for (const existing of [false, true]) {
        if (existing) fs.writeFileSync(target, 'sentinel\n');
        fs.symlinkSync(target, old);
        for (const enabled of [false, true]) {
            for (const action of ['start', 'stop', 'restart']) {
                const fd = openCapture();
                assert.notEqual(fd, null);
                assert.equal(fs.existsSync(formerName), false);
                fs.symlinkSync(target, formerName);
                const messages = enabled ? (action === 'restart' ? 'stop\nstart\nretry\n' : `${action}\n`) : '';
                for (const message of messages.match(/[^\n]+\n/g) || []) fs.writeSync(fd, message);
                const result = Buffer.alloc(256);
                const length = fs.readSync(fd, result, 0, result.length, 0);
                assert.equal(result.subarray(0, length).toString(), messages);
                assert.equal(fs.fstatSync(fd).nlink, 0);
                fs.closeSync(fd);
                fs.unlinkSync(formerName);
                assert.equal(fs.existsSync(target), existing);
                if (existing) assert.equal(fs.readFileSync(target, 'utf8'), 'sentinel\n');
                assert.equal(fs.lstatSync(old).isSymbolicLink(), true);
                captureCases++;
            }
        }
        fs.unlinkSync(old);
    }
    for (const fault of ['mkstemp', 'fstat', 'owner', 'type', 'links', 'mode', 'fcntl', 'unlink', 'fdopen']) {
        assert.equal(openCapture(fault), null, fault);
        if (fault === 'unlink') fs.unlinkSync(formerName);
        assert.equal(fs.existsSync(formerName), false, fault);
        captureCases++;
    }
    fs.symlinkSync(target, formerName);
    assert.equal(openCapture(), null);
    assert.equal(fs.readFileSync(target, 'utf8'), 'sentinel\n');
    fs.unlinkSync(formerName);
    assert.equal(attempts, 22);
    captureCases++;
}

function capabilityHardeningChecks() {
    const adminMapping = privs.slice(privs.indexOf('[ZCAP_SYS_ADMIN] ='));
    assert.match(adminMapping, /^\[ZCAP_SYS_ADMIN\] =\s*\{\s*0, NULL,/);

    const initStart = privs.indexOf('static void zprivs_caps_init(struct zebra_privs_t *zprivs)\n{');
    assert.ok(initStart >= 0, 'zprivs_caps_init must be present');
    const init = privs.slice(initStart);
    const boundingDrop = init.indexOf('prctl(PR_CAPBSET_DROP, CAP_SYS_ADMIN');
    const uidDrop = init.indexOf('setreuid(');

    assert.ok(boundingDrop >= 0, 'CAP_SYS_ADMIN must be dropped from the bounding set');
    assert.ok(uidDrop > boundingDrop, 'drop CAP_SYS_ADMIN before changing uid');
    assert.match(init.slice(boundingDrop, uidDrop), /exit\(1\)/,
        'fail closed if the bounding-set drop fails');
}

try {
    stderrCaptureChecks();
    capabilityHardeningChecks();
    fs.mkdirSync(path.join(temporary, 'daemons'));
    for (const script of ['frrcommon.sh', 'watchfrr.sh', 'frrinit.sh']) {
        const result = spawnSync('/bin/sh', ['-n', path.join(root, base, 'files', script)]);
        assert.equal(result.status, 0, script);
    }

    assert.match(common, /ROOT_RUN_PATH="\/var\/run\/frr"/);
    assert.match(common, /V_PATH="\$ROOT_RUN_PATH\/daemons"/);
    assert.match(common, /if \[ -n "\$FRR_CONFIG_DIR" \]; then[\s\S]*?PRIMARY_C_PATH="\$cfg_dir"[\s\S]*?fi\nfi/);
    assert.doesNotMatch(common, /nvram get frr_config_dir/);
    assert.match(common, /\. "\$DAEMONS_C_PATH\/daemons"/);
    assert.match(rc, /static int frr_config_dir_trusted\(const char \*path\)[\s\S]*?lstat\(checked, &st\)[\s\S]*?!S_ISDIR\(st\.st_mode\)[\s\S]*?st\.st_uid != 0[\s\S]*?st\.st_mode & 0022/);
    assert.match(rc, /if \(!nvram_get_int\("ntp_ready"\)\) \{\s*logmessage\("FRR", "deferring startup until NTP initial clock set"\);[\s\S]*?return;\s*\}/);
    assert.doesNotMatch(rc, /frr_should_defer_until_pppd|deferring startup until pppd/);
    const ntpdSync = ntpd.slice(ntpd.indexOf('int ntpd_synced_main'), ntpd.indexOf('\nstatic void set_alarm'));
    assert.match(ntpdSync, /nvram_set\("ntp_ready", "1"\);[\s\S]*logmessage\("ntpd", "Initial clock set"\);[\s\S]*notify_rc\("start_frr"\);/);
    assert.match(rc, /static int frr_daemons_file_trusted\(const char \*cfg_dir\)[\s\S]*?lstat\(path, &st\)[\s\S]*?errno == ENOENT[\s\S]*?S_ISREG\(st\.st_mode\)[\s\S]*?st\.st_uid == 0[\s\S]*?st\.st_mode & 0022/);
    assert.match(rc, /!frr_config_dir_trusted\(buf\) \|\| !frr_daemons_file_trusted\(buf\)/);
    assert.match(common, /chown 0:0 "\$ROOT_RUN_PATH" && chmod 0755 "\$ROOT_RUN_PATH"/);
    assert.match(common, /\[ ! -L "\$ROOT_RUN_PATH" \]/);
    assert.match(common, /\[ ! -L "\$V_PATH" \]/);
    assert.match(makefile, /--enable-user=frr[\s\S]*--enable-group=frr[\s\S]*--enable-vty-group=frrvty/);
    assert.match(common, /FRR_USER="frr"[\s\S]*FRR_GROUP="frr"[\s\S]*FRR_VTY_GROUP="frrvty"/);
    assert.match(common, /chown "\$FRR_USER:\$FRR_GROUP" "\$V_PATH" && chmod 0755 "\$V_PATH"/);
    assert.match(services, /#ifdef RTCONFIG_FRR\s+fprintf\(fp, "%s:%s:0:0:99999:7:0:0:\\n", "frr", "\*"\);/);
    assert.match(services, /"frr:x:65532:65532:frr:\/dev\/null:\/dev\/null\\n"/);
    assert.match(services, /"frr:\*:65532:\\n"[\s\S]*"frrvty:\*:65531:frr\\n"/);
    assert.doesNotMatch(rc, /frr_fix_run_dir_owner|chown\(FRR_RUN_DIR/);
    assert.doesNotMatch(read(base + 'files/watchfrr.sh'), /chownfrr/);
    assert.match(makefile, /--localstatedir=\/var\/run\/frr\/daemons/);
    assert.match(vty, /hostname = getenv\("FRR_VTY_BIND_ADDRESS"\);[\s\S]*hostname = "127\.0\.0\.1";/);
    assert.match(rc, /setenv\("FRR_VTY_BIND_ADDRESS", vty_addr, 1\);/);
    assert.match(rc, /strcmp\(frr_passwd, "zebra"\)[\s\S]*strcmp\(frr_enpasswd, "zebra"\)/);
    assert.match(rc, /open\("\/dev\/urandom", O_RDONLY\)/);
    assert.match(rc, /pw_enc\(password, encrypted, 1\)/);
    assert.match(rc, /nvram_commit\(\);/);
    assert.match(rc, /passwords_rotated \|\| force_regen/);
    assert.match(rc, /passwords_rotated \|\| !strcmp\(frr_ui_string\(request, "frr_passwd_changed"\), "1"\)/);
    assert.match(rc, /frr_runtime_passwords_match\(frr_passwd/);
    assert.ok(rc.indexOf('frr_sync_runtime_config(cfg_dir, daemons_path, conf_path);') <
        rc.lastIndexOf('setenv("FRR_VTY_BIND_ADDRESS", vty_addr, 1);'));
    assert.match(rc, /frr_lan_network_prefix\(lip, lnm, network/);
    assert.match(rc, /access-list vty permit %s\/%d/);
    assert.match(staticMain, /master = frr_init\(\);\s*access_list_init\(\);/);
    assert.match(common, /\$args \$pidopt \$\(daemon_pidfile\)/);
    assert.match(watch, /\{"pid-file", required_argument, NULL, 'p'\}/);
    assert.match(watch, /case 'p':\s*watchfrr_di\.pid_file = optarg;/);
    const tryRestart = watch.slice(watch.indexOf('static void try_restart(struct daemon *dmn)\n{'), watch.indexOf('\nstatic int wakeup_unresponsive'));
    assert.match(tryRestart, /gs\.special->state == DAEMON_UP\)\s*&& \(gs\.phase == PHASE_NONE\) && !gs\.restart\.pid/);
    for (const daemon of ['zebra', 'bgpd', 'bfdd'])
        assert.ok(web.includes(`/var/run/frr/daemons/${daemon}.vty`), daemon);
    assert.doesNotMatch(web, /"\/var\/run\/frr\/(?:%s\.pid|\w+\.vty)"/);
    for (const name of ['frr_daemon_running', 'frr_daemon_uptime']) {
        const start = web.indexOf(name + '(const char *daemon_name)');
        assert.ok(start >= 0, name);
        const body = web.slice(start, web.indexOf('\n}', start));
        if (name === 'frr_daemon_running') {
            assert.match(body, /frr_daemon_pid_from_file\(daemon_name\)/, name);
            assert.match(body, /frr_daemon_process_matches\(pid, daemon_name\)/, name);
        } else {
            assert.match(body, /if \(strcmp\(daemon_name, "watchfrr"\) == 0\)\s*strlcpy\(pid_file, "\/var\/run\/frr\/watchfrr\.pid", sizeof\(pid_file\)\);\s*else\s*snprintf\(pid_file, sizeof\(pid_file\), "\/var\/run\/frr\/daemons\/%s\.pid", daemon_name\);/, name);
        }
    }
    assert.match(web, /getsockopt\(fd, SOL_SOCKET, SO_PEERCRED, &credentials/);
    assert.match(web, /credentials\.pid == expected_pid/);
    assert.match(web, /proc_stat\.st_ino == daemon_stat\.st_ino/);
    assert.match(pidWriter, /O_RDWR \| O_CREAT \| O_NOFOLLOW \| O_NONBLOCK/);
    for (const check of ['!S_ISREG(st.st_mode)', 'st.st_uid != geteuid()',
        'st.st_nlink != 1', '(st.st_mode & 0022)'])
        assert.ok(pidWriter.includes(check), check);
    assert.ok(pidWriter.indexOf('fstat(fd') < pidWriter.indexOf('write(fd'));
    assert.ok(pidWriter.indexOf('F_SETLK') < pidWriter.indexOf('write(fd'));
    assert.match(watch, /open\(started, O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW, 0644\)/);
    assert.doesNotMatch(watch, /fopen\(started/);

    for (const [daemon, instance, expected] of [
        ['watchfrr', 'watchfrr', `${temporary}/watchfrr.pid`],
        ['zebra', 'zebra', `${temporary}/daemons/zebra.pid`],
        ['bgpd', 'bgpd-2', `${temporary}/daemons/bgpd-2.pid`]
    ]) {
        assert.equal(shell(`daemon=${daemon}; dmninst=${instance}; daemon_pidfile`), expected);
    }

    for (const daemon of ['watchfrr', 'zebra']) {
        const args = shell(`all_wrap=launch; daemon_start ${daemon}`, `
frr_prepare_run_dir() { return 0; }
daemon_prep() { return 0; }
wait_for_pppd_boot_ready() { return 0; }
vtysh_b() { return 0; }
launch() { printf '%s\\n' "$@"; }
`);
        const expected = daemon === 'watchfrr' ? `${temporary}/watchfrr.pid` : `${temporary}/daemons/zebra.pid`;
        assert.ok(args.startsWith(`/usr/sbin/${daemon}\n`));
        const pidOption = daemon === 'watchfrr' ? '-p' : '-i';
        assert.ok(args.endsWith(`${pidOption}\n${expected}`));
    }

    const runDirectory = path.join(temporary, 'run');
    const ownershipLog = path.join(temporary, 'ownership');
    const mockOwner = 'chown() { printf \'%s\\n\' "$*" >> "$ROOT_RUN_PATH/../ownership"; }';
    shell(`ROOT_RUN_PATH=${JSON.stringify(runDirectory)}; V_PATH="$ROOT_RUN_PATH/daemons";
FRR_USER=frr; FRR_GROUP=frr; frr_prepare_run_dir`, mockOwner);
    assert.equal(fs.statSync(runDirectory).mode & 0o777, 0o755);
    assert.equal(fs.statSync(path.join(runDirectory, 'daemons')).mode & 0o777, 0o755);
    assert.equal(fs.readFileSync(ownershipLog, 'utf8'), `0:0 ${runDirectory}\nfrr:frr ${runDirectory}/daemons\n`);
    fs.rmSync(path.join(runDirectory, 'daemons'), { recursive: true });
    fs.symlinkSync(temporary, path.join(runDirectory, 'daemons'));
    shell(`ROOT_RUN_PATH=${JSON.stringify(runDirectory)}; V_PATH="$ROOT_RUN_PATH/daemons";
! frr_prepare_run_dir`, mockOwner);
    const alias = path.join(temporary, 'alias');
    fs.symlinkSync(runDirectory, alias);
    shell(`ROOT_RUN_PATH=${JSON.stringify(alias)}; V_PATH="$ROOT_RUN_PATH/daemons";
! frr_prepare_run_dir`, 'chown() { echo unexpected-chown >&2; return 1; }');

    const pidfile = path.join(temporary, 'daemons/zebra.pid');
    const signals = path.join(temporary, 'signals');
    const reset = pid => {
        fs.writeFileSync(pidfile, pid);
        fs.writeFileSync(signals, '');
    };
    const matching = "readlink() { printf '%s\\n' /usr/sbin/zebra; }";
    for (const pid of ['1', '0', '-1', '01', '00', '+12', '2 3', '2\n3', 'abc', '']) {
        reset(pid);
        shell('daemon_stop zebra; result=$?; [ "$result" -eq 1 ] || [ ! -s "$V_PATH/zebra.pid" ]', matching);
        assert.equal(fs.readFileSync(signals, 'utf8'), '', pid);
        shell('! daemon_status zebra', matching);
    }
    reset('123');
    shell('! daemon_stop zebra', "readlink() { printf '%s\\n' /sbin/init; }");
    assert.equal(fs.readFileSync(signals, 'utf8'), '');
    shell('! daemon_status zebra', 'readlink() { return 1; }');

    reset('123');
    shell('! daemon_stop zebra', matching);
    assert.equal(fs.readFileSync(signals, 'utf8'), '-0 123\n-2 123\n-15 123\n-9 123\n');

    for (const signal of ['-2', '-15']) {
        reset('123');
        shell('daemon_stop zebra', `
readlink() {
    if grep -q -- '^${signal} ' "$ROOT_RUN_PATH/signals"; then
        printf '%s\\n' /sbin/init
    else
        printf '%s\\n' /usr/sbin/zebra
    fi
}`);
        const sent = fs.readFileSync(signals, 'utf8');
        assert.ok(sent.includes(`${signal} 123\n`));
        assert.ok(!sent.includes('-9 123\n'));
        if (signal === '-2') assert.ok(!sent.includes('-15 123\n'));
    }

    const executable = fs.realpathSync(process.execPath);
    shell(`D_PATH=${JSON.stringify(path.dirname(executable))}; daemon_pid_matches ${process.pid} ${JSON.stringify(path.basename(executable))}`);
    shell(`! daemon_pid_matches ${process.pid} zebra`);

    fs.writeFileSync(path.join(temporary, 'watchfrr.pid'), '1');
    fs.writeFileSync(signals, '');
    shell('! daemon_stop watchfrr', "readlink() { printf '%s\\n' /usr/sbin/watchfrr; }");
    assert.equal(fs.readFileSync(signals, 'utf8'), '');

    const target = path.join(temporary, 'target');
    const link = path.join(temporary, 'unsafe.pid');
    fs.writeFileSync(target, 'unchanged');
    fs.symlinkSync(target, link);
    assert.throws(() => fs.openSync(link, fs.constants.O_RDWR | fs.constants.O_CREAT |
        fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o644), { code: 'ELOOP' });
    assert.equal(fs.readFileSync(target, 'utf8'), 'unchanged');
    assert.throws(() => fs.openSync(link, fs.constants.O_WRONLY | fs.constants.O_CREAT |
        fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o644), { code: 'EEXIST' });
    assert.equal(fs.readFileSync(target, 'utf8'), 'unchanged');

    if (process.getuid() === 0) {
        fs.chmodSync(temporary, 0o755);
        const privateRun = path.join(temporary, 'private');
        fs.mkdirSync(privateRun, { mode: 0o755 });
        fs.writeFileSync(path.join(privateRun, 'watchfrr.pid'), '123', { mode: 0o644 });
        const frrRun = path.join(privateRun, 'daemons');
        fs.mkdirSync(frrRun, { mode: 0o755 });
        fs.chownSync(frrRun, 65532, 65532);
        fs.writeFileSync(path.join(frrRun, 'zebra.vty'), '', { mode: 0o770 });
        fs.chownSync(path.join(frrRun, 'zebra.vty'), 65532, 65531);
        fs.chmodSync(path.join(frrRun, 'zebra.vty'), 0o770);
        fs.writeFileSync(path.join(frrRun, 'zserv.api'), '', { mode: 0o700 });
        fs.chownSync(path.join(frrRun, 'zserv.api'), 65532, 65532);
        fs.chmodSync(path.join(frrRun, 'zserv.api'), 0o700);
        const result = spawnSync(process.execPath, ['-e', `
            const fs = require('node:fs'), assert = require('node:assert/strict');
            const directory = ${JSON.stringify(privateRun)};
            assert.throws(() => fs.writeFileSync(directory + '/watchfrr.pid', '1'), { code: 'EACCES' });
            assert.throws(() => fs.unlinkSync(directory + '/watchfrr.pid'), { code: 'EACCES' });
            assert.throws(() => fs.symlinkSync('/etc/passwd', directory + '/new.pid'), { code: 'EACCES' });
            assert.throws(() => fs.writeFileSync(directory + '/daemons/new.pid', '1'), { code: 'EACCES' });
            assert.throws(() => fs.unlinkSync(directory + '/daemons/zebra.vty'), { code: 'EACCES' });
            assert.throws(() => fs.accessSync(directory + '/daemons/zebra.vty', fs.constants.W_OK), { code: 'EACCES' });
            assert.throws(() => fs.accessSync(directory + '/daemons/zserv.api', fs.constants.W_OK), { code: 'EACCES' });
        `], { uid: 65534, gid: 65534, encoding: 'utf8' });
        assert.equal(result.status, 0, result.stderr);
    } else {
        console.log('SKIP: actual root/nobody directory-access tests require uid 0');
    }
    console.log(`PASS: ${captureCases} source-translated capture/filesystem checks; ${cases} actual shell checks, intercepted stop signals, runtime path contracts and host nofollow check`);
    console.log('NOTE: C and firmware not compiled; router startup/recovery still requires hardware validation');
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}