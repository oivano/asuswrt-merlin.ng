const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const base = 'release/src/router/frr-8.1/';
const common = read(base + 'files/frrcommon.sh');
const pidWriter = read(base + 'lib/pid_output.c');
const watch = read(base + 'watchfrr/watchfrr.c');
const rc = read('release/src/router/rc/frr.c');
const web = read('release/src/router/httpd/frr_web.c');
const makefile = read('release/src/router/Makefile');
const functions = common.slice(common.indexOf('daemon_inst()'), common.indexOf('stop_watchfrr_first()'));
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'frr-runtime-'));
let cases = 0;

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

try {
    fs.mkdirSync(path.join(temporary, 'daemons'));
    for (const script of ['frrcommon.sh', 'watchfrr.sh', 'frrinit.sh']) {
        const result = spawnSync('/bin/sh', ['-n', path.join(root, base, 'files', script)]);
        assert.equal(result.status, 0, script);
    }

    assert.match(common, /ROOT_RUN_PATH="\/var\/run\/frr"/);
    assert.match(common, /V_PATH="\$ROOT_RUN_PATH\/daemons"/);
    assert.match(common, /chown 0:0 "\$ROOT_RUN_PATH" && chmod 0755 "\$ROOT_RUN_PATH"/);
    assert.match(common, /\[ ! -L "\$ROOT_RUN_PATH" \]/);
    assert.match(common, /\[ ! -L "\$V_PATH" \]/);
    assert.doesNotMatch(rc, /frr_fix_run_dir_owner|chown\(FRR_RUN_DIR/);
    assert.doesNotMatch(read(base + 'files/watchfrr.sh'), /chownfrr/);
    assert.match(makefile, /--localstatedir=\/var\/run\/frr\/daemons/);
    assert.match(common, /\$args \$pidopt \$\(daemon_pidfile\)/);
    assert.match(watch, /\{"pid-file", required_argument, NULL, 'p'\}/);
    assert.match(watch, /case 'p':\s*watchfrr_di\.pid_file = optarg;/);
    for (const daemon of ['zebra', 'bgpd', 'bfdd'])
        assert.ok(web.includes(`/var/run/frr/daemons/${daemon}.vty`), daemon);
    assert.doesNotMatch(web, /"\/var\/run\/frr\/(?:%s\.pid|\w+\.vty)"/);
    for (const name of ['frr_daemon_running', 'frr_daemon_uptime']) {
        const start = web.indexOf(name + '(const char *daemon_name)');
        assert.ok(start >= 0, name);
        const body = web.slice(start, web.indexOf('\n}', start));
        assert.match(body, /if \(strcmp\(daemon_name, "watchfrr"\) == 0\)\s*strlcpy\(pid_file, "\/var\/run\/frr\/watchfrr\.pid", sizeof\(pid_file\)\);\s*else\s*snprintf\(pid_file, sizeof\(pid_file\), "\/var\/run\/frr\/daemons\/%s\.pid", daemon_name\);/, name);
    }
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
FRR_USER=nobody; FRR_GROUP=nobody; frr_prepare_run_dir`, mockOwner);
    assert.equal(fs.statSync(runDirectory).mode & 0o777, 0o755);
    assert.equal(fs.statSync(path.join(runDirectory, 'daemons')).mode & 0o777, 0o755);
    assert.equal(fs.readFileSync(ownershipLog, 'utf8'), `0:0 ${runDirectory}\nnobody:nobody ${runDirectory}/daemons\n`);
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
        const nobodyRun = path.join(privateRun, 'daemons');
        fs.mkdirSync(nobodyRun, { mode: 0o755 });
        fs.chownSync(nobodyRun, 65534, 65534);
        const result = spawnSync(process.execPath, ['-e', `
            const fs = require('node:fs'), assert = require('node:assert/strict');
            const directory = ${JSON.stringify(privateRun)};
            assert.throws(() => fs.writeFileSync(directory + '/watchfrr.pid', '1'), { code: 'EACCES' });
            assert.throws(() => fs.unlinkSync(directory + '/watchfrr.pid'), { code: 'EACCES' });
            assert.throws(() => fs.symlinkSync('/etc/passwd', directory + '/new.pid'), { code: 'EACCES' });
            fs.writeFileSync(directory + '/daemons/zebra.pid', '1');
        `], { uid: 65534, gid: 65534, encoding: 'utf8' });
        assert.equal(result.status, 0, result.stderr);
    } else {
        console.log('SKIP: actual root/nobody directory-access tests require uid 0');
    }
    console.log(`PASS: ${cases} actual shell checks, intercepted stop signals, runtime path contracts and host nofollow check`);
    console.log('NOTE: C and firmware not compiled; router startup/recovery still requires hardware validation');
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}