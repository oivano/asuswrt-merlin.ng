const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const ipsec = read('release/src/router/rc/rc_ipsec.c');
const openconnect = read('release/src/router/rc/rc_openconnect.c');
const underlay = ipsec.slice(ipsec.indexOf('static void _ipsec_underlay_bypass_rules'),
    ipsec.indexOf('static void _ipsec_updown_host_net_cli'));
const subnet = ipsec.slice(ipsec.indexOf('static void _get_my_ip_by_subnet',
    ipsec.indexOf('static void _ipsec_underlay_bypass_rules')),
    ipsec.indexOf('static void _ipsec_updown_net_net'));
const openconnectLog = openconnect.slice(openconnect.indexOf('static int openconnect_log_open'),
    openconnect.indexOf('/* Check if OpenConnect client is running */'));

assert.match(ipsec, /static FILE \*ipsec_state_open\(const char \*path, int create\)/);
assert.match(ipsec, /O_NOFOLLOW \| O_NONBLOCK/);
assert.match(ipsec, /st\.st_uid != 0 \|\| st\.st_gid != 0 \|\| st\.st_nlink != 1/);
assert.match(underlay, /ipsec_private_dir\(FILE_PATH_IPSEC_PRIVATE_DIR\)/);
assert.match(underlay, /FILE_PATH_IPSEC_PRIVATE_DIR "\/ipsec-wan-%d"/);
assert.match(underlay, /ipsec_state_open\(path, 0\)/);
assert.match(underlay, /ipsec_state_open\(temporary, 1\)/);
assert.match(underlay, /_ipsec_valid_ipv4_prefix\(network\)/);
assert.match(underlay, /_ipsec_valid_ipv4_gateway\(saved_gateway\)/);
assert.doesNotMatch(underlay, /"\/tmp\/ipsec-wan-|fopen\(|_ipsec_valid_route_prefix\(network\)/);
assert.match(subnet, /popen\(v6 \? "ip -6 route show table local"/);
assert.match(subnet, /pclose\(fp\)/);
assert.doesNotMatch(subnet, /system\(|\/tmp\/ipsec_my_subnet|>\s*\/tmp/);
assert.match(openconnectLog, /mkdir\(OPENCONNECT_LOG_DIR, 0700\)/);
assert.match(openconnectLog, /O_NOFOLLOW \| O_NONBLOCK/);
assert.match(openconnectLog, /st\.st_uid != 0 \|\| st\.st_gid != 0 \|\| st\.st_nlink != 1/);
assert.match(openconnectLog, /ftruncate\(descriptor, 0\)/);
assert.doesNotMatch(openconnect, /"\/tmp\/openconnect_client%d\.log"|O_TRUNC/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'ipsec-vpn-tmp-'));
try {
    fs.chmodSync(temporary, 0o1777);
    const privateDir = path.join(temporary, 'ipsec-private');
    fs.mkdirSync(privateDir, { mode: 0o700 });
    const victim = path.join(temporary, 'victim');
    fs.writeFileSync(victim, 'sentinel');
    const oldPaths = [
        'ipsec-wan-1', 'ipsec-wan-1.new', 'ipsec_my_subnet', 'openconnect_client1.log'
    ];
    for (const name of oldPaths)
        fs.symlinkSync(victim, path.join(temporary, name));
    assert.equal(fs.readFileSync(victim, 'utf8'), 'sentinel');
    for (const name of oldPaths)
        assert.equal(fs.readlinkSync(path.join(temporary, name)), victim);

    const planted = path.join(privateDir, 'openconnect_client1.log');
    fs.symlinkSync(victim, planted);
    assert.throws(() => fs.openSync(planted, fs.constants.O_WRONLY |
        fs.constants.O_CREAT | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600),
    { code: 'ELOOP' });
    assert.equal(fs.readFileSync(victim, 'utf8'), 'sentinel');
    console.log('PASS: VPN hook source contracts and host no-follow probes; old-path symlink sentinels remain untouched');
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}