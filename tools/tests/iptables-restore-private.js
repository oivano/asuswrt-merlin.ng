const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const rcHeader = read('release/src/router/rc/rc.h');
const init = read('release/src/router/rc/init.c');
const firewall = read('release/src/router/rc/firewall.c');
const services = read('release/src/router/rc/services.c');
const qosMultiwan = read('release/src/router/rc/qos_multiwan.c');

assert.match(rcHeader, /#define FIREWALL_RULES_DIR "\/tmp\/ppp\/firewall"/);
assert.match(rcHeader, /#define NAT_RULES\s+FIREWALL_RULES\("nat_rules"\)/);
const prepare = init.match(/static int rc_firewall_rules_dir_prepare\(void\)\s*\{([\s\S]*?)\n\}/);
assert.ok(prepare, 'early firewall rules directory preparation exists');
assert.match(prepare[1], /lstat\("\/tmp\/ppp", &parent\)/);
assert.match(prepare[1], /parent\.st_uid != 0/);
assert.match(prepare[1], /parent\.st_mode & 0022/);
assert.match(prepare[1], /mkdir\(FIREWALL_RULES_DIR, 0700\)/);
assert.match(prepare[1], /open\(FIREWALL_RULES_DIR, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(prepare[1], /S_ISDIR\(st\.st_mode\) && st\.st_uid == 0/);
assert.match(prepare[1], /fchmod\(fd, 0700\)/);
assert.match(prepare[1], /st\.st_mode & 0077/);
assert.match(init, /chmod\("\/tmp", 01777\);\s*if \(!rc_firewall_rules_dir_prepare\(\)\)/);
assert.ok(init.indexOf('rc_firewall_rules_dir_prepare()') < init.indexOf('start_services();'),
    'private directory is prepared before unprivileged services start');

for (const source of [firewall, services, qosMultiwan])
    assert.doesNotMatch(source, /\/tmp\/(?:filter_rules(?:_ipv6)?|nat_rules(?:_[^" ]+)?|filter\.default|filter_ipv6\.default|cap_apmode_filter\.default|hive_filter\.default|mangle_rules(?:_ipv6(?:\.[^" ]+)?)?)/,
        'restore file no longer uses a fixed world-writable /tmp path');
assert.match(firewall, /fopen\(FIREWALL_RULES\("filter_rules"\), "w"\)/);
assert.match(firewall, /eval\("iptables-restore", FIREWALL_RULES\("filter_rules"\)\)/);
assert.match(firewall, /fopen\(FIREWALL_RULES\("filter_rules_ipv6"\), "w"\)/);
assert.match(firewall, /eval\("ip6tables-restore", FIREWALL_RULES\("filter_rules_ipv6"\)\)/);
assert.match(firewall, /symlink\(name, NAT_RULES\)/);
assert.match(services, /eval\("iptables-restore", FIREWALL_RULES\("filter_rules"\)\)/);
assert.match(qosMultiwan, /mangle_fn = FIREWALL_RULES\("mangle_rules"\)/);

if (process.getuid && process.getuid() === 0) {
    const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'iptables-private-'));
    try {
        fs.chmodSync(temporary, 0o755);
        const directory = path.join(temporary, 'firewall');
        fs.mkdirSync(directory, { mode: 0o700 });
        const result = spawnSync('/bin/sh', ['-c', `
            touch "$1/filter_rules"
            ln -s /etc/passwd "$1/filter_rules_ipv6"
            mkfifo "$1/nat_rules_wan0"
        `, 'nobody', directory], { uid: 65534, gid: 65534, encoding: 'utf8' });
        assert.ifError(result.error);
        assert.notEqual(result.status, 0, 'unprivileged user cannot plant restore inputs');
        assert.deepEqual(fs.readdirSync(directory), []);
    } finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
}

console.log('PASS: iptables restore inputs use the root-only firewall directory');