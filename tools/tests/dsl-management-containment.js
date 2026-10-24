const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/rc/firewall.c'), 'utf8');
const dsl = fs.readFileSync(path.join(root, 'release/src/router/rc/dsl.c'), 'utf8');
const managementAddress = dsl.match(/route_add\("vlan2", 0, "([^"]+)"/)[1];

for (const name of ['filter_setting', 'filter_setting2']) {
    const start = source.indexOf(`\n${name}(`);
    assert.ok(start >= 0);
    const end = source.indexOf('\n}\n', start);
    assert.ok(end > start);
    const body = source.slice(start, end);
    const guard = body.match(/#ifdef RTCONFIG_DSL_TCLINUX\s+fprintf\(fp, "(-A FORWARD -d ([^ ]+) -j DROP)\\n"\);\s+#endif/);
    assert.ok(guard, `${name}: unconditional DSL management drop`);
    assert.equal(guard[2], `${managementAddress}/32`);
    const before = body.slice(0, guard.index);
    assert.doesNotMatch(before, /-A FORWARD|add_GN_WBL_ChainRule\(/,
        `${name}: guard precedes forwarding rules and guest rule writer`);
    assert.doesNotMatch(before, /if\s*\(.*fw_enable_x/,
        `${name}: guard does not depend on the firewall toggle`);
    assert.ok(body.indexOf('--state ESTABLISHED,RELATED') > guard.index);
    const lanAccept = body.indexOf('"-A FORWARD -i %s -j %s\\n", lan_if, logaccept');
    assert.ok(lanAccept > guard.index);

    const tokens = guard[1].split(' ');
    assert.deepEqual(tokens, ['-A', 'FORWARD', '-d', `${managementAddress}/32`, '-j', 'DROP']);
    function verdict(packet, includeGuard = true) {
        if (includeGuard && packet.chain === tokens[1] &&
            packet.destination === tokens[3].split('/')[0]) return tokens[5];
        return 'ACCEPT';
    }
    for (const ingress of ['br0', 'br1', 'br2', 'wl0.1', 'tun11']) {
        for (const output of ['vlan2', 'vlan4090']) {
            for (const protocol of ['udp', 'tcp', 'icmp']) {
                for (const state of ['NEW', 'ESTABLISHED', 'RELATED']) {
                    const packet = {chain: 'FORWARD', destination: managementAddress,
                        ingress, output, protocol, state};
                    assert.equal(verdict(packet), 'DROP');
                    assert.equal(verdict(packet, false), 'ACCEPT', 'negative control');
                }
            }
        }
    }
    assert.equal(verdict({chain: 'OUTPUT', destination: managementAddress}), 'ACCEPT',
        'router-originated tp_init, tftp and ftpget bypass FORWARD');
    for (const destination of ['1.1.1.1', '192.168.1.1', '169.254.0.2']) {
        assert.equal(verdict({chain: 'FORWARD', destination}), 'ACCEPT');
    }
}

console.log('PASS: both DSL filter generators contain management forwarding before accepts; source/rule models only, not C or hardware execution');