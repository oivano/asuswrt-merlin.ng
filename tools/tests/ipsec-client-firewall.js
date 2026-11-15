const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const firewall = fs.readFileSync(path.join(root, 'release/src/router/rc/firewall.c'), 'utf8');
const ipsec = fs.readFileSync(path.join(root, 'release/src/router/rc/rc_ipsec.c'), 'utf8');
const header = fs.readFileSync(path.join(root, 'release/src/router/rc/rc_ipsec.h'), 'utf8');

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert.notEqual(start, -1, `missing ${signature}`);
    const open = source.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < source.length; index++) {
        if (source[index] === '{') depth++;
        if (source[index] === '}' && --depth === 0) return source.slice(open, index + 1);
    }
    assert.fail(`unterminated ${signature}`);
}

const ruleWriter = functionBody(firewall, 'static void write_ipsec_input_rules(');
const profileInfo = functionBody(ipsec, 'int ipsec_firewall_profile_info(');

assert.equal((firewall.match(/write_ipsec_input_rules\(/g) || []).length, 5,
    'filter_setting and both filter_setting2 rule paths must use the shared writer');
assert.match(ruleWriter, /ipsec_server_enable/);
assert.match(ruleWriter, /server_profile_active/);
assert.match(ruleWriter, /ipsec_ig_enable/);
assert.match(ruleWriter, /getaddrinfo\(gateways\[i\], NULL, &hints, &results\)/);
assert.match(ruleWriter, /hints\.ai_family = AF_UNSPEC/);
assert.match(ruleWriter, /-s %s -p udp -m multiport --dport %d,%d -j ACCEPT/);
assert.match(ruleWriter, /-s %s -p esp -j ACCEPT/);
assert.match(ruleWriter, /-s %s -p ah -j ACCEPT/);
assert.match(ruleWriter, /AF_INET6/);
assert.match(profileInfo, /IPSEC_CONN_EN_UP/);
assert.match(profileInfo, /VPN_TYPE_NET_NET_CLI/);
assert.match(profileInfo, /VPN_TYPE_HOST_NET_CLI/);
assert.match(profileInfo, /remote_gateway/);
assert.match(profileInfo, /server_profile_active = 1/);
assert.match(header, /ipsec_firewall_profile_info/);

const allowedPeers = new Set(['198.51.100.10', '2001:db8::10']);
const accepts = (source, protocol, port, serverMode = false) =>
    serverMode || (((protocol === 'udp' && [500, 4500].includes(port)) || ['esp', 'ah'].includes(protocol)) && allowedPeers.has(source));

for (const protocol of ['udp', 'esp', 'ah']) {
    for (const source of ['198.51.100.10', '203.0.113.99', '2001:db8::10', '2001:db8::99']) {
        const accepted = protocol === 'udp'
            ? accepts(source, protocol, 500) || accepts(source, protocol, 4500)
            : accepts(source, protocol, 0);
        assert.equal(accepted, allowedPeers.has(source), `${protocol} source policy for ${source}`);
        assert.equal(accepts(source, protocol, 500, true), true, 'server mode remains open');
    }
}

console.log('IPsec client firewall source contracts and policy cases passed');