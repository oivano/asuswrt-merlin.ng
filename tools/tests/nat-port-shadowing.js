const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const natCore = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/netfilter/nf_nat_core.c'), 'utf8');
const masqueradeTarget = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/netfilter/ipt_MASQUERADE.c'), 'utf8');
const firewall = fs.readFileSync(path.join(root, 'release/src/router/rc/firewall.c'), 'utf8');

const remapHelper = natCore.slice(natCore.indexOf('tuple_force_port_remap('),
    natCore.indexOf('/* Manipulate the tuple into the range given.'));
assert.match(remapHelper, /IPPROTO_TCP/);
assert.match(remapHelper, /IPPROTO_UDP/);
assert.match(remapHelper, /source_port < 16384 && destination_port >= 32768/);

const tupleSelection = natCore.slice(natCore.indexOf('get_unique_tuple('),
    natCore.indexOf('unsigned int\nnf_nat_setup_info('));
assert.match(tupleSelection, /maniptype == IP_NAT_MANIP_SRC/);
assert.match(tupleSelection, /inet_addr_type\(net, orig_tuple->src\.u3\.ip\) != RTN_LOCAL/);
assert.match(tupleSelection, /adjusted_range\.flags \|= IP_NAT_RANGE_PROTO_RANDOM/);
assert.match(tupleSelection, /range = &adjusted_range/);
assert.match(masqueradeTarget,
    /inet_addr_type\(nf_ct_net\(ct\),\s*ct->tuplehash\[IP_CT_DIR_ORIGINAL\]\.tuple\.src\.u3\.ip\) == RTN_LOCAL/);
assert.match(masqueradeTarget, /newrange\.flags &= ~IP_NAT_RANGE_PROTO_RANDOM/);

const wanMasqueradeRules = firewall.split('\n').filter(line =>
    line.includes('-A POSTROUTING %s -o %s ! -s %s -j MASQUERADE'));
assert.equal(wanMasqueradeRules.length, 10);
for (const rule of wanMasqueradeRules)
    assert.doesNotMatch(rule, /--random/);

function shouldAutomaticallyRemap(protocol, sourcePort, destinationPort, localSource) {
    return !localSource && ['tcp', 'udp'].includes(protocol) &&
        sourcePort < 16384 && destinationPort >= 32768;
}

for (const protocol of ['tcp', 'udp']) {
    assert.equal(shouldAutomaticallyRemap(protocol, 53, 40000, false), true);
    assert.equal(shouldAutomaticallyRemap(protocol, 1194, 50000, false), true);
    assert.equal(shouldAutomaticallyRemap(protocol, 500, 500, false), false);
    assert.equal(shouldAutomaticallyRemap(protocol, 500, 50000, true), false);
}
assert.equal(shouldAutomaticallyRemap('icmp', 53, 40000, false), false);
assert.equal(shouldAutomaticallyRemap('udp', 16384, 40000, false), false);
assert.equal(shouldAutomaticallyRemap('udp', 500, 32767, false), false);

console.log('NAT port-shadowing source contracts and threshold cases passed');