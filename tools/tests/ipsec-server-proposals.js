const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const rc = read('release/src/router/rc/rc_ipsec.c');
const topology = rc.slice(rc.indexOf('void rc_ipsec_topology_set()\n{'),
    rc.indexOf('void rc_ipsec_nvram_convert_check('));
const policy = topology.match(/const char \*server_ike = "([^"]+)";/)[1];

assert.ok(policy.endsWith('!'), 'Do not append implicit strongSwan defaults');
const proposals = policy.slice(0, -1).split(',');
assert.ok(proposals.length > 0);
for (const proposal of proposals) {
    assert.match(proposal, /^aes256-sha256-(modp2048|modp3072|ecp256)$/);
}
assert.equal(proposals[0], 'aes256-sha256-modp2048');

const defaultWriter = topology.match(/fprintf\(fp,"conn %%default[^;]+;/)[0];
assert.match(defaultWriter, /ike=%s\\n", server_ike\);$/);
const serverWriter = topology.match(/else if\(VPN_TYPE_HOST_NET == prof\[prof_count\]\[i\]\.vpn_type\) \{([^}]+)\}/)[1];
assert.match(serverWriter, /fprintf\(fp,"  ike=%s\\n", server_ike\);/);
assert.doesNotMatch(serverWriter, /DH_GROUP_2|SHA1|modp(?:768|1024|1536)/);
assert.match(serverWriter, /dpdtimeout=30s/);
assert.match(topology, /if\(VPN_TYPE_HOST_NET != prof\[prof_count\]\[i\]\.vpn_type\s*&& VPN_TYPE_HOST_NET_CLI != prof\[prof_count\]\[i\]\.vpn_type\s*\)\{\s*ipsec_conf_phase1_set\(fp, i, prof_count\);\s*ipsec_conf_phase2_set\(fp, i, prof_count\);/);
assert.match(topology, /else\s*\{\s*fprintf\(fp,"  ike=%s-%s-%s\\n", encryp\[ENCRYPTION_TYPE_AES256\], hash\[HASH_TYPE_SHA1\], dh_group\[DH_GROUP_2\]\);/);

const stroke = read('release/src/router/strongswan/src/libcharon/plugins/stroke/stroke_config.c');
assert.match(stroke, /if \(\*strict == '!'\)[\s\S]*?if \(strict\)\s*\{\s*return TRUE;\s*\}[\s\S]*?proposal_create_default\(proto\)/);

const select = (configured, offered) => configured.find(proposal => offered.includes(proposal)) ?? null;
const weak = 'aes256-sha1-modp1024';
for (const ike of ['IKEv1', 'IKEv2']) {
    for (const strong of ['aes256-sha256-modp2048', 'aes256-sha256-ecp256']) {
        assert.equal(select(proposals, [weak, strong]), strong, ike);
        assert.equal(select(proposals, [strong, weak]), strong, ike);
    }
    assert.equal(select(proposals, [weak]), null, ike);
    assert.equal(select(proposals, ['aes256-sha256-modp1024']), null, ike);
    assert.equal(select(proposals, ['aes256-sha1-modp2048']), null, ike);
}
assert.equal(select([weak, ...proposals], [proposals[0], weak]), weak,
    'Negative control reproduces the old configured-first downgrade');

console.log('IPsec server proposal source contracts and selection models passed (not compiled C or live IKE).');