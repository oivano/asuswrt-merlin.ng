const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const firewall = fs.readFileSync(path.join(root, 'release/src/router/rc/firewall.c'), 'utf8');
const guard = firewall.match(/static void write_guest_nat_reflection_guard\([\s\S]*?\n\}/);

assert.ok(guard, 'guest reflection guard helper exists');
assert.match(guard[0], /guest_wlif\(ifname\)/);
assert.match(guard[0], /"%s_lanaccess", wif_to_vif\(ifname\)/);
assert.match(guard[0], /nvram_match\(nv, "off"\)/);
assert.match(guard[0], /-m physdev --physdev-in %s -d %s -j DROP/);
assert.strictEqual((firewall.match(/write_guest_nat_reflection_guard\(fp,/g) || []).length, 4);

function functionSource(signature) {
    const start = firewall.indexOf(signature);
    assert.notStrictEqual(start, -1, `${signature} exists`);
    const end = firewall.indexOf('\nvoid ', start + signature.length);
    return firewall.slice(start, end === -1 ? firewall.length : end);
}

for (const signature of [
    'void nat_setting(char *wan_if',
    'void nat_setting2(char *lan_if'
]) {
    const body = functionSource(signature);
    for (const wanAddress of ['wan_ip', 'wanx_ip']) {
        const guardIndex = body.indexOf(`write_guest_nat_reflection_guard(fp, ${wanAddress})`);
        assert.notStrictEqual(guardIndex, -1, `${signature} guards ${wanAddress}`);
        for (const chain of ['GAME_VSERVER', 'VSERVER']) {
            const reflection = body.slice(guardIndex).search(new RegExp(
                `fprintf\\(fp, "-A PREROUTING -d %s -j ${chain}\\\\n", ${wanAddress}\\)`
            ));
            assert.notStrictEqual(reflection, -1, `${wanAddress} ${chain} jump follows its guard`);
        }
    }
}

console.log('guest NAT reflection source contracts passed');