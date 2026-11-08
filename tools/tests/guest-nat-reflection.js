const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const firewall = fs.readFileSync(path.join(root, 'release/src/router/rc/firewall.c'), 'utf8');
const lan = fs.readFileSync(path.join(root, 'release/src/router/rc/lan.c'), 'utf8');
const kernelConfig = fs.readFileSync(path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36/config_base.6a'), 'utf8');
const physdevKconfig = fs.readFileSync(path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/Kconfig'), 'utf8');
const guard = firewall.match(/static void write_guest_nat_reflection_guard\([\s\S]*?\n\}/);

assert.ok(guard, 'guest reflection guard helper exists');
assert.match(guard[0], /guest_wlif\(ifname\)/);
assert.match(guard[0], /"%s_lanaccess", wif_to_vif\(ifname\)/);
assert.match(guard[0], /nvram_match\(nv, "off"\)/);
assert.match(guard[0], /-m mark --mark %s\/%s -d %s -j DROP/);
assert.match(guard[0], /BIT_GUEST_IPV4, BIT_GUEST_IPV4, wan_ip/);
assert.doesNotMatch(guard[0], /physdev/);
assert.strictEqual((firewall.match(/write_guest_nat_reflection_guard\(fp,/g) || []).length, 4);

assert.match(kernelConfig, /^# CONFIG_BRIDGE_NETFILTER is not set$/m,
    'DSL-AC68U kernel config excludes bridge netfilter');
assert.match(kernelConfig, /^CONFIG_NETFILTER_XT_MATCH_PHYSDEV=y$/m,
    'base config contains the stale xt_physdev request');
assert.match(kernelConfig, /^CONFIG_NETFILTER_XT_MATCH_MARK=y$/m,
    'DSL-AC68U kernel includes the iptables mark match');
assert.match(kernelConfig, /^CONFIG_BRIDGE_EBT_MARK_T=m$/m,
    'DSL-AC68U kernel includes the ebtables mark target');
assert.match(physdevKconfig, /config NETFILTER_XT_MATCH_PHYSDEV[\s\S]*?depends on BRIDGE && BRIDGE_NETFILTER/,
    'xt_physdev requires bridge netfilter, so the stale request is dropped');
const generatedConfigPath = path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36/.config');
if (fs.existsSync(generatedConfigPath)) {
    const generatedConfig = fs.readFileSync(generatedConfigPath, 'utf8');
    assert.match(generatedConfig, /^# CONFIG_BRIDGE_NETFILTER is not set$/m);
    assert.doesNotMatch(generatedConfig, /^CONFIG_NETFILTER_XT_MATCH_PHYSDEV=(?:y|m)$/m,
        'generated DSL-AC68U config cannot provide xt_physdev');
}
assert.match(lan, /"-p", "ipv4", "-j", "mark", "--mark-or", BIT_GUEST_IPV4/,
    'isolated guest ingress receives the IPv4 guest mark');

assert.match(firewall, /static int disable_inbound_nat\(void\)[\s\S]*?iptables", "-t", "nat", "-F", "PREROUTING"[\s\S]*?iptables", "-t", "nat", "-F", "OUTPUT"/,
    'safe fallback removes inbound and locally generated DNAT entry points');
const applyCheck = firewall.match(/void rule_apply_checking\([^\)]*\)\s*\{[\s\S]*?\n\}/);
assert.ok(applyCheck, 'firewall rule-apply error handler exists');
assert.match(applyCheck[0], /!strncmp\(rule_name, "nat_rules"/);
assert.match(applyCheck[0], /!strncmp\(rule_name, "redirect_rules"/);
assert.match(applyCheck[0], /!strncmp\(rule_name, "filter"/);
assert.match(applyCheck[0], /disable_inbound_nat\(\)/);
assert.match(applyCheck[0], /inbound NAT fallback %s/,
    'restore failures report the fallback result to syslog');

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