const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const core = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/core.c');
const init = read('release/src/router/rc/sysdeps/init-broadcom.c');
const common = read('release/src/router/rc/common.c');
const defaults = read('release/src/router/shared/defaults.c');
const body = (source, start, end) => {
    const offset = source.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = source.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return source.slice(offset, limit);
};

const slow = body(core, 'int nf_hook_slow(', 'EXPORT_SYMBOL(nf_hook_slow);');
assert.doesNotMatch(core, /lfp_hit_hook|NFC_LFP_ENABLE/,
    'LFP must not bypass registered netfilter hooks, even when enabled or cached');
const beforeIterate = slow.slice(slow.indexOf('{'), slow.indexOf('verdict = nf_iterate('));
assert.match(slow, /verdict = nf_iterate\(&nf_hooks\[pf\]\[hook\], skb, hook, indev,/);
assert.doesNotMatch(beforeIterate, /\breturn\b|\bgoto\b/,
    'no early acceptance before registered hooks run');
assert.match(slow, /verdict == NF_DROP\)\s*\{\s*kfree_skb\(skb\);\s*ret = -EPERM;/,
    'preserve filter drop verdicts');
console.log('PASS: LFP cannot short-circuit netfilter dispatch (source contract)');

const boot = body(init, '#ifdef RTCONFIG_SHP', '#endif');
assert.doesNotMatch(boot, /nvram_set\("lfp_disable", "0"\)/,
    'boot must not override an operator disable');
assert.match(boot, /if \(nvram_get_int\("qos_enable"\) == 1 \|\| nvram_get_int\("lfp_disable_force"\)\) \{\s*nvram_set\("lfp_disable", "1"\);\s*\}\s*restart_lfp\(\);/,
    'boot retains QoS/forced disable and always refreshes kernel state');
assert.match(defaults, /\{ "lfp_disable", "1",/,
    'factory default disables LFP');
const restart = body(common, 'void restart_lfp()', '#endif');
assert.match(restart, /if\(nvram_get_int\("lfp_disable"\)==0\)/);
assert.match(restart, /else\s*\{\s*f_write_string\("\/proc\/net\/lfpctrl", "", 0, 0\);/,
    'disabled LFP clears the actual lfpctrl proc entry');

for (const disabled of [0, 1]) {
    for (const qos of [0, 1]) {
        for (const forced of [0, 1]) {
            let stored = disabled;
            const executeBoot = new Function('nvram_get_int', 'nvram_set', 'restart_lfp',
                boot.replace('#ifdef RTCONFIG_SHP', ''));
            executeBoot(key => ({lfp_disable: stored, qos_enable: qos, lfp_disable_force: forced})[key],
                (key, value) => {
                    assert.equal(key, 'lfp_disable');
                    stored = Number(value);
                }, () => assert.equal(stored, disabled || qos || forced));
            assert.equal(stored, disabled || qos || forced);
        }
    }
}
console.log('PASS: default-off, persistent disable, and QoS/force boot models (not compiled C)');