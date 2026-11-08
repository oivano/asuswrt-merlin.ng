const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/rc/firewall.c'), 'utf8');
const start = source.indexOf('\nvoid add_mswan_rules(');
const end = source.indexOf('\n}\n#endif', start);
assert(start >= 0 && end > start, 'multiservice firewall function exists');
const body = source.slice(start, end);

assert.match(source, /mswan_reset_chain\(const char \*table, const char \*chain\)[\s\S]*?"-N", chain\)[\s\S]*?"-F", chain\)/,
    'owned chains are created when absent and flushed on every reconciliation');
assert.match(source, /while \(eval\("iptables", "-t", table, "-D", hook, "-j", chain\) == 0\)/,
    'duplicate hook jumps are removed before adding one');
const loop = body.indexOf('for (unit = WAN_UNIT_FIRST_MULTISRV_BASE;');
assert(loop > 0, 'service-unit reconciliation loop exists');
for (const chain of ['MSWAN_FORWARD', 'MSWAN_INPUT_PING', 'MSWAN_PREROUTING', 'MSWAN_POSTROUTING']) {
    const table = chain === 'MSWAN_PREROUTING' || chain === 'MSWAN_POSTROUTING' ? 'nat' : 'filter';
    const reset = body.indexOf(`mswan_reset_chain("${table}", "${chain}")`);
    assert(reset >= 0 && reset < loop, `${chain} is flushed before active units repopulate it`);
}

assert.doesNotMatch(body, /"-I", "FORWARD"/, 'service hook does not insert an unconditional FORWARD verdict');
assert.doesNotMatch(body, /"-A", "FORWARD"[\s\S]{0,100}"ACCEPT"/, 'no direct service FORWARD accept');
assert.match(body, /"-A", "MSWAN_FORWARD"\s*,\s*"-o", wan_ifname, "!", "-i", lan_ifname, "-j", logdrop/,
    'non-LAN traffic headed to a service interface is dropped');
assert.match(body, /mswan_attach_chain\("filter", "FORWARD", "MSWAN_FORWARD", 1\)/,
    'drop-only guard runs before the ordered FORWARD policy');
assert.match(body, /"-A", "MSWAN_INPUT_PING"[\s\S]*?"-A", "MSWAN_PREROUTING"[\s\S]*?"-A", "MSWAN_POSTROUTING"/,
    'dynamic input and NAT rules are confined to owned chains');
assert.match(body, /mswan_attach_chain\("filter", "INPUT_PING", "MSWAN_INPUT_PING", 0\)[\s\S]*?mswan_attach_chain\("nat", "PREROUTING", "MSWAN_PREROUTING", 0\)[\s\S]*?mswan_attach_chain\("nat", "POSTROUTING", "MSWAN_POSTROUTING", 0\)/,
    'each owned chain has one hook after reconciliation');
assert(body.indexOf('mswan_attach_chain("filter", "FORWARD", "MSWAN_FORWARD", 1)') > loop,
    'hooks are reattached only after the current unit set is rebuilt');
assert.match(body, /if \(!is_wan_connect\(unit\)\)\s+continue;[\s\S]*?if\(nvram_pf_match\(wan_prefix, "proto", "bridge"\)\)\s+continue;/,
    'only connected, non-bridge units repopulate owned chains');
assert.match(body, /if \(nvram_pf_get_int\(wan_prefix, "nat_x"\)\)[\s\S]*?MSWAN_PREROUTING[\s\S]*?MSWAN_POSTROUTING/,
    'service NAT remains conditional on nat_x');

console.log('PASS: multiservice WAN firewall rule ownership and forwarding policy contracts');