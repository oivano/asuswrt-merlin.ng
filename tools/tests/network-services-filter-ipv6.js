const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.resolve(__dirname, '../../release/src/router/rc/firewall.c'), 'utf8');
const start = source.indexOf('filter_setting(int wan_unit');
const end = source.indexOf('evalRet = eval("iptables-restore"', start);
assert(start >= 0 && end > start, 'single-WAN filter_setting() is present');
const body = source.slice(start, end);

const ipv4Jump = body.indexOf('fprintf(fp, "-A FORWARD -j %s\\n", chain);');
const ipv6Jump = body.indexOf('fprintf(fp_ipv6, "-A FORWARD -j %s\\n", chain);');
const ipv6Policy = body.indexOf('fprintf(fp_ipv6, "-A %s -i %s -o %s -j %s\\n", chain, lan_if, wan6face, dtype);');
const ipv6WanAccept = body.indexOf('fprintf(fp_ipv6, "-A FORWARD -o %s -i %s -j %s\\n", wan6face, lan_if, logaccept);');
assert(ipv4Jump >= 0, 'IPv4 FORWARD dispatches through NSFW');
assert(ipv6Jump > ipv4Jump, 'IPv6 FORWARD dispatches through NSFW');
assert(ipv6Jump < ipv6Policy && ipv6Policy < ipv6WanAccept,
    'IPv6 NSFW dispatch and policy precede the WAN6 accept');

assert(body.includes('fprintf(fp_ipv6, "-A %s %s -i %s -o %s -p ipv6-icmp --icmpv6-type %s -j %s\\n", chain, g, lan_if, wan6face, ptr, ftype);'),
    'IPv6 ICMP filter entries use the configured ICMPv6 type');
assert(body.includes('fprintf(fp_ipv6, "-I %s -i %s -o %s -p tcp --dport %d -j DROP\\n", chain, lan_if, wan6face, 1723);'));
assert(body.includes('fprintf(fp_ipv6, "-I %s -i %s -o %s -p 47 -j DROP\\n", chain, lan_if, wan6face);'));
assert(body.includes('fprintf(fp_ipv6, "-I %s -i %s -o %s -p udp --dport %d -j DROP\\n", chain, lan_if, wan6face, 1701);'));
assert(body.includes('fprintf(fp_ipv6, "-I %s -i %s -o %s -p udp --dport %d -j DROP\\n", chain, lan_if, wan6face, 500);'));
assert(body.includes('fprintf(fp_ipv6, "-I %s -i %s -o %s -p udp --dport %d -j DROP\\n", chain, lan_if, wan6face, 4500);'));
assert(body.includes('fprintf(fp_ipv6, "-I %s -i %s -o %s -p 50 -j DROP\\n", chain, lan_if, wan6face);'));
assert(body.includes('fprintf(fp_ipv6, "-I %s -i %s -o %s -p 51 -j DROP\\n", chain, lan_if, wan6face);'));

const dhcpv6Accepts = [...source.matchAll(/fprintf\([^;]*--dport 546[^;]*;/gs)];
assert.equal(dhcpv6Accepts.length, 4,
    'all four direct DHCPv6 client accepts are covered');
for (const [rule] of dhcpv6Accepts) {
    assert.match(rule, /-i %s -s fe80::\/10/,
        'direct DHCPv6 accepts are limited to link-local sources on a specific interface');
    assert.match(rule, /get_wan6face\(\)/,
        'direct DHCPv6 accepts use the interface bound by odhcp6c');
}
assert.doesNotMatch(source, /-A INPUT -p udp --sport 547 --dport 546/,
    'no unrestricted DHCPv6 client accept remains');

const dualStart = source.indexOf('filter_setting2(char *lan_if');
const dualRestore = source.indexOf('evalRet = eval("iptables-restore"', dualStart);
assert(dualStart >= 0 && dualRestore > dualStart, 'dual-WAN firewall generator is present');
const dualBody = source.slice(dualStart, dualRestore);
const establishedRule = 'fprintf(fp_ipv6, "-A INPUT -m state --state RELATED,ESTABLISHED -j %s\\n", logaccept);';
const scopedRule = 'fprintf(fp_ipv6, "-A INPUT -i %s -s fe80::/10 -p udp --sport 547 --dport 546';
for (const [name, firewallBody] of [['single-WAN', body], ['dual-WAN', dualBody]]) {
    assert(firewallBody.indexOf(establishedRule) >= 0 &&
        firewallBody.indexOf(establishedRule) < firewallBody.indexOf(scopedRule),
        `${name} conntrack accept remains before the link-local-only DHCPv6 accept`);
}

console.log('PASS: single-WAN IPv6 Network Services Filter dispatch, ordering, ICMP and VPN passthrough contracts');