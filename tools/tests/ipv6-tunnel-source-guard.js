const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const firewall = read('release/src/router/rc/firewall.c');
const services = read('release/src/router/rc/services.c');
const sit = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/sit.c');
const kernelTunnelHeader = read('release/src-rt-6.x.4708/linux/linux-2.6.36/include/linux/if_tunnel.h');
const iprouteHeader = read('release/src/router/iproute2-3.x/include/linux/if_tunnel.h');
const iprouteTunnel = read('release/src/router/iproute2-3.x/ip/iptunnel.c');
const readme = read('README.md');

assert.match(kernelTunnelHeader, /struct ip_tunnel_6rd\s*\{[^}]*__be32\s+br_addr;/s);
assert.match(iprouteHeader, /struct ip_tunnel_6rd\s*\{[^}]*__be32\s+br_addr;/s);
assert.match(iprouteTunnel, /strcmp\(\*argv, "6rd-br"\)[\s\S]*?prefix\.bitlen != 32[\s\S]*?ip6rd\.br_addr/);
assert.match(services, /service == IPV6_6RD[\s\S]*?ipv6_6rd_router[\s\S]*?addr4\.s_addr == INADDR_ANY[\s\S]*?return;/);
assert.match(services, /"6rd-br", nvram_safe_get\(ipv6_nvname\("ipv6_6rd_router"\)\)/);

const receiveCheck = sit.slice(sit.indexOf('static inline int ipip6_tunnel_rcv_check'), sit.indexOf('static int ipip6_rcv'));
assert.match(receiveCheck, /if \(ip6rd_addr_to_4\(&ipv6h->saddr, tunnel, &embedded\)\)\s*\{\s*if \(embedded != iph->saddr\)\s*return 0;\s*\}\s*#ifdef CONFIG_IPV6_SIT_6RD\s*else if \(tunnel->ip6rd\.br_addr &&\s*iph->saddr != tunnel->ip6rd\.br_addr\)\s*return 0;\s*#endif/);
assert.match(sit, /ip6rd\.br_addr = t->ip6rd\.br_addr;/);
assert.match(sit, /t->ip6rd\.br_addr = ip6rd\.br_addr;/);
assert.match(sit, /t->ip6rd\.br_addr = 0;/);

const generators = firewall.split(/\nfilter_setting2?\(/).slice(1);
assert.equal(generators.length, 2);
for (const generator of generators) {
    const body = generator.slice(0, generator.indexOf('evalRet = eval("iptables-restore"'));
    const sixInFour = body.slice(body.indexOf('case IPV6_6IN4:'), body.indexOf('#ifdef RTCONFIG_SOFTWIRE46', body.indexOf('case IPV6_6IN4:')));
    assert.match(sixInFour, /case IPV6_6IN4:[\s\S]*?ipv6_tun_v4end[\s\S]*?inet_aton\(ip, &tunnel_peer\)[\s\S]*?-A INPUT -s %s -p 41 -j ACCEPT/);
    const sixToFourRd = body.slice(body.indexOf('case IPV6_6TO4:'), body.indexOf('case IPV6_6IN4:'));
    assert.match(sixToFourRd, /case IPV6_6TO4:[\s\S]*?case IPV6_6RD:[\s\S]*?-A INPUT -p 41 -j %s/);
    assert(!sixToFourRd.includes('ipv6_tun_v4end'));
}

assert.match(readme, /6to4 uses anycast[\s\S]*?source-\s*scoped IPv6 firewall rules do not authenticate the outer tunnel sender/);