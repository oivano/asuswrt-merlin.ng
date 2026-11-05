const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const lan = fs.readFileSync(path.join(root, 'release/src/router/rc/lan.c'), 'utf8');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const firewall = fs.readFileSync(path.join(root, 'release/src/router/rc/firewall.c'), 'utf8');
const rcHeader = fs.readFileSync(path.join(root, 'release/src/router/rc/rc.h'), 'utf8');
const kernelConfig = fs.readFileSync(path.join(
	root,
	'release/src-rt-6.x.4708/linux/linux-2.6/config_base.6a'
), 'utf8');
const ebtMarkTarget = fs.readFileSync(path.join(
	root,
	'release/src-rt-6.x.4708/linux/linux-2.6/net/bridge/netfilter/ebt_mark.c'
), 'utf8');
const bridgeInput = fs.readFileSync(path.join(
	root,
	'release/src-rt-6.x.4708/linux/linux-2.6.36/net/bridge/br_input.c'
), 'utf8');
const ip6Match = fs.readFileSync(path.join(
	root,
	'release/src-rt-6.x.4708/linux/linux-2.6.36/net/bridge/netfilter/ebt_ip6.c'
), 'utf8');
const ip6Header = fs.readFileSync(path.join(
	root,
	'release/src-rt-6.x.4708/linux/linux-2.6.36/include/linux/netfilter_bridge/ebt_ip6.h'
), 'utf8');

assert.match(lan, /eval\("ebtables", "--concurrent", "-t", "filter"/);
assert.match(rcHeader, /#define BIT_GUEST_IPV6\s+"0x200"/);
assert.match(kernelConfig, /CONFIG_BRIDGE_EBT_MARK_T=m/);
assert.match(kernelConfig, /CONFIG_NETFILTER_XT_MATCH_MARK=y/);
assert.match(ebtMarkTarget, /skb->mark \|= info->mark/);
assert.doesNotMatch(lan, /GUEST_ARP_EBTABLES\("-C"/);
assert.match(lan, /"--arp-mac-src", binding->mac,[\s\S]*?"--arp-ip-src", binding->ip/);
assert.match(lan, /"--arp-ip-src", "0\.0\.0\.0", "-j", "ACCEPT"/);
assert.match(lan, /"-p", "arp",[\s\S]*?"-j", "DROP"/);
assert.match(lan, /#define GUEST_ARP_SOURCE_CHAIN "GUESTSRC"/);
assert.match(lan, /"-s", binding->mac, "-p", "ipv4", "--ip-src", binding->ip,[\s\S]*?"-j", "ACCEPT"/);
assert.match(lan, /"--ip-sport", "68",[\s\S]*?"--ip-dport", "67", "-j", "ACCEPT"/);
assert.match(lan, /GUEST_ARP_SOURCE_CHAIN, "-i", active_ifnames\[i\],[\s\S]*?"-p", "ipv4", "-j", "DROP"/);
assert.match(lan, /"-I", "INPUT", "1", "-i", active_ifnames\[i\],[\s\S]*?"-j", GUEST_ARP_SOURCE_CHAIN/);
assert.match(lan, /"-D", GUEST_ARP_SOURCE_CHAIN, "-i", binding->ifname,[\s\S]*?"--ip-src", binding->ip,[\s\S]*?"-j", "ACCEPT"/);
assert.match(lan, /"--ip6-icmp-type", "neighbour-solicitation"/);
assert.match(lan, /"--ip6-icmp-type", "neighbour-advertisement"/);
assert.match(lan, /GUEST_ARP_EBTABLES\("-D", "INPUT", "-i", cleanup_ifnames\[i\], "-p", "IPv6"[\s\S]*?"neighbour-solicitation"/);
assert.match(lan, /GUEST_ARP_EBTABLES\("-D", "INPUT", "-i", cleanup_ifnames\[i\], "-p", "IPv6"[\s\S]*?"neighbour-advertisement"/);
assert.match(ip6Header, /#define EBT_IP6_ICMP6 0x40/);
assert.match(ip6Header, /uint8_t icmpv6_type\[2\]/);
assert.match(ip6Header, /uint8_t icmpv6_code\[2\]/);
assert.match(ip6Match, /skb_header_pointer\(skb, offset_ph,[\s\S]*?icmp6h->icmp6_type[\s\S]*?icmp6h->icmp6_code/);
assert.match(ip6Match, /!\(info->bitmask & EBT_IP6_PROTO\)/);
assert.match(ip6Match, /info->protocol != IPPROTO_ICMPV6/);
assert.match(lan, /guest_arp_binding_find\(current_bindings, current_count,[\s\S]*?binding->ifname, binding->mac, binding->ip\)/);
assert.match(lan, /guest_arp_save_state\(state_dirfd, current_bindings, current_count\)/);
assert.match(lan, /#define GUEST_ARP_STATE_DIR "\/tmp\/guest-arp"/);
const stateLoad = lan.match(/static int guest_arp_load_state\([\s\S]*?\n\}/)[0];
const stateSave = lan.match(/static int guest_arp_save_state\([\s\S]*?\n\}/)[0];
assert.match(lan, /open\(GUEST_ARP_STATE_DIR, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(lan, /st\.st_uid != 0[\s\S]*?st\.st_gid != 0[\s\S]*?fchmod\(fd, 0700\)/);
assert.match(stateLoad, /openat\(dirfd, GUEST_ARP_STATE_NAME, O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK\)/);
assert.match(stateLoad, /S_ISREG\(st\.st_mode\)[\s\S]*?st\.st_uid != 0[\s\S]*?st\.st_nlink != 1/);
assert.doesNotMatch(stateLoad, /fopen\(|GUEST_ARP_STATE_FILE/);
assert.match(stateSave, /O_CREAT \| O_EXCL \| O_NOFOLLOW \| O_NONBLOCK/);
assert.match(stateSave, /S_ISREG\(st\.st_mode\)[\s\S]*?st\.st_uid != 0[\s\S]*?st\.st_nlink != 1/);
assert.match(stateSave, /renameat\(dirfd, GUEST_ARP_STATE_TMP_NAME,[\s\S]*?dirfd, GUEST_ARP_STATE_NAME\)/);
assert.doesNotMatch(stateSave, /\bfopen\(|\bchmod\(|\brename\(|GUEST_ARP_STATE_TMP_FILE/);
assert.match(lan, /active = is_router_mode\(\) && find_in_list\(lan_ifnames, ifnames\[i\]\) &&[\s\S]*?nvram_match\(key, "off"\)/);
assert.match(lan, /guest_arp_filter_refresh\(\);/);
assert.match(lan, /void lanaccess_wl\(void\)[\s\S]*?guest_arp_filter_refresh\(\);/);
assert.match(services, /int dnsmasq_script_main\([\s\S]*?guest_arp_filter_refresh\(\);/);

const bridgeFinish = bridgeInput.match(/int br_handle_frame_finish\(struct sk_buff \*skb\)[\s\S]*?\n\}/)[0];
const bridgePassFrameUp = bridgeInput.match(/static int br_pass_frame_up\(struct sk_buff \*skb\)[\s\S]*?\n\}/)[0];
const sourceIsolation = bridgeFinish.indexOf('if (p->flags & BR_ISOLATE_MODE)');
const multicastForward = bridgeFinish.indexOf('br_multicast_forward(mdst, skb, skb2)');
const floodForward = bridgeFinish.indexOf('br_flood_forward(br, skb, skb2)');
assert.ok(sourceIsolation >= 0 && sourceIsolation < multicastForward && sourceIsolation < floodForward);
assert.match(bridgePassFrameUp, /NF_HOOK\(NFPROTO_BRIDGE, NF_BR_LOCAL_IN,[\s\S]*?netif_receive_skb/);
assert.match(bridgeFinish, /if \(p->flags & BR_ISOLATE_MODE\) \{\s*skb2 = skb;\s*skb = NULL;\s*\} else if \(is_multicast_ether_addr\(dest\)\)/);

const guestIsolation = lan.match(/void lanaccess_mssid\([\s\S]*?\n\}/)[0];
assert.match(guestIsolation,
	/while \(eval\("ebtables", "-t", "filter", "-D", "INPUT", "-i", lifname,[\s\S]*?"-p", "IPv6", "-j", "mark", "--mark-or", BIT_GUEST_IPV6,[\s\S]*?"--mark-target", "CONTINUE"\) == 0\)/);
assert.match(guestIsolation,
	/if \(mode && eval\("ebtables", "-t", "filter", "-I", "INPUT", "1", "-i", lifname,[\s\S]*?"-p", "IPv6", "-j", "mark", "--mark-or", BIT_GUEST_IPV6,[\s\S]*?"--mark-target", "CONTINUE"\) != 0\)/);
assert.match(guestIsolation,
	/if \(mode\) \{\s*eval\("ebtables", "-I", "FORWARD", "1", "-i", lifname, "-j", "DROP"\);[\s\S]*?eval\("ebtables", "-I", "FORWARD", "1", "-o", lifname, "-j", "DROP"\);/);
assert.match(guestIsolation,
	/eval\("ebtables", "-D", "FORWARD", "-i", lifname, "-j", "DROP"\);[\s\S]*?eval\("ebtables", "-D", "FORWARD", "-o", lifname, "-j", "DROP"\);/);

const ipv6Filter = firewall.match(/FIREWALL_RULES\("filter_ipv6\.default"\)[\s\S]*?evalRet = eval\("ip6tables-restore"/)[0];
const guestAllowlist = ipv6Filter.match(/-A INPUT -m mark --mark %s\/%s -p ipv6-icmp -j ACCEPT[\s\S]*?-A INPUT -m mark --mark %s\/%s -j DROP/);
assert.ok(guestAllowlist, 'marked guest IPv6 INPUT policy is emitted');
assert.ok(guestAllowlist[0].indexOf('--dport 53 -j ACCEPT') < guestAllowlist[0].indexOf('-j DROP'));
assert.ok(guestAllowlist[0].indexOf('--dport 547 -j ACCEPT') < guestAllowlist[0].indexOf('-j DROP'));
assert.ok(guestAllowlist[0].indexOf('--sport 547 --dport 546 -j ACCEPT') < guestAllowlist[0].indexOf('-j DROP'));
assert.ok(guestAllowlist[0].indexOf('ipv6-icmp -j ACCEPT') < guestAllowlist[0].indexOf('-j DROP'));
assert.ok(guestAllowlist[0].indexOf('-j DROP') < ipv6Filter.indexOf('--state RELATED,ESTABLISHED'));
assert.doesNotMatch(guestAllowlist[0], /-A FORWARD/);
assert.match(bridgeInput, /NF_HOOK\(NFPROTO_BRIDGE, NF_BR_LOCAL_IN,[\s\S]*?netif_receive_skb/);

console.log('guest ARP, bridge, and IPv6 isolation source contracts passed');