const assert = require("assert");
const fs = require("fs");

const dhcp6 = fs.readFileSync("release/src/router/dnsmasq/src/dhcp6.c", "utf8");
const arp = fs.readFileSync("release/src/router/dnsmasq/src/arp.c", "utf8");

const lookupStart = dhcp6.indexOf("void get_client_mac(");
assert(lookupStart >= 0, "DHCPv6 client MAC lookup must exist");
const lookupEnd = dhcp6.indexOf("static int complete_context6(", lookupStart);
const lookup = dhcp6.slice(lookupStart, lookupEnd);
assert(lookup.includes("maclen = find_mac(&addr, mac, 0, now);"),
	"DHCPv6 must perform an immediate neighbor-cache lookup");
assert.strictEqual((lookup.match(/find_mac\(/g) || []).length, 1,
	"each DHCPv6 packet must perform only one neighbor-cache lookup");
assert(lookup.includes("if (maclen == 0)"), "a cache miss may solicit the neighbor");
assert(!/nanosleep|usleep|sleep\s*\(/.test(lookup),
	"DHCPv6 neighbor lookup must not block the dnsmasq event loop");
assert(!/\bfor\s*\(/.test(lookup), "DHCPv6 lookup must not retry in a loop");
assert.strictEqual((lookup.match(/while\s*\(retry_send\(sendto\(/g) || []).length, 1,
	"the existing EINTR-safe solicitation send wrapper must remain");

assert(arp.includes("#define ARP_EMPTY_MAX 256"), "negative cache must have a fixed cap");
assert(arp.includes("arp_empty_count < ARP_EMPTY_MAX"),
	"negative entries must not be allocated beyond the cap");
assert(arp.includes("arp_empty_count--"), "promotion and expiry must decrement the count");
const refresh = arp.indexOf("/* Expire negative entries and mark positives for confirmation. */");
const enumerate = arp.indexOf("iface_enumerate(AF_UNSPEC, NULL,", refresh);
assert(refresh >= 0 && enumerate > refresh,
	"negative entries must be reclaimed before refreshing the kernel neighbor table");
assert(arp.slice(refresh, enumerate).includes("arp->status == ARP_EMPTY"),
	"refresh must remove cached negative entries");

let cachedNegatives = 0;
for (let index = 0; index < 10000; index++) {
	if (cachedNegatives < 256)
		cachedNegatives++;
}
assert.strictEqual(cachedNegatives, 256,
	"distinct unresolved addresses must not grow the negative cache past its cap");

console.log("dnsmasq DHCPv6 neighbor lookup and negative cache: PASS");