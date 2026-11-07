const assert = require("assert");
const fs = require("fs");

const source = fs.readFileSync("release/src/router/rc/wan.c", "utf8");
const start = source.indexOf("static void\nadd_validated_dhcp_route(");
const end = source.indexOf("static void\nadd_dhcp_routes(", start);
assert(start >= 0 && end > start, "shared DHCP route admission helper must exist");
const admission = source.slice(start, end);
const routeParser = source.slice(end, source.indexOf("\nint\ndel_routes(", end));

assert(admission.includes("dhcp_route_gateway_on_link"),
    "every DHCP route must pass the WAN-link gateway check");
assert(admission.includes("dhcp_route_overlaps_local"),
    "every DHCP route must pass local-network overlap checks");
assert(admission.includes("Reject DHCP route"), "rejected routes must be logged");
assert(admission.includes("route_add(ifname"), "accepted routes must be installed after validation");
assert(routeParser.includes("add_validated_dhcp_route(ifname, metric, ipaddr, netsize, gateway, wan_ip, wan_mask)"),
    "classful, MS classless, and RFC classless routes must share validation");
assert.strictEqual((routeParser.match(/add_validated_dhcp_route\(ifname, metric/g) || []).length, 3,
    "all three DHCP route option formats must use the shared validator");
assert(!routeParser.includes("route_add("),
    "the DHCP route parser must not install a route without passing validation");
assert(source.includes("vpn_server%d_sn") && source.includes("subnet_rulelist") &&
    source.includes("lan_route") && source.includes("getifaddrs"),
    "configured VPN/LAN routes and active local interfaces must be checked");
assert(source.includes("dhcp_route_parse_prefix(prefix_text, &netsize)"),
    "classless prefixes must be parsed strictly rather than truncated by atoi");

function mask(prefix) {
    return prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
}

function ipv4(value) {
    return value.split(".").reduce((address, octet) => ((address << 8) | Number(octet)) >>> 0, 0);
}

function overlaps(first, firstPrefix, second, secondPrefix) {
    const common = Math.min(firstPrefix, secondPrefix);
    return (ipv4(first) & mask(common)) === (ipv4(second) & mask(common));
}

function allowed(destination, prefix, gateway, wanAddress, wanPrefix, localNetworks) {
    const gatewayAddress = ipv4(gateway);
    const wanAddressValue = ipv4(wanAddress);
    const wanMask = mask(wanPrefix);
    const wanNetwork = (wanAddressValue & wanMask) >>> 0;
    const wanBroadcast = (wanNetwork | (~wanMask >>> 0)) >>> 0;
    const invalidEndpoint = wanPrefix <= 30 &&
        (gatewayAddress === wanNetwork || gatewayAddress === wanBroadcast);
    if (prefix < 1 || prefix > 32 || !gateway ||
        ((gatewayAddress & wanMask) >>> 0) !== wanNetwork ||
        gatewayAddress === wanAddressValue || invalidEndpoint)
        return false;
    const reserved = [["0.0.0.0", 8], ["127.0.0.0", 8], ["169.254.0.0", 16],
    ["224.0.0.0", 4], ["240.0.0.0", 4]];
    return ![...reserved, ...localNetworks].some(([network, localPrefix]) =>
        overlaps(destination, prefix, network, localPrefix));
}

const wanAddress = "203.0.113.10";
const wanPrefix = 24;
const localNetworks = [["192.168.1.0", 24], ["10.8.0.0", 24], ["192.168.20.0", 24]];
assert(!allowed("192.168.1.0", 25, "203.0.113.1", wanAddress, wanPrefix, localNetworks),
    "first half of the LAN /24 must be rejected");
assert(!allowed("192.168.1.128", 25, "203.0.113.1", wanAddress, wanPrefix, localNetworks),
    "second half of the LAN /24 must be rejected");
assert(!allowed("10.8.0.0", 24, "203.0.113.1", wanAddress, wanPrefix, localNetworks),
    "configured VPN server subnet must be rejected");
assert(!allowed("192.168.20.0", 24, "203.0.113.1", wanAddress, wanPrefix, localNetworks),
    "secondary bridge subnet must be rejected");
assert(!allowed("169.254.0.0", 16, "203.0.113.1", wanAddress, wanPrefix, localNetworks),
    "modem link-local subnet must be rejected");
assert(!allowed("127.0.0.0", 8, "203.0.113.1", wanAddress, wanPrefix, localNetworks),
    "loopback subnet must be rejected");
assert(!allowed("224.0.0.0", 4, "203.0.113.1", wanAddress, wanPrefix, localNetworks),
    "multicast range must be rejected");
assert(!allowed("198.51.100.0", 24, "192.168.1.1", wanAddress, wanPrefix, localNetworks),
    "off-link route gateway must be rejected");
assert(!allowed("198.51.100.0", 24, "203.0.113.0", wanAddress, wanPrefix, localNetworks),
    "WAN subnet network address must not be accepted as a gateway");
assert(!allowed("198.51.100.0", 24, "203.0.113.255", wanAddress, wanPrefix, localNetworks),
    "WAN subnet broadcast address must not be accepted as a gateway");
assert(allowed("198.51.100.0", 24, "203.0.113.1", wanAddress, wanPrefix, localNetworks),
    "a non-local route through an on-link gateway must remain allowed");

console.log("WAN DHCP route local-network and gateway validation: PASS");