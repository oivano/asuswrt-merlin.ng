const assert = require("assert");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");
const rcIpsec = read("release/src/router/rc/rc_ipsec.c");
const services = read("release/src/router/rc/services.c");
const netlink = read("release/src/router/strongswan/src/libcharon/plugins/kernel_netlink/kernel_netlink_net.c");
const ovpnConfig = read("release/src/router/libovpn/openvpn_config.c");
const web = read("release/src/router/httpd/web.c");
const page = read("release/src/router/www/Advanced_VPNDirector.asp");
const menu = read("release/src/router/www/require/menuTrees/menuTree_no_bwdpi.js");
const defaults = read("release/src/router/shared/defaults.c");

assert.match(netlink, /install_routing_table_rule"\s*,\s*TRUE/);
assert.match(netlink, /if \(this->routing_table && this->install_routing_table_rule\)/);
assert.match(netlink, /if \(this->routing_table && this->install_routing_table_rule && this->socket\)/);
assert.match(netlink, /this->install_routing_table_rule &&\s*hdr->nlmsg_type == RTM_DELRULE/);
assert.match(netlink, /this->process_rules \|\|\s*\(this->routing_table && this->install_routing_table_rule\)/);
assert.match(rcIpsec, /install_table_rule = _ipsec_director_selective_unit\(\) \? "no" : "yes"/);
assert.match(rcIpsec, /install_routing_table_rule = %s/);
assert.match(rcIpsec, /_ipsec_director_rules_set\(unit, rules, 1\)/);
assert.match(rcIpsec, /"iif", lan_ifname, "from", src, "to", dst, "lookup", "220"/);
assert.match(rcIpsec, /"iif", lan_ifname, "to", dst, "lookup", "220"/);
assert.match(rcIpsec, /"pref", "102", "to", peer, "lookup", "main"/);
assert.match(rcIpsec, /vpn_type == VPN_TYPE_NET_NET_CLI/);
assert.match(rcIpsec, /_ipsec_director_policy_lifecycle\(unit, 0, safe_getenv\("PLUTO_PEER"\)\)/);
assert.match(rcIpsec, /_ipsec_director_policy_lifecycle\(unit, 1, safe_getenv\("PLUTO_PEER"\)\)/);
assert.match(rcIpsec, /_ipsec_lan_exclude_route_set\("220"\);[\s\S]*?_ipsec_director_policy_lifecycle\(unit, 1/);
assert.match(rcIpsec, /director_changed \|\|/);
assert.match(rcIpsec, /ovpn_get_ipsec_policy_rules\(unit, rules, sizeof\(rules\)\)/);
assert.match(services, /unit == 0 && nvram_get_int\("ipsec_client_enable"\)/);
assert.match(ovpnConfig, /"IPSEC%d", unit/);
assert.match(ovpnConfig, /inet_pton\(AF_INET, address/);
assert.match(ovpnConfig, /strlen\(buffer\) > 7999/);
assert.match(web, /do_get_ipsec_director_profiles_cgi/);
const profileEndpoint = web.match(/do_get_ipsec_director_profiles_cgi[\s\S]*?do_get_ipsec_clientlist_cgi/)[0];
assert.match(profileEndpoint, /json_object_new_string\(name\)/);
assert.doesNotMatch(profileEndpoint, /passwd|auth_method_key/);
assert.match(page, /get_ipsec_director_profiles\.cgi/);
assert.match(page, /IPSEC" \+ unit/);
assert.match(page, /ipsec_client" \+ unit \+ "_routing_mode/);
assert.match(page, /Director mode requires exactly one active IPsec net-to-net client profile/);
assert.match(menu, /Advanced_VPNDirector\.asp/);
for (let unit = 1; unit <= 5; unit++) {
    assert.match(defaults, new RegExp(`ipsec_client${unit}_routing_mode",\\s*"full", CKN_STR16`));
}

function route({ mode, input, source, destination, selectedSource, selectedDestination, peer }) {
    if (destination === peer) return "main";
    if (mode === "full") return "ipsec0";
    if (input === "br0" &&
        (selectedSource === null || source === selectedSource) &&
        (selectedDestination === null || destination === selectedDestination)) return "ipsec0";
    return "main";
}

assert.strictEqual(route({ mode: "director", input: "br0", source: "192.168.1.10", destination: "1.1.1.1", selectedSource: "192.168.1.10", selectedDestination: "1.1.1.1", peer: "203.0.113.8" }), "ipsec0");
assert.strictEqual(route({ mode: "director", input: "br0", source: "192.168.1.10", destination: "9.9.9.9", selectedSource: "192.168.1.10", selectedDestination: "1.1.1.1", peer: "203.0.113.8" }), "main");
assert.strictEqual(route({ mode: "director", input: "br0", source: "192.168.1.11", destination: "1.1.1.1", selectedSource: "192.168.1.10", selectedDestination: "1.1.1.1", peer: "203.0.113.8" }), "main");
assert.strictEqual(route({ mode: "director", input: "local", source: "192.168.1.1", destination: "1.1.1.1", selectedSource: "192.168.1.1", selectedDestination: "1.1.1.1", peer: "203.0.113.8" }), "main");
assert.strictEqual(route({ mode: "director", input: "br0", source: "192.168.1.10", destination: "203.0.113.8", selectedSource: "192.168.1.10", selectedDestination: null, peer: "203.0.113.8" }), "main");
assert.strictEqual(route({ mode: "full", input: "br0", source: "192.168.1.11", destination: "1.1.1.1", selectedSource: null, selectedDestination: null, peer: "203.0.113.8" }), "ipsec0");

let refs = 0;
let installed = false;
const up = () => { if (refs++ === 0) installed = true; };
const down = () => { if (refs > 0 && --refs === 0) installed = false; };
up();
up();
down();
assert.strictEqual(installed, true);
down();
assert.strictEqual(installed, false);

console.log("IPsec Director source contracts and routing lifecycle model passed");
