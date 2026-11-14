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
const processRule = netlink.match(/static void process_rule\([\s\S]*?\n\}/)[0];
assert.match(processRule, /case FRA_PRIORITY/);
assert.match(processRule, /if \(this->process_rules\)\s*\{\s*fire_roam_event\(this, FALSE\);/);
assert.match(rcIpsec, /install_table_rule = _ipsec_director_selective_unit\(\) \? "no" : "yes"/);
assert.match(rcIpsec, /install_routing_table_rule = %s/);
const directorSnapshot = rcIpsec.match(/static void _ipsec_director_config_snapshot\([\s\S]*?\n\}/)[0];
assert.doesNotMatch(directorSnapshot, /ovpn_get_ipsec_policy_rules/);
assert.match(rcIpsec, /static int _ipsec_director_rules_update\(int unit\);[\s\S]*?static int _ipsec_director_rules_update\(int unit\)\s*\{/);
assert.match(rcIpsec, /#ifdef RTCONFIG_OPENVPN\s+static int _ipsec_director_rules_update\(int unit\);\s+#endif/);
assert.match(rcIpsec, /_ipsec_director_rules_update\(_ipsec_director_selective_unit\(\)\)/);
const liveRuleUpdate = rcIpsec.match(/static int _ipsec_director_rules_update\(int unit\)\s*\{[\s\S]*?\n\}/)[0];
assert.match(liveRuleUpdate, /_ipsec_director_rules_set\(unit, previous, 0\)/);
assert.match(liveRuleUpdate, /_ipsec_director_rules_set\(unit, current, 1\)/);
assert.match(liveRuleUpdate, /_ipsec_director_rules_set\(unit, previous, 1\)/);
assert.match(rcIpsec, /else if \(director_rules_changed <= 0\)\s*\{\s*rc_ipsec_rereadall/);
assert.match(rcIpsec, /if \(!pids\("charon"\)\)\s*rc_ipsec_start\(fp\)/);
assert.match(rcIpsec, /_ipsec_director_rules_set\(unit, rules, 1\)/);
assert.match(rcIpsec, /"iif", lan_ifname, "from", src, "to", dst, "lookup", "220"/);
assert.match(rcIpsec, /"iif", lan_ifname, "to", dst, "lookup", "220"/);
assert.match(rcIpsec, /"pref", "102", "to", peer, "lookup", "main"/);
assert.match(rcIpsec, /vpn_type == VPN_TYPE_NET_NET_CLI/);
assert.match(rcIpsec, /_ipsec_director_policy_lifecycle\(unit, 0, safe_getenv\("PLUTO_PEER"\)\)/);
assert.match(rcIpsec, /_ipsec_director_policy_lifecycle\(unit, 1, safe_getenv\("PLUTO_PEER"\)\)/);
assert.match(rcIpsec, /_ipsec_lan_exclude_route_set\("220"\);[\s\S]*?_ipsec_director_policy_lifecycle\(unit, 1/);
const updownMain = rcIpsec.match(/int ipsec_updown_main\([\s\S]*?\n\}/)[0];
assert.match(updownMain, /pre_ipsec_prof_set\(\);[\s\S]*?_ipsec_updown_net_net\(unit, vpn_type\)/);
assert.match(rcIpsec, /director_changed \|\|/);
assert.match(rcIpsec, /FILE_PATH_IPSEC_PRIVATE_DIR "\/director-config"/);
assert.match(rcIpsec, /_ipsec_director_config_changed\(director_snapshot\)/);
assert.match(rcIpsec, /if \(!fp\)\s*return 1;/);
assert.match(rcIpsec, /ipsec_run_script\(FILE_PATH_IPSEC_SH\) == 0 &&\s*_ipsec_director_config_save\(director_snapshot\)/);
assert.match(rcIpsec, /static int ipsec_prepare_config_dirs\(void\)/);
assert.match(rcIpsec, /system\("cp -rf \/usr\/etc\/\* \/tmp\/etc\/"\) != 0/);
assert.match(rcIpsec, /if \(ipsec_prepare_config_dirs\(\) < 0\)\s*return;/);
assert.match(rcIpsec, /static int _ipsec_director_rules_set/);
assert.match(rcIpsec, /result \|= eval\("ip", "rule", add \? "add" : "del"/);
assert.match(rcIpsec, /if \(lock < 0\)\s*return;/);
assert.match(rcIpsec, /failed to install VPN Director rules/);
assert.match(rcIpsec, /failed to remove VPN Director rules/);
assert.match(rcIpsec, /ovpn_get_ipsec_policy_rules\(unit, rules, sizeof\(rules\)\)/);
assert.match(services, /unit == 0 && nvram_get_int\("ipsec_client_enable"\)/);
assert.match(ovpnConfig, /"IPSEC%d", unit/);
assert.match(ovpnConfig, /inet_pton\(AF_INET, address/);
assert.match(ovpnConfig, /strlen\(buffer\) > 7999/);
assert.match(web, /do_get_ipsec_director_profiles_cgi/);
const profileEndpoint = web.match(/do_get_ipsec_director_profiles_cgi[\s\S]*?do_get_ipsec_clientlist_cgi/)[0];
assert.match(profileEndpoint, /json_object_new_string\(name\)/);
assert.match(profileEndpoint, /json_object_object_add\(item, "gateway",/);
assert.match(profileEndpoint, /json_object_object_add\(item, "active", json_object_new_boolean/);
assert.doesNotMatch(profileEndpoint, /passwd|auth_method_key/);
assert.match(page, /get_ipsec_director_profiles\.cgi/);
assert.match(page, /IPSEC" \+ unit/);
assert.match(page, /ipsec_client" \+ unit \+ "_routing_mode/);
assert.match(page, /IPsec clients status/);
assert.match(page, /get_ipsec_conn/);
assert.match(page, /set_ipsec_client_active/);
assert.match(page, /statusCell\.addClass\("hint-color"\)/);
assert.match(page, /table-layout:fixed/);
assert.strictEqual((page.match(/width:36%;/g) || []).length, 2);
assert.strictEqual((page.match(/width:24%;/g) || []).length, 2);
assert.match(page, /nvramCharToAscii\(\[key\], true\)/);
assert.match(page, /ipsec_start_cli/);
assert.match(page, /ipsec_stop_cli/);
assert.match(page, /name="ipsec_action_form"/);
assert.match(page, /Only one IPSec connection can be active at a time/);
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
