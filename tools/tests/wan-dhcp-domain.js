"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../..");
const wan = fs.readFileSync(path.join(root, "release/src/router/rc/wan.c"), "utf8");
const busyboxConfig = fs.readFileSync(path.join(root, "release/src/router/busybox/config_base"), "utf8");
const busyboxClient = fs.readFileSync(path.join(root, "release/src/router/busybox/networking/udhcp/dhcpc.c"), "utf8");

assert.match(busyboxConfig, /^CONFIG_FEATURE_UDHCPC_SANITIZEOPT=y$/m);
assert.match(busyboxClient, /if \(type == OPTION_STRING_HOST && !good_hostname\(dest\)\)\s+safe_strncpy\(dest, "bad", len\);/);
assert.match(wan, /skip_wan_domain = dnspriv_enable;/);
assert.match(wan, /skip_wan_domain \|= ovpn_skip_dnsmasq\(\);/);
assert.match(wan, /if \(!skip_wan_domain\)\s*\{[\s\S]*?is_valid_domainname\(domain\)[\s\S]*?server=\/%s\/%s/);
assert.match(wan, /if \(!skip_wan_domain\)\s*foreach\(domain, wan_domain, next_domain\)\s*if \(is_valid_domainname\(domain\)\)\s*fprintf\(fp_servers, "server=\/%s\/%s\\n", domain, tmp\);/);

const multiServiceLoop = wan.match(/#ifdef RTCONFIG_MULTISERVICE_WAN\s+for \(unit = 1; unit < WAN_MULTISRV_MAX; unit\+\+\) \{([\s\S]*?)\n\t\t\}\n#endif/);
assert(multiServiceLoop, "multi-service WAN resolver loop must remain present");
assert.match(multiServiceLoop[1], /fprintf\(fp, "nameserver %s\\n", tmp\);\s*if \(!skip_wan_domain\)\s*\{\s*fprintf\(fp_servers, "server=%s\\n", tmp\);/);
assert.match(multiServiceLoop[1], /if \(yadns_mode != YADNS_DISABLED\)\s*fprintf\(fp_servers, "server=\/%s\/%s\\n", "local", tmp\);\s*#endif\s*\}/);

const accepted = /^[A-Za-z0-9._-]+$/;
for (const domain of ["bank.example", "router_lan", "x-1.example"]) {
  assert(accepted.test(domain), `expected valid token: ${domain}`);
}
for (const domain of ["#", "x/y", "x\nserver=/#/1.2.3.4", "x@host", "a b"]) {
  assert(!accepted.test(domain), `expected rejected token: ${JSON.stringify(domain)}`);
}

console.log("WAN DHCP domain resolver checks passed");