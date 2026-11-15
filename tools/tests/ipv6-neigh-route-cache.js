#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const root = path.resolve(__dirname, "../..");
const header = fs.readFileSync(path.join(root, "release/src-rt-6.x.4708/linux/linux-2.6.36/include/net/ip6_route.h"), "utf8");
const dstHeader = fs.readFileSync(path.join(root, "release/src-rt-6.x.4708/linux/linux-2.6.36/include/net/dst.h"), "utf8");
const dst = fs.readFileSync(path.join(root, "release/src-rt-6.x.4708/linux/linux-2.6.36/net/core/dst.c"), "utf8");
const route = fs.readFileSync(path.join(root, "release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/route.c"), "utf8");
const firewall = fs.readFileSync(path.join(root, "release/src/router/rc/firewall.c"), "utf8");
const neighbor = fs.readFileSync(path.join(root, "release/src-rt-6.x.4708/linux/linux-2.6.36/net/core/neighbour.c"), "utf8");
const kernelConfig = fs.readFileSync(path.join(root, "release/src-rt-6.x.4708/linux/linux-2.6.36/config_base.6a"), "utf8");

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert.notEqual(start, -1, `missing function ${signature}`);
    const bodyStart = source.indexOf("{", start);
    let depth = 0;
    for (let index = bodyStart; index < source.length; index++) {
        if (source[index] === "{") depth++;
        if (source[index] === "}" && --depth === 0) return source.slice(bodyStart, index + 1);
    }
    assert.fail(`unterminated function ${signature}`);
}

assert.match(header, /#define RT6_LOOKUP_F_INPUT\s+0x00000040/);
assert.match(dstHeader, /#define DST_EPHEMERAL\s+16/);

const routeLookup = functionBody(route, "static struct rt6_info *ip6_pol_route(");
const inputRoute = functionBody(route, "void ip6_route_input(");
const outputRoute = functionBody(route, "struct dst_entry * ip6_route_output(");
const dstRelease = functionBody(dst, "void dst_release(");

assert.match(inputRoute, /RT6_LOOKUP_F_HAS_SADDR\s*\|\s*RT6_LOOKUP_F_INPUT/);
assert.doesNotMatch(outputRoute, /RT6_LOOKUP_F_INPUT/);
assert.match(routeLookup, /int cache_route = 1;/);
assert.match(routeLookup, /nrt = rt6_alloc_cow\(rt, &fl->fl6_dst, &fl->fl6_src\);\s*if \(flags & RT6_LOOKUP_F_INPUT\)\s*cache_route = 0;/);
assert.match(routeLookup, /if \(!cache_route\)\s*\{\s*nrt->dst.flags \|= DST_EPHEMERAL \| DST_NOHASH;\s*goto out2;\s*\}\s*err = ip6_ins_rt\(nrt\);/);
assert.match(dstRelease, /newrefcnt = atomic_dec_return\(&dst->__refcnt\);[\s\S]*?if \(!newrefcnt && \(dst->flags & DST_EPHEMERAL\)\)\s*dst_destroy\(dst\);/);
assert.doesNotMatch(routeLookup, /dst_free\(&nrt->dst\)/);

const forwardRules = functionBody(firewall, "static void write_ipv6_forward_icmp_rules(");
assert.match(forwardRules, /--limit 20\/s --limit-burst 40/,
    "LAN-forwarded echo requests have an unconditional global rate limit");
assert.match(forwardRules,
    /--hashlimit-upto 1\/sec --hashlimit-burst 2 "\s+"--hashlimit-mode dstip/,
    "LAN-forwarded echo requests are also limited per destination");
assert.match(forwardRules, /lan_if, lan_echo_limit, logaccept/,
    "the LAN echo accept uses both default limits rather than fw_dos_x");
assert.equal((firewall.match(/write_ipv6_forward_icmp_rules\(fp_ipv6, lan_if,/g) || []).length, 2,
    "both filter_setting generators use the shared protected rule writer");
assert.match(kernelConfig, /^CONFIG_NETFILTER_XT_MATCH_HASHLIMIT=m$/m,
    "the target kernel builds the hashlimit match");

const pendingGuard = functionBody(neighbor, "static int neigh_ipv6_incomplete_limit_reached(");
assert.match(neighbor, /#define IPV6_NEIGH_INCOMPLETE_LIMIT 256/);
assert.match(pendingGuard, /n->dev != neigh->dev/,
    "the unresolved-entry cap is counted per network device");
assert.match(pendingGuard, /n->nud_state & NUD_INCOMPLETE/,
    "only active unresolved probes consume the per-device cap");

const eventSend = functionBody(neighbor, "int __neigh_event_send(");
assert.match(eventSend,
    /family == AF_INET6[\s\S]*?write_lock_bh\(&neigh->tbl->lock\);\s*write_lock\(&neigh->lock\);/,
    "IPv6 admissions serialize with neighbor-table GC before taking a neighbor lock");
assert.match(eventSend,
    /table_locked && !\(neigh->nud_state & NUD_VALID\) &&\s*neigh_ipv6_incomplete_limit_reached\(neigh\)[\s\S]*?kfree_skb\(skb\);\s*return 1;/,
    "over-limit unresolved destinations are dropped without arming another probe timer");
assert.doesNotMatch(neighbor, /struct neighbour\s*\{[^}]*incomplete_count/s,
    "the neighbor ABI layout is unchanged");

function admitResolution(entries, device, limit) {
    const pending = entries.filter(entry => entry.device === device && entry.state === "INCOMPLETE").length;
    return pending < limit;
}

const attackerEntries = Array.from({ length: 10000 }, (_, index) => ({
    device: "br0",
    state: index < 256 ? "INCOMPLETE" : "NONE"
}));
assert.equal(admitResolution(attackerEntries, "br0", 256), false);
assert.equal(admitResolution(attackerEntries, "wan0", 256), true,
    "pressure on one interface does not consume another interface's quota");
assert.equal(admitResolution(attackerEntries, "br0", 257), true,
    "a responsive entry can proceed once an unresolved probe completes");

console.log("PASS: IPv6 ingress routes remain ephemeral and forwarding echo/unresolved-neighbor pressure is bounded.");
