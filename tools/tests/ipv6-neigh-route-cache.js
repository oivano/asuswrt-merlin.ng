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

console.log("IPv6 ingress COW routes bypass FIB caching and release neighbours synchronously after the last packet reference.");
