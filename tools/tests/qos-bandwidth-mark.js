const assert = require("assert");
const fs = require("fs");

const qosSource = fs.readFileSync("release/src/router/rc/qos.c", "utf8");
const sharedHeader = fs.readFileSync("release/src/router/shared/shared.h", "utf8");
const qosMaskMatch = sharedHeader.match(/^#define\s+QOS_MASK\s+\((0x[0-9A-Fa-f]+)\)/m);
assert(qosMaskMatch, "QOS_MASK must be defined in shared.h");
const qosMask = Number(qosMaskMatch[1]);
const guestIsolationBit = 0x400;

const wgnStart = qosSource.indexOf("static void add_iptables_AMAS_WGN(");
const wgnEnd = qosSource.indexOf("/*\n\tip / mac / ip-range status", wgnStart);
assert(wgnStart >= 0 && wgnEnd > wgnStart, "AMAS-WGN limiter helper must exist");
const wgnRules = qosSource.slice(wgnStart, wgnEnd);
assert(wgnRules.includes('"%s %d/0x%x", action, guest_mark, QOS_MASK'),
    "AMAS-WGN guest marks must be restricted to QoS bits");
assert(wgnRules.includes('"-A PREROUTING -s %s -j %s\\n", net, act_buf'),
    "AMAS-WGN rules must emit the masked action");

const limiterStart = qosSource.indexOf("static int add_bandwidth_limiter_rules(");
const limiterEnd = qosSource.indexOf("/* Setup guest network's ebtables rules */", limiterStart);
assert(limiterStart >= 0 && limiterEnd > limiterStart, "bandwidth limiter rule builder must exist");
const limiterRules = qosSource.slice(limiterStart, limiterEnd);
assert(limiterRules.includes('"%s 9/0x%x", action, QOS_MASK'),
    "router-access marks must be restricted to QoS bits");
assert(limiterRules.includes("safe_atoi(prio) + INITIAL_MARKNUM, QOS_MASK)"),
    "per-client marks must be restricted to QoS bits");
assert.strictEqual((limiterRules.match(/-j %s\\n/g) || []).length, 7,
    "router-access, IP, MAC, and IP-range rules must emit the formatted action");
assert(!/-j %s (?:9|%d)\\n/.test(limiterRules),
    "the limiter must not emit unmasked packet-mark values");

function setMaskedMark(mark, value, mask) {
    return ((mark & ~mask) | (value & mask)) >>> 0;
}

assert.strictEqual(qosMask & guestIsolationBit, 0,
    "QOS_MASK must not include the guest-isolation bit");
const marked = setMaskedMark(guestIsolationBit, 9, qosMask);
assert.strictEqual(marked & guestIsolationBit, guestIsolationBit,
    "setting a QoS mark must preserve BIT_GUEST_IPV4");
assert.strictEqual(marked & qosMask, 9,
    "bandwidth-limiter classification must retain its QoS mark");
