const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/bridge/br_forward.c'), 'utf8');
const helper = source.slice(source.indexOf('static int br_is_modem_console('),
    source.indexOf('static void __br_forward('));
assert.match(helper, /__be16 protocol = skb->protocol;/);
assert.match(helper, /int offset = 0;/);
assert.match(helper, /depth < 2/);
assert.match(helper, /skb_header_pointer\(skb, offset, sizeof\(header\), &header\)/);
assert.match(helper, /if \(!tag\)\s*return 1;/);
assert.match(helper, /protocol = tag->h_vlan_encapsulated_proto;/);
assert.match(helper, /offset \+= VLAN_HLEN;/);

const conditions = [...helper.matchAll(/if \((protocol !=[\s\S]*?)\)\s*break;/g)];
assert.equal(conditions.length, 1);
const translate = expression => expression.replace(/htons\(([^)]+)\)/g, '$1')
    .replace(/ETH_P_8021Q/g, '0x8100');
const isNotTag = new Function('protocol', `return ${translate(conditions[0][1])};`);
const final = helper.match(/return (protocol ==[\s\S]*?);/);
assert.ok(final);
const rejectFinal = new Function('protocol', `return ${translate(final[1])};`);
function rejects(protocol, payload) {
    let offset = 0;
    const limit = Number(helper.match(/depth < (\d+)/)[1]);
    for (let depth = 0; depth < limit; depth++) {
        if (isNotTag(protocol)) break;
        if (offset + 4 > payload.length) return true;
        protocol = payload.readUInt16BE(offset + 2);
        offset += 4;
    }
    return rejectFinal(protocol);
}
function frame(protocol, tags) {
    const payload = Buffer.alloc(tags.length * 4);
    tags.forEach((tag, index) => {
        payload.writeUInt16BE(123, index * 4);
        payload.writeUInt16BE(index + 1 < tags.length ? tags[index + 1] : protocol,
            index * 4 + 2);
    });
    return [tags[0] || protocol, payload];
}
for (const tags of [[], [0x8100], [0x88a8], [0x9100],
    [0x8100, 0x8100], [0x88a8, 0x8100], [0x9100, 0x8100]]) {
    assert.equal(rejects(...frame(0xaaaa, tags)), true);
    for (const protocol of [0x0800, 0x86dd, 0x0806, 0x8863, 0x8864, 0x888e]) {
        assert.equal(rejects(...frame(protocol, tags)), false,
            `ordinary protocol ${protocol.toString(16)} with ${tags.length} tags`);
    }
}
for (const tag of [0x8100, 0x88a8, 0x9100]) {
    for (let length = 0; length < 4; length++) {
        assert.equal(rejects(tag, Buffer.alloc(length)), true);
    }
    assert.equal(rejects(...frame(0x0800, [tag, tag, tag])), true);
}
assert.equal(rejects(0xaaaa, Buffer.alloc(0)), true,
    'hardware-stripped VLAN metadata leaves the inner EtherType visible');

const forward = source.slice(source.indexOf('static void __br_forward('),
    source.indexOf('/* called with rcu_read_lock */', source.indexOf('static void __br_forward(')));
assert.match(forward, /if \(br_is_modem_console\(skb\)\) \{\s*kfree_skb\(skb\);\s*return;\s*\}/);
assert.ok(forward.indexOf('br_is_modem_console(skb)') < forward.indexOf('skb->dev = to->dev'));
assert.ok(forward.indexOf('br_is_modem_console(skb)') < forward.indexOf('NF_HOOK('));
assert.match(source, /deliver_clone\(to, skb, __br_forward\)/);
assert.match(source, /br_flood\(br, skb, skb2, __br_forward, true\)/);
assert.match(source, /br_multicast_flood\(mdst, skb, skb2, __br_forward\)/);
const deliver = source.slice(source.indexOf('static void __br_deliver('),
    source.indexOf('static int br_is_modem_console('));
assert.doesNotMatch(deliver, /br_is_modem_console/);
assert.equal((source.match(/br_is_modem_console\(skb\)/g) || []).length, 1);
console.log('PASS: bridge console guard source contracts and VLAN packet models; not compiled kernel or hardware execution');