const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const bridgeDir = path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/bridge');
const fdb = fs.readFileSync(path.join(bridgeDir, 'br_fdb.c'), 'utf8');
const forward = fs.readFileSync(path.join(bridgeDir, 'br_forward.c'), 'utf8');
const device = fs.readFileSync(path.join(bridgeDir, 'br_device.c'), 'utf8');
const bpdu = fs.readFileSync(path.join(bridgeDir, 'br_stp_bpdu.c'), 'utf8');
const sysfs = fs.readFileSync(path.join(bridgeDir, 'br_sysfs_if.c'), 'utf8');
const input = fs.readFileSync(path.join(bridgeDir, 'br_input.c'), 'utf8');

const receive = input.match(/int br_handle_frame_finish\(struct sk_buff \*skb\)[\s\S]*?\n\}/)[0];
const taggedDrop = receive.match(/if \(\(p->flags & BR_ISOLATE_MODE\) &&\s*\(skb->protocol == htons\(ETH_P_8021Q\) \|\|\s*skb->protocol == htons\(0x88a8\) \|\|\s*skb->protocol == htons\(0x9100\)\)\)\s*goto drop;/)[0];
assert(receive.indexOf(taggedDrop) < receive.indexOf('br_fdb_update('));

const addCache = fdb.match(/br_brc_add\(unsigned char \*ea,[\s\S]*?\n\}/)[0];
assert.match(addCache, /struct net_bridge_port \*source/);
assert.match(addCache, /source->flags & BR_ISOLATE_MODE[\s\S]*?ctf_brc_delete\(kcih, ea\)[\s\S]*?return;/);
assert.match(addCache, /ctf_isenabled\(kcih,[\s\S]*?\brxdev\)/);
assert.match(fdb, /br_brc_add\(\(unsigned char \*\)addr, source, skb\)/g);
assert.match(fdb, /ctf_brc_delete\(kcih, f->addr\.addr\)/);
assert.match(
    fdb,
    /else if \(!\(source->flags & BR_ISOLATE_MODE\) \|\|\s*\(fdb->dst->flags & BR_ISOLATE_MODE\)\)\s*\{[\s\S]*?br_brc_add\([\s\S]*?fdb->dst = source;/
);

const mayUpdateEntry = (sourceIsolated, entryIsolated) =>
    !sourceIsolated || entryIsolated;
for (const { sourceIsolated, entryIsolated, expected } of [
    { sourceIsolated: false, entryIsolated: false, expected: true },
    { sourceIsolated: false, entryIsolated: true, expected: true },
    { sourceIsolated: true, entryIsolated: false, expected: false },
    { sourceIsolated: true, entryIsolated: true, expected: true },
]) {
    assert.strictEqual(mayUpdateEntry(sourceIsolated, entryIsolated), expected);
}

const receiveBpdu = bpdu.match(/void br_stp_rcv\([\s\S]*?\n\}/)[0];
assert.match(receiveBpdu, /p = br_port_get_rcu\(dev\);\s*if \((?:p->flags & BR_ISOLATE_MODE|!p \|\| \(p->flags & BR_ISOLATE_MODE\))\)\s*goto err;/);

assert.match(forward, /if \(\(forward \|\| skip_isolated\) &&\s*\(p->flags & BR_ISOLATE_MODE\)\)\s*continue;/);
assert.match(forward, /void br_flood_deliver_unicast\([\s\S]*?br_flood\(br, skb, NULL, __br_deliver, false, true\);/);
assert.match(device, /else if \(\(dst = __br_fdb_get\(br, dest\)\) != NULL\)\s*br_deliver\(dst->dst, skb\);\s*else\s*br_flood_deliver_unicast\(br, skb\);/);
assert.match(device, /if \(is_multicast_ether_addr\(dest\)\)[\s\S]*?br_flood_deliver\(br, skb\);/);

const deleteByPort = fdb.match(/void br_fdb_delete_by_port\([\s\S]*?\n\}/)[0];
assert.match(deleteByPort, /if \(f->dst != p\)\s*continue;[\s\S]*?fdb_delete\(f\)/);

const setIsolate = sysfs.match(/static ssize_t store_isolate_mode\([\s\S]*?\n\}/)[0];
assert.match(setIsolate, /if \(v\)\s*\{[\s\S]*?p->flags \|= BR_ISOLATE_MODE;[\s\S]*?br_fdb_delete_by_port\(p->br, p, 0\);[\s\S]*?\} else[\s\S]*?p->flags &= ~BR_ISOLATE_MODE;/);

console.log('bridge isolation tagged-frame, FDB, BPDU, flood, and CTF cache contracts passed');
