const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const bridgeDir = path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/bridge');
const fdb = fs.readFileSync(path.join(bridgeDir, 'br_fdb.c'), 'utf8');
const sysfs = fs.readFileSync(path.join(bridgeDir, 'br_sysfs_if.c'), 'utf8');

const addCache = fdb.match(/br_brc_add\(unsigned char \*ea,[\s\S]*?\n\}/)[0];
assert.match(addCache, /struct net_bridge_port \*source/);
assert.match(addCache, /source->flags & BR_ISOLATE_MODE[\s\S]*?ctf_brc_delete\(kcih, ea\)[\s\S]*?return;/);
assert.match(addCache, /ctf_isenabled\(kcih,[\s\S]*?\brxdev\)/);
assert.match(fdb, /br_brc_add\(\(unsigned char \*\)addr, source, skb\)/g);
assert.match(fdb, /ctf_brc_delete\(kcih, f->addr\.addr\)/);

const deleteByPort = fdb.match(/void br_fdb_delete_by_port\([\s\S]*?\n\}/)[0];
assert.match(deleteByPort, /if \(f->dst != p\)\s*continue;[\s\S]*?fdb_delete\(f\)/);

const setIsolate = sysfs.match(/static ssize_t store_isolate_mode\([\s\S]*?\n\}/)[0];
assert.match(setIsolate, /if \(v\)\s*\{[\s\S]*?p->flags \|= BR_ISOLATE_MODE;[\s\S]*?br_fdb_delete_by_port\(p->br, p, 0\);[\s\S]*?\} else[\s\S]*?p->flags &= ~BR_ISOLATE_MODE;/);

console.log('bridge isolation CTF cache contracts passed');
