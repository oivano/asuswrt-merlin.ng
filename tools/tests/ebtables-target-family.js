const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const ebtables = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/bridge/netfilter/ebtables.c');
const device = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/core/dev.c');

const watcherCheck = ebtables.match(/ebt_check_watcher\([\s\S]*?\n\}/);
assert(watcherCheck, 'watcher validation function exists');
assert.match(watcherCheck[0], /watcher->family != NFPROTO_BRIDGE/);
assert.match(watcherCheck[0], /module_put\(watcher->me\);\s*return -EINVAL;/);
assert(watcherCheck[0].indexOf('watcher->family != NFPROTO_BRIDGE') < watcherCheck[0].indexOf('w->u.watcher = watcher'));

const entryCheck = ebtables.match(/ebt_check_entry\([\s\S]*?\n\}/);
assert(entryCheck, 'entry validation function exists');
assert.match(entryCheck[0], /target->family != NFPROTO_BRIDGE/);
assert.match(entryCheck[0], /module_put\(target->me\);\s*ret = -EINVAL;\s*goto cleanup_watchers;/);
assert(entryCheck[0].indexOf('target->family != NFPROTO_BRIDGE') < entryCheck[0].indexOf('t->u.target = target'));

const load = device.match(/void dev_load\(struct net \*net, const char \*name\)\s*\{([\s\S]*?)\n\}/);
assert(load, 'dev_load function exists');
assert.match(load[1], /request_module\("netdev-%s", name\)/);
assert.doesNotMatch(load[1], /request_module\("%s", name\)/);

console.log('ebtables target-family and dev_load alias contracts passed');