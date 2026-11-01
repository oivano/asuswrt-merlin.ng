const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const header = read('release/src/router/shared/frr_ui_config.h');
const rc = read('release/src/router/rc/frr.c');
const generate = header.slice(header.indexOf('static int frr_ui_generate'), header.indexOf('static int frr_ui_merge'));
const merge = header.slice(header.indexOf('static int frr_ui_merge('), header.indexOf('static int frr_ui_merge_daemons'));
const legacy = rc.slice(rc.indexOf('static void frr_write_ospf_block'), rc.indexOf('static void frr_write_bfd_block'));

assert.match(generate, /router ospf\\n ospf router-id %s\\n/);
assert.match(generate, /fprintf\(out, " passive-interface br0\\n"\)/);
assert.match(merge, /no passive-interface br0/);
assert.match(merge, /seen_ospf_br0 = handled = 1/);
assert.match(merge, /if \(!seen_ospf_br0\) fprintf\(out, "router ospf\\n passive-interface br0\\nexit\\n!\\n"\);/);
assert.ok(merge.indexOf('while ((line = strsep(&cursor, "\\n"))') < merge.indexOf('router ospf\\n passive-interface br0'));
assert.match(legacy, /fprintf\(fp, " passive-interface br0\\n"\)/);
assert.match(legacy, /if \(\*ospf_networks\) \{/);
assert.doesNotMatch(legacy, /network 0\.0\.0\.0\/0 area/);

console.log('FRR OSPF LAN safety source contracts passed');