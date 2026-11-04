'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), 'utf8');
const kernel = 'release/src-rt-6.x.4708/linux/linux-2.6.36';
const arpreply = read(`${kernel}/net/bridge/netfilter/ebt_arpreply.c`);
const ebtables = read(`${kernel}/net/bridge/netfilter/ebtables.c`);
const header = read(`${kernel}/include/linux/netfilter_bridge/ebtables.h`);

assert.match(arpreply, /info->target != EBT_ACCEPT && info->target != EBT_DROP &&\s*info->target != EBT_CONTINUE && info->target != EBT_RETURN\)\s*return -EINVAL;/);
assert.match(arpreply, /BASE_CHAIN && info->target == EBT_RETURN\)\s*return -EINVAL;/);
assert.match(ebtables, /t->u\.target->target && verdict != EBT_ACCEPT &&\s*verdict != EBT_DROP && verdict != EBT_CONTINUE &&\s*verdict != EBT_RETURN/);
assert.match(ebtables, /!t->u\.target->target && verdict < -NUM_STANDARD_TARGETS/);
assert.match(ebtables, /if \(sp <= 0 \|\| !cs\) \{[\s\S]*?return NF_DROP;/);
assert.match(ebtables, /if \(!cs\) \{\s*read_unlock_bh\(&table->lock\);\s*return NF_DROP;\s*\}\s*cs\[sp\]\.n/);
assert.match(header, /#define EBT_ACCEPT\s+-1[\s\S]*#define EBT_DROP\s+-2[\s\S]*#define EBT_CONTINUE\s+-3[\s\S]*#define EBT_RETURN\s+-4/);

const verdicts = { accept: -1, drop: -2, continue: -3, return: -4 };
const isStandardVerdict = (verdict) => Object.values(verdicts).includes(verdict);
const extensionVerdict = (verdict) => isStandardVerdict(verdict) ? verdict : 'drop';
const standardVerdict = (verdict) => verdict < -4 ? 'drop' : verdict > 0 ? 'jump' : verdict;
const returnVerdict = (stackDepth, hasStack) => stackDepth > 0 && hasStack ? 'return' : 'drop';

for (const verdict of Object.values(verdicts))
  assert.equal(extensionVerdict(verdict), verdict);
for (const verdict of [1, 0, -5, -2147483648, 2147483647])
  assert.equal(extensionVerdict(verdict), 'drop');
assert.equal(standardVerdict(64), 'jump');
assert.equal(standardVerdict(-5), 'drop');
assert.equal(returnVerdict(1, true), 'return');
assert.equal(returnVerdict(0, false), 'drop');
assert.equal(returnVerdict(0, true), 'drop');

console.log('ebtables extension verdict and chain-stack checks passed');