const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const sourcePath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/sched/cls_u32.c';
const source = fs.readFileSync(path.join(root, sourcePath), 'utf8');
const selector = source.indexOf('s = nla_data(tb[TCA_U32_SEL]);');
assert.ok(selector >= 0, 'u32_change reads the selector attribute');

const guard = source.slice(selector).match(
    /if \(nla_len\(tb\[TCA_U32_SEL\]\) <\s*sizeof\(\*s\) \+ s->nkeys\*sizeof\(struct tc_u32_key\)\)\s*return -EINVAL;/
);
assert.ok(guard, 'reject a selector shorter than its declared key array');
const allocation = source.indexOf('n = kzalloc(', selector);
const copy = source.indexOf('memcpy(&n->sel, s,', selector);
assert.ok(allocation > selector && copy > allocation, 'selector allocation and copy remain present');
assert.ok(selector < allocation && source.indexOf(guard[0], selector) < allocation,
    'validate selector length before allocating the knode');
assert.ok(source.indexOf(guard[0], selector) < copy,
    'validate selector length before copying selector bytes');

const rejectShortSelector = new Function('attr_len', 'selector_size', 'nkeys', 'key_size',
    `return attr_len < selector_size + nkeys * key_size;`);
assert.equal(rejectShortSelector(16, 16, 200, 16), true,
    'reject a 16-byte selector declaring 200 keys');
assert.equal(rejectShortSelector(16 + 200 * 16, 16, 200, 16), false,
    'accept a selector containing all 200 keys');
assert.equal(rejectShortSelector(16 + 200 * 16 - 1, 16, 200, 16), true,
    'reject a selector one byte shorter than its declared keys');

console.log('PASS: cls_u32 selector length guard (source contract/model; not kernel execution)');