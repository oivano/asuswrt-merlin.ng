const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/core/filter.c'), 'utf8');
const helperStart = source.indexOf('static void *__load_pointer(');
const helperEnd = source.indexOf('\n}', helperStart);
assert.notEqual(helperStart, -1);
assert.notEqual(helperEnd, -1);
const helper = source.slice(helperStart, helperEnd);
assert.match(helper, /__load_pointer\(struct sk_buff \*skb, int k, unsigned int size\)/);

const bounds = helper.match(/if \((ptr >= skb->head && ptr \+ size <= skb_tail_pointer\(skb\))\)/);
assert.ok(bounds, 'negative-offset access must fit wholly before skb tail');
const fits = new Function('ptr', 'head', 'tail', 'size',
    `return ${bounds[1].replace(/skb->head/g, 'head')
        .replace(/skb_tail_pointer\(skb\)/g, 'tail')};`);

assert.match(source, /return __load_pointer\(skb, k, size\);/);
const runnerStart = source.indexOf('unsigned int sk_run_filter(');
const runnerEnd = source.indexOf('EXPORT_SYMBOL(sk_run_filter)', runnerStart);
const runner = source.slice(runnerStart, runnerEnd);
assert.match(runner, /u32 A = 0;/);
assert.match(runner,
    /case BPF_S_LD_W_ABS:[\s\S]*?if \(ptr != NULL\) \{\s*A = get_unaligned_be32\(ptr\);\s*continue;\s*\}\s*break;/);
assert.match(runner, /case BPF_S_RET_A:\s*return A;/);
for (const [opcode, width] of [['BPF_S_LD_B_ABS', 1],
['BPF_S_LD_H_ABS', 2], ['BPF_S_LD_W_ABS', 4]]) {
    assert.match(source, new RegExp(`case ${opcode}:[\\s\\S]*?load_pointer\\(skb, k, ${width}, &tmp\\)`));
    assert.equal(fits(99, 0, 100, width), width === 1,
        `${width}-byte access starting at the final byte`);
    assert.equal(fits(100 - width, 0, 100, width), true,
        `${width}-byte access ending exactly at skb tail`);
    assert.equal(fits(9, 10, 100, width), false,
        `${width}-byte access starting before skb head`);
}

console.log('PASS: width bounds and direct RET A failure path; source/model check only, not compiled-kernel execution');