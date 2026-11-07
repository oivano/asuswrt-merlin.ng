const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const sourcePath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/sched/sch_api.c';
const source = fs.readFileSync(path.join(root, sourcePath), 'utf8');

const modifyStart = source.indexOf('static int tc_modify_qdisc(');
const lookup = source.indexOf('qdisc_lookup(dev, tcm->tcm_handle)', modifyStart);
const ref = source.indexOf('atomic_inc(&q->refcnt);', lookup);
assert.ok(modifyStart >= 0 && lookup > modifyStart && ref > lookup,
    'existing-qdisc lookup and graft reference increment exist');

const parentGuard = source.slice(lookup, ref).match(
    /if \(q->parent != clid\)\s*return -EINVAL;/
);
assert.ok(parentGuard, 'reject an existing qdisc requested under a different parent');
const parentMismatch = new Function('qParent', 'requestedParent',
    `return ${parentGuard[0].match(/q->parent != clid/)[0]
        .replace('q->parent', 'qParent')
        .replace('clid', 'requestedParent')
        .replace('!=', '!==')};`);
assert.equal(parentMismatch('1:1', 'root'), true,
    'reject moving a child qdisc to the device root');
assert.equal(parentMismatch('1:1', '1:2'), true,
    'reject moving a child qdisc to another class');
assert.equal(parentMismatch('1:1', '1:1'), false,
    'allow replacement at the qdisc current parent');

const treeStart = source.indexOf('void qdisc_tree_decrease_qlen(');
const treeEnd = source.indexOf('EXPORT_SYMBOL(qdisc_tree_decrease_qlen);', treeStart);
assert.ok(treeStart >= 0 && treeEnd > treeStart,
    'qdisc_tree_decrease_qlen implementation exists');
const tree = source.slice(treeStart, treeEnd);
assert.match(tree,
    /cl = cops->get\(sch, parentid\);\s*if \(cl\) \{\s*cops->qlen_notify\(sch, cl\);\s*cops->put\(sch, cl\);\s*\}/,
    'skip class notification and put when the parent class lookup fails');

console.log('PASS: tc qdisc parent replacement and missing-class guard (source contract/model; not kernel execution)');