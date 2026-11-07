const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const sourcePath = path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/net/sched/sch_hfsc.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const changeStart = source.indexOf('hfsc_change_class(struct Qdisc *sch');
const changeEnd = source.indexOf('\nstatic void\nhfsc_destroy_class', changeStart);
assert(changeStart >= 0 && changeEnd > changeStart, 'missing hfsc_change_class');
const change = source.slice(changeStart, changeEnd);

const parentLookup = change.indexOf('parent = hfsc_find_class(parentid, sch);');
const parentGuard = change.indexOf(
    'if (parent != &q->root && !(parent->cl_flags & HFSC_FSC))');
const allocation = change.indexOf('kzalloc(sizeof(struct hfsc_class), GFP_KERNEL);');
assert(parentLookup >= 0, 'non-root parent lookup must remain present');
assert(parentGuard > parentLookup && parentGuard < allocation,
    'parent eligibility must be checked before class allocation');
assert.match(change.slice(parentGuard),
    /^if \(parent != &q->root && !\(parent->cl_flags & HFSC_FSC\)\)\s*return -EINVAL;/,
    'an inner parent must have an FSC curve');

const HFSC_FSC = 0x2;
const canBeParent = (isRoot, flags) => isRoot || (flags & HFSC_FSC) !== 0;
assert.equal(canBeParent(true, 0), true, 'root remains a valid parent');
assert.equal(canBeParent(false, HFSC_FSC), true,
    'an FSC class remains a valid parent');
assert.equal(canBeParent(false, 0x1), false,
    'an rt-only class cannot become a parent');
assert.equal(canBeParent(false, 0x4), false,
    'an ls-only class cannot become a parent');

console.log('sch-hfsc-parent-fsc: ok');