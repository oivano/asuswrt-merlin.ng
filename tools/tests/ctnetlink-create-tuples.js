const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const src = fs.readFileSync(path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/nf_conntrack_netlink.c'), 'utf8');
const start = src.indexOf('ctnetlink_new_conntrack(');
assert(start >= 0, 'missing ctnetlink_new_conntrack');
const end = src.indexOf('\nstatic int', start + 1);
assert(end > start, 'missing end of ctnetlink_new_conntrack');
const handler = src.slice(start, end);
const createBranch = handler.indexOf('if (nlh->nlmsg_flags & NLM_F_CREATE)');
const guard = handler.indexOf('if (!cda[CTA_TUPLE_ORIG] || !cda[CTA_TUPLE_REPLY])');
const allocate = handler.indexOf('ctnetlink_create_conntrack(');

assert(createBranch >= 0, 'missing create branch');
assert(guard > createBranch && guard < allocate,
    'missing-tuple guard must run in the create branch before allocation');
assert.match(handler.slice(guard, allocate), /err = -EINVAL;\s*goto out_unlock;/);

function createResult({ orig, reply, existing, create }) {
    let allocations = 0;
    if (existing) return { error: null, allocations };
    if (!create) return { error: -2, allocations };
    if (!orig || !reply) return { error: -22, allocations };
    allocations++;
    return { error: null, allocations };
}

for (const [orig, reply] of [[false, false], [true, false], [false, true]]) {
    assert.deepEqual(createResult({ orig, reply, existing: false, create: true }),
        { error: -22, allocations: 0 });
}
assert.deepEqual(createResult({ orig: true, reply: true, existing: false, create: true }),
    { error: null, allocations: 1 });
assert.deepEqual(createResult({ orig: true, reply: false, existing: true, create: true }),
    { error: null, allocations: 0 });
assert.deepEqual(createResult({ orig: true, reply: false, existing: false, create: false }),
    { error: -2, allocations: 0 });

console.log('ctnetlink-create-tuples: ok');