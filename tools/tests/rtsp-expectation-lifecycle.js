const assert = require('assert');
const fs = require('fs');
const path = require('path');

const sourcePath = path.join(
    __dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/netfilter/nf_nat_rtsp.c'
);
const source = fs.readFileSync(sourcePath, 'utf8');
const start = source.indexOf('case pb_discon:');
const end = source.indexOf('\n    }\n\n    if (rbuf1len == 0)', start);

assert(start >= 0 && end > start, 'slash-port expectation block exists');
const block = source.slice(start, end);
assert.strictEqual(
    (block.match(/nf_ct_expect_related\(exp\)/g) || []).length,
    1,
    'original expectation is registered only for the low port'
);
assert.match(block, /nf_ct_expect_alloc\(ct\)/);
assert.match(block, /nf_ct_expect_related\(exp2\)/);
assert.match(block, /exp2->tuple = exp->tuple;/);
assert.match(block, /exp2->mask = exp->mask;/);
assert.match(block, /exp2->expectfn = exp->expectfn;/);
assert.match(block, /nf_ct_unexpect_related\(exp\);[\s\S]*?nf_ct_expect_put\(exp2\);/);

const failure = source.slice(source.indexOf('mangle_failed:'), source.indexOf('\n}\n\nstatic uint', source.indexOf('mangle_failed:')));
assert.match(failure, /nf_ct_unexpect_related\(exp\);/);
assert.match(failure, /nf_ct_unexpect_related\(exp2\);/);
assert.match(failure, /nf_ct_expect_put\(exp2\);/);

console.log('RTSP expectation lifecycle checks passed');
