const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = 'release/src-rt-6.x.4708/linux/linux-2.6.36/';
const source = fs.readFileSync(path.join(root, kernel, 'net/netfilter/xt_u32.c'), 'utf8');
const header = fs.readFileSync(path.join(root, kernel, 'include/linux/netfilter/xt_u32.h'), 'utf8');
const xtables = fs.readFileSync(path.join(root, kernel, 'net/netfilter/x_tables.c'), 'utf8');
const body = (text, start, end) => {
    const offset = text.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = text.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return text.slice(offset, limit);
};

const validation = body(source, 'static int u32_mt_checkentry(', 'static struct xt_match xt_u32_mt_reg');
assert.match(validation, /data->ntests > ARRAY_SIZE\(data->tests\)/);
assert.match(validation, /test->nnums > ARRAY_SIZE\(test->location\)/);
assert.match(validation, /test->nvalues > ARRAY_SIZE\(test->value\)/);
assert.match(validation, /return -EINVAL;/);
assert.match(source, /\.family\s*= NFPROTO_UNSPEC,/,
    'one family-unspecified match registration serves IPv4 and IPv6');
assert.match(source, /\.checkentry\s*= u32_mt_checkentry,/);
assert.match(xtables, /if \(par->match->checkentry != NULL\)\s*\{\s*ret = par->match->checkentry\(par\);\s*if \(ret < 0\)\s*return ret;/,
    'x_tables rejects rules when the match checkentry returns an error');

const limits = header.match(/#define XT_U32_MAXSIZE (\d+)/);
assert.ok(limits, 'find the fixed u32 array size');
const arrayLength = Number(limits[1]) + 1;
assert.match(header, /location\[XT_U32_MAXSIZE\+1\]/);
assert.match(header, /value\[XT_U32_MAXSIZE\+1\]/);
assert.match(header, /tests\[XT_U32_MAXSIZE\+1\]/);

function rejected(rule) {
    if (rule.ntests > arrayLength)
        return true;
    for (let testIndex = 0; testIndex < rule.ntests; testIndex++) {
        const test = rule.tests[testIndex];
        if (test.nnums > arrayLength || test.nvalues > arrayLength)
            return true;
    }
    return false;
}

const validRule = (ntests = 1, nnums = 1, nvalues = 1) => ({
    ntests,
    tests: Array.from({ length: ntests }, () => ({ nnums, nvalues })),
});

assert.equal(rejected(validRule()), false, 'accept a normal rule');
assert.equal(rejected(validRule(arrayLength, arrayLength, arrayLength)), false,
    'accept counts that fit the fixed arrays');
assert.equal(rejected(validRule(arrayLength + 1)), true, 'reject ntests=12');
assert.equal(rejected(validRule(1, arrayLength + 1)), true, 'reject nnums=12');
assert.equal(rejected(validRule(1, 1, arrayLength + 1)), true, 'reject nvalues=12');
assert.equal(rejected(validRule(1, 255, 255)), true, 'reject maximum byte counts');

console.log('PASS: u32 count bounds and shared IPv4/IPv6 checkentry contracts (source/model only)');