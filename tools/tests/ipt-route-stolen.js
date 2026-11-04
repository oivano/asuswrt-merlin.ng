const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/sched/act_ipt.c'), 'utf8');
const start = source.indexOf('static int ipt_init_target(');
assert.notEqual(start, -1, 'ipt_init_target exists');
const open = source.indexOf('{', start);
let depth = 1;
let end = open + 1;
for (; end < source.length && depth !== 0; end++) {
    if (source[end] === '{') depth++;
    if (source[end] === '}') depth--;
}
assert.equal(depth, 0, 'ipt_init_target body is closed');
const body = source.slice(open + 1, end - 1);

const refusal = body.indexOf('!strncmp(t->u.user.name, "ROUTE", sizeof(t->u.user.name))');
const lookup = body.indexOf('xt_request_find_target');
assert.ok(refusal >= 0, 'the vendor ROUTE target is refused');
assert.ok(refusal < lookup, 'ROUTE is refused before target lookup and autoload');
assert.match(body.slice(refusal, lookup), /return -EOPNOTSUPP;/);

const isRefused = name => {
    const field = Buffer.alloc(29);
    field.write(name, 'ascii');
    return field.subarray(0, 6).equals(Buffer.from('ROUTE\0', 'ascii'));
};
assert.equal(isRefused('ROUTE'), true);
assert.equal(isRefused('ROUTE\0trailing'), true);
assert.equal(isRefused('ROUTER'), false);
assert.equal(isRefused('MARK'), false);

console.log('PASS: tc ipt refuses ROUTE before loading the skb-consuming target');