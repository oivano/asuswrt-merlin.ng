const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter');
const expectSource = fs.readFileSync(path.join(kernel, 'nf_conntrack_expect.c'), 'utf8');
const coreSource = fs.readFileSync(path.join(kernel, 'nf_conntrack_core.c'), 'utf8');

const lookupStart = expectSource.indexOf('nf_ct_find_expectation(');
const lookupEnd = expectSource.indexOf('/* delete all expectations for this conntrack */', lookupStart);
assert.ok(lookupStart >= 0 && lookupEnd > lookupStart,
    'nf_ct_find_expectation implementation exists');
const lookup = expectSource.slice(lookupStart, lookupEnd);

const confirmed = lookup.indexOf('if (!nf_ct_is_confirmed(exp->master))');
const acquire = lookup.indexOf('!atomic_inc_not_zero(&exp->master->ct_general.use)');
const permanent = lookup.indexOf('if (exp->flags & NF_CT_EXPECT_PERMANENT)');
const timerClaim = lookup.indexOf('del_timer(&exp->timeout)');
const release = lookup.indexOf('nf_ct_put(exp->master);');
assert.ok(confirmed >= 0 && acquire > confirmed && permanent > acquire &&
    timerClaim > permanent && release > timerClaim,
    'master must be confirmed and referenced before expectation removal');
assert.match(lookup, /nf_ct_is_dying\(exp->master\)\s*\|\|\s*!atomic_inc_not_zero/,
    'reject a dying master or a zero reference count');
assert.match(lookup, /else if \(del_timer\(&exp->timeout\)\)\s*\{[\s\S]*?return exp;/,
    'transfer the acquired reference when the timer is claimed');
assert.match(lookup, /nf_ct_put\(exp->master\);\s*return NULL;/,
    'drop the acquired reference if the timer cannot be claimed');

const initStart = coreSource.indexOf('init_conntrack(struct net *net');
const initEnd = coreSource.indexOf('/* On success, returns conntrack ptr', initStart);
assert.ok(initStart >= 0 && initEnd > initStart, 'init_conntrack implementation exists');
const init = coreSource.slice(initStart, initEnd);
assert.match(init, /ct->master = exp->master;/,
    'store the reference transferred by expectation lookup');
assert.doesNotMatch(init, /nf_conntrack_get\(&ct->master->ct_general\)/,
    'do not increment the master reference a second time');
assert.match(init, /nf_conntrack_get\(&ct->ct_general\);/,
    'preserve the new child conntrack initial reference');

console.log('PASS: conntrack expectation master reference ownership (source contract; not kernel execution)');