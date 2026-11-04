const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/netfilter/ipt_TRIGGER.c'), 'utf8');
const functionBody = signature => {
    const start = source.indexOf(signature);
    assert.notEqual(start, -1, `${signature} exists`);
    const open = source.indexOf('{', start);
    let depth = 1;
    for (let cursor = open + 1; cursor < source.length; cursor++) {
        if (source[cursor] === '{') depth++;
        if (source[cursor] === '}' && --depth === 0) return source.slice(open + 1, cursor);
    }
    assert.fail(`${signature} body is closed`);
};

assert.match(source, /#define LIST_FIND_LOCKED/);
assert.equal((source.match(/LIST_FIND\(/g) || []).length, 1, 'unsafe lookup macro has no callers');
assert.match(source, /active;\s*\/\* Protected by trigger_lock \*\//);

for (const name of ['trigger_out', 'trigger_in', 'trigger_refresh']) {
    const body = functionBody(`static unsigned int ${name}(`);
    assert.ok(body.indexOf('write_lock_bh(&trigger_lock)') < body.indexOf('LIST_FIND_LOCKED('),
        `${name} acquires the lifetime lock before lookup`);
    assert.match(body, /__trigger_timer_refresh_locked\(/, `${name} refreshes while locked`);
    assert.match(body, /write_unlock_bh\(&trigger_lock\)/, `${name} releases the lock`);
}

const dnat = functionBody('static unsigned int trigger_dnat(');
assert.ok(dnat.indexOf('write_lock_bh(&trigger_lock)') < dnat.indexOf('LIST_FIND_LOCKED('));
assert.ok(dnat.indexOf('trig->srcip') < dnat.indexOf('write_unlock_bh(&trigger_lock)'));
assert.ok(dnat.indexOf('trig->reply = 1') < dnat.indexOf('write_unlock_bh(&trigger_lock)'));
assert.doesNotMatch(dnat.slice(dnat.indexOf('write_unlock_bh(&trigger_lock)')), /trig->/);
assert.match(dnat, /IP_NAT_RANGE_MAP_IPS, srcip, srcip/);

const timeout = functionBody('static void trigger_timeout(');
assert.ok(timeout.indexOf('trig->active = 0') < timeout.indexOf('list_del_init(&trig->list)'));
assert.ok(timeout.indexOf('list_del_init(&trig->list)') < timeout.lastIndexOf('write_unlock_bh(&trigger_lock)'));
assert.ok(timeout.indexOf('write_unlock_bh(&trigger_lock)') < timeout.indexOf('nf_ct_iterate_cleanup'));
assert.ok(timeout.indexOf('nf_ct_iterate_cleanup') < timeout.indexOf('kfree(trig)'));

const flush = functionBody('static void trigger_flush(');
assert.ok(flush.indexOf('trig->active = 0') < flush.indexOf('write_unlock_bh(&trigger_lock)'));
assert.ok(flush.indexOf('write_unlock_bh(&trigger_lock)') < flush.indexOf('del_timer_sync(&trig->timeout)'));
assert.ok(flush.indexOf('del_timer_sync(&trig->timeout)') < flush.indexOf('nf_ct_iterate_cleanup'));
assert.ok(flush.indexOf('nf_ct_iterate_cleanup') < flush.indexOf('kfree(trig)'));

console.log('PASS: packet lookups retain trigger lifetime; timeout and flush claim entries exclusively');