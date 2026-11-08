import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../../release/src/router/snooper/${path}`, import.meta.url), 'utf8');
const cache = read('cache.c');
const timerSource = read('timer.c');

function functionBody(source, signature) {
    let start = source.indexOf(signature);
    assert.notEqual(start, -1, `${signature} exists`);
    let open = source.indexOf('{', start);
    while (source.indexOf(';', start) < open && source.indexOf(';', start) !== -1) {
        start = source.indexOf(signature, start + signature.length);
        assert.notEqual(start, -1, `${signature} definition exists`);
        open = source.indexOf('{', start);
    }
    let depth = 0;
    for (let index = open; index < source.length; index++) {
        if (source[index] === '{') depth++;
        if (source[index] === '}' && --depth === 0) return source.slice(open + 1, index);
    }
    assert.fail(`${signature} has a closing brace`);
}

const getGroup = functionBody(cache, 'static struct group_entry *get_group(');
const consumeGroup = functionBody(cache, 'static void consume_group(');
const consumePort = functionBody(cache, 'static void consume_port(');
const consumeMember = functionBody(cache, 'static void consume_member(');
const addMember = functionBody(cache, 'int add_member(');
const expireMembers = functionBody(cache, 'int expire_members(');

assert.ok(getGroup.indexOf('consume_group(group)') < getGroup.indexOf('memset(group, 0, sizeof(*group))'),
    'recycled group cleanup runs before the entry is cleared');
assert.ok(consumeGroup.indexOf('del_timer(&group->timer)') < consumeGroup.indexOf('consume_port(group, port)'),
    'group cleanup detaches its timer before returning members');
assert.match(consumePort, /consume_member\(member\)/);
assert.match(consumeMember, /LIST_INSERT_HEAD\(&members\.free, member, link\)/);

assert.match(addMember,
    /timer = &group->timer;\s*if \(group->portmap\) \{\s*if \(!timer_pending\(timer\)[\s\S]*?mod_timer\(timer, group->time\);\s*\} else\s*del_timer\(timer\);/,
    'add_member cancels rather than arms a memberless group timer');
const emptyGroupExpirations = expireMembers.match(
    /if \(group->portmap\) \{\s*if \(!timer_pending\(&group->timer\)[\s\S]*?mod_timer\(&group->timer, time\);\s*\} else\s*del_timer\(&group->timer\);/g);
assert.equal(emptyGroupExpirations?.length, 2,
    'both targeted and all-groups expiry avoid arming memberless groups');

assert.match(functionBody(timerSource, 'int run_timers('), /TAILQ_FOREACH_SAFE/);
assert.match(functionBody(timerSource, 'int next_timer('), /TAILQ_FOREACH/);

function makeQueue() {
    const headSlot = { value: null };
    return { headSlot, tailSlot: headSlot };
}

function append(queue, node) {
    node.nextSlot.value = null;
    node.prev = queue.tailSlot;
    queue.tailSlot.value = node;
    queue.tailSlot = node.nextSlot;
}

function remove(queue, node) {
    const next = node.nextSlot.value;
    node.prev.value = next;
    if (next) next.prev = node.prev;
    else queue.tailSlot = node.prev;
    node.prev = null;
    node.nextSlot.value = null;
}

function assertQueueValid(queue) {
    let slot = queue.headSlot;
    const seen = new Set();
    while (slot.value) {
        const node = slot.value;
        assert.ok(!seen.has(node), 'timer queue contains no cycle');
        assert.equal(node.prev, slot, 'each timer points to its predecessor slot');
        seen.add(node);
        slot = node.nextSlot;
    }
    assert.equal(slot, queue.tailSlot, 'tail points at the final next slot');
    assert.equal(queue.tailSlot.value, null, 'tail next slot is empty');
    return [...seen];
}

const before = { name: 'before', nextSlot: { value: null }, prev: null };
const recycled = { name: 'recycled', nextSlot: { value: null }, prev: null };
const after = { name: 'after', nextSlot: { value: null }, prev: null };
const queue = makeQueue();
append(queue, before);
append(queue, recycled);
append(queue, after);
remove(queue, recycled);
recycled.nextSlot.value = null;
recycled.prev = null;
append(queue, recycled);
assert.deepEqual(assertQueueValid(queue).map((node) => node.name), ['before', 'after', 'recycled']);

const brokenQueue = makeQueue();
const staleTail = { name: 'stale-tail', nextSlot: { value: null }, prev: null };
append(brokenQueue, staleTail);
staleTail.nextSlot.value = null;
staleTail.prev = null;
append(brokenQueue, staleTail);
assert.throws(() => assertQueueValid(brokenQueue), /cycle|predecessor slot/,
    'zeroing a queued tail reproduces the self-linked timer');

console.log('IGMP snooper timer recycle regression passed');