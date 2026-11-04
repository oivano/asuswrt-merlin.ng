'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src/router/snooper/broadcom.c'), 'utf8');
const body = (start, end) => {
    const offset = source.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = source.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return source.slice(offset, limit);
};

const readEntry = body('static int read_entry(', 'static int write_entry(');
const add = body('int switch_add_portmap(', 'int switch_del_portmap(');
const del = body('int switch_del_portmap(', 'int switch_clr_portmap(');

assert.match(readEntry, /\*index = -1;\s*\*free_slots = 0;/);
assert.match(readEntry, /if \(!valid\) \{[\s\S]*?\(\*free_slots\)\+\+;/);
assert.match(readEntry, /memset\(entry, 0, sizeof\(uint16_t\) \* 6\);/);
assert.match(add, /value = read_entry\(hwaddr, vlan, entry, &index, &free_slots\);/);
assert.match(add, /if \(index < 0 \|\| free_slots <= 1\)\s*return -1;/);
assert.ok(add.indexOf('free_slots <= 1') < add.indexOf('write_entry('),
    'reject insertion before any table write');
assert.match(del, /if \(value < 0\)\s*return -1;/);
assert.match(del, /if \(portmap == cpu_portmap\) \{[\s\S]*?write_entry\(hwaddr, vlan, entry, index, -1\);/);

function addGroup(entries, mac, ports) {
    const existing = entries.find(entry => entry && entry.mac === mac);
    if (existing) {
        existing.ports |= ports;
        return true;
    }
    const freeSlots = entries.filter(entry => entry === null).length;
    if (freeSlots <= 1)
        return false;
    const free = entries.findIndex(entry => entry === null);
    entries[free] = {mac, ports};
    return true;
}

function learnUnicast(entries, mac) {
    const free = entries.findIndex(entry => entry === null);
    if (free < 0)
        return false;
    entries[free] = {mac, ports: 8, dynamic: true};
    return true;
}

function deletePorts(entries, mac, ports, cpuPorts) {
    const index = entries.findIndex(entry => entry && entry.mac === mac);
    if (index < 0)
        return false;
    const remaining = (entries[index].ports & ~ports) | cpuPorts;
    if (remaining === cpuPorts)
        entries[index] = null;
    else
        entries[index].ports = remaining;
    return true;
}

for (const size of [2, 4]) {
    const entries = Array.from({length: size}, () => null);
    entries[0] = {mac: 'router', ports: 1};
    while (entries.filter(entry => entry === null).length > 1)
        assert.equal(addGroup(entries, `group-${size}-${entries.filter(Boolean).length}`, 3), true);
    const before = entries.map(entry => entry && {...entry});
    assert.equal(addGroup(entries, `overflow-${size}`, 4), false,
        `${size}-way bucket keeps its final way available for learning`);
    assert.deepEqual(entries, before, 'a refused join leaves every bucket entry intact');
}

const bucket = [
    {mac: 'router', ports: 1},
    {mac: 'group-a', ports: 3},
    {mac: 'group-b', ports: 5},
    null
];
assert.equal(learnUnicast(bucket, 'learned-unicast'), true,
    'a unicast can use the way reserved by snooper joins');
const full = bucket.map(entry => entry && {...entry});
assert.equal(addGroup(bucket, 'group-c', 9), false,
    'a full bucket refuses a colliding multicast entry');
assert.deepEqual(bucket, full, 'full-bucket refusal does not evict the router or learned MAC');
assert.equal(addGroup(bucket, 'group-a', 16), true,
    'an existing group can be updated without consuming another way');
assert.equal(bucket[1].ports, 19);

const cleanup = [
    {mac: 'router', ports: 1},
    {mac: 'group-a', ports: 5},
    null,
    null
];
assert.equal(deletePorts(cleanup, 'group-a', 4, 1), true);
assert.equal(cleanup[1], null, 'last non-CPU membership clears the ARL entry');
assert.equal(cleanup.some(entry => entry && entry.mac === 'group-a'), false);

const remainingMember = [
    {mac: 'group-b', ports: 7},
    null
];
assert.equal(deletePorts(remainingMember, 'group-b', 2, 1), true);
assert.deepEqual(remainingMember[0], {mac: 'group-b', ports: 5},
    'entries with another member remain installed');

console.log('PASS: Broadcom snooper ARL collision and empty-group contracts (modeled, not switch hardware)');