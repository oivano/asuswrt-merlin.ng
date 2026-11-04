'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = (relativePath) => fs.readFileSync(path.join(root, relativePath), 'utf8');
const xTables = source('release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/x_tables.c');
const header = source('release/src-rt-6.x.4708/linux/linux-2.6.36/include/linux/netfilter/x_tables.h');
const ipv4 = source('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/netfilter/ip_tables.c');
const ipv6 = source('release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/netfilter/ip6_tables.c');

assert.match(header, /xt_check_entry_offsets\(const void \*, const char \*,/);
assert.match(xTables, /int xt_check_entry_offsets\(/);
assert.match(xTables, /target_offset < size_of_base_struct/);
assert.match(xTables, /target_offset \+ sizeof\(\*target\) > next_offset/);
assert.match(xTables, /target->u.target_size < sizeof\(\*target\)/);
assert.match(xTables, /pos->u.match_size < sizeof\(\*pos\)/);
assert.match(xTables, /pos->u.match_size > length/);
assert.match(xTables, /XT_EXTENSION_MAXNAMELEN - 1\] != '\\0'/);

for (const familySource of [ipv4, ipv6]) {
  assert.match(familySource, /e->next_offset > limit - \(unsigned char \*\)e/);
  assert.match(familySource, /xt_check_entry_offsets\(e, \(char \*\)e->elems/);
  assert.match(familySource, /e->target_offset != sizeof\(\*e\)/);
  assert.match(familySource, /set_bit\(\(unsigned long\)\(\(char \*\)iter - \(char \*\)entry0\)/);
  assert.match(familySource, /!test_bit\(newpos, entry_bitmap\)/);
  assert.match(familySource, /e->next_offset >=\s+newinfo->size - pos/);
}

function validEntry({ remaining, entrySize, nextOffset, targetOffset, targetSize, matches }) {
  const matchHeaderSize = 32;
  const targetHeaderSize = 32;

  if (remaining < entrySize || nextOffset < entrySize + targetHeaderSize || nextOffset > remaining)
    return false;
  if (targetOffset < entrySize || targetOffset + targetHeaderSize > nextOffset)
    return false;
  if (targetSize < targetHeaderSize || targetOffset + targetSize > nextOffset)
    return false;

  let matchLength = targetOffset - entrySize;
  for (const matchSize of matches) {
    if (matchSize < matchHeaderSize || matchSize > matchLength)
      return false;
    matchLength -= matchSize;
  }
  return matchLength === 0;
}

const valid = {
  remaining: 128,
  entrySize: 64,
  nextOffset: 128,
  targetOffset: 96,
  targetSize: 32,
  matches: [32],
};
assert.equal(validEntry(valid), true);
assert.equal(validEntry({ ...valid, remaining: 96 }), false);
assert.equal(validEntry({ ...valid, targetOffset: 32, matches: [] }), false);
assert.equal(validEntry({ ...valid, nextOffset: 120, targetOffset: 104, matches: [] }), false);
assert.equal(validEntry({ ...valid, targetSize: 16 }), false);
assert.equal(validEntry({ ...valid, targetSize: 64 }), false);
assert.equal(validEntry({ ...valid, targetOffset: 96, matches: [16] }), false);
assert.equal(validEntry({ ...valid, targetOffset: 96, matches: [64] }), false);
assert.equal(validEntry({ ...valid, targetOffset: 64, targetSize: 64, matches: [] }), true);

const ruleStarts = new Set([0, 128, 256]);
const isRuleStart = (offset) => ruleStarts.has(offset);
assert.equal(isRuleStart(128), true);
assert.equal(isRuleStart(136), false);
assert.equal(isRuleStart(256), true);
assert.equal(288 + 32 < 320, false);

function backtrackStep(familySource) {
  const block = familySource.match(/\/\* Move along one \*\/([\s\S]*?)\n\s*} else {/);
  assert.ok(block, 'chain backtracking block exists');
  const translated = block[1]
    .replace(/ret = -EINVAL;\s*goto out;/g, 'throw new RangeError("invalid offset");')
    .replace(/test_bit\(([^,]+), entry_bitmap\)/g, 'entry_bitmap.has($1)')
    .replace(/\(struct ip6?t_entry \*\)\s*\(entry0 \+ ([^)]+)\)/g, 'entries.get($1)')
    .replace(/e->/g, 'e.').replace(/newinfo->/g, 'newinfo.');
  return new Function('entries', 'newinfo', 'entry_bitmap', 'pos', `
    let e = entries.get(pos);
    let size;
    ${translated}
    return { pos, predecessor: e.counters.pcnt };
  `);
}

function walkChains(advance, rules, hooks) {
  const active = 1 << 5;
  const entries = new Map(rules.map((rule, index) => [index * 128, {
    ...rule, next_offset: 128, counters: { pcnt: 0 }, comefrom: 0,
  }]));
  const starts = new Set(entries.keys());
  const table = { size: rules.length * 128 };
  for (const [hook, start] of hooks.entries()) {
    let pos = start;
    let entry = entries.get(pos);
    entry.counters.pcnt = pos;
    let steps = 0;
    for (;;) {
      assert.ok(++steps < 100, 'chain walk terminates');
      const visited = entry.comefrom & (1 << hook);
      assert.equal(entry.comefrom & active, 0, 'no traversal marker on re-entry');
      entry.comefrom |= (1 << hook) | active;
      if (entry.terminal || visited) {
        let finished = false;
        let oldpos;
        do {
          entry.comefrom ^= active;
          oldpos = pos;
          pos = entry.counters.pcnt;
          entry.counters.pcnt = 0;
          if (pos === oldpos) {
            finished = true;
            break;
          }
          assert.ok(starts.has(pos));
          entry = entries.get(pos);
        } while (oldpos === pos + entry.next_offset);
        if (finished)
          break;
        pos = advance(entries, table, starts, pos).pos;
        entry = entries.get(pos);
      } else {
        const next = entry.jump === undefined ? pos + entry.next_offset : entry.jump;
        assert.ok(starts.has(next));
        entry = entries.get(next);
        entry.counters.pcnt = pos;
        pos = next;
      }
    }
  }
  for (const entry of entries.values()) {
    assert.equal(entry.comefrom & active, 0, 'hook masks exclude the traversal bit');
    assert.equal(entry.counters.pcnt, 0, 'temporary predecessor is cleared');
  }
  return entries;
}

for (const familySource of [ipv4, ipv6]) {
  const advance = backtrackStep(familySource);
  const entries = new Map([0, 128, 256].map((offset) => [offset, {
    next_offset: 128, counters: { pcnt: 0 },
  }]));
  const table = { size: 384 };
  assert.deepEqual(advance(entries, table, ruleStarts, 0), { pos: 128, predecessor: 0 });
  assert.deepEqual(advance(entries, table, ruleStarts, 128), { pos: 256, predecessor: 128 });
  assert.throws(() => advance(entries, table, ruleStarts, 256), /invalid offset/);
  assert.throws(() => advance(entries, table, new Set([0, 256]), 0), /invalid offset/);
  const walked = walkChains(advance, [
    {}, { jump: 768 }, { terminal: true },
    {}, { jump: 768 }, { terminal: true },
    {}, { terminal: true },
  ], [0, 384]);
  assert.equal(walked.get(0).comefrom, 1);
  assert.equal(walked.get(384).comefrom, 2);
  assert.equal(walked.get(768).comefrom, 3, 'shared chain is reachable from both hooks');
}

console.log('iptables offset validation, backtracking and shared-chain hook checks passed');
