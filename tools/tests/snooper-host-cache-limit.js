#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const cachePath = path.join(__dirname, '../../release/src/router/snooper/cache.c');
const source = fs.readFileSync(cachePath, 'utf8');
const hostCache = source.match(/static struct host_entry \*get_host\([\s\S]*?\n}\n\nint get_port/);

assert(hostCache, 'get_host() source exists');
assert.match(source, /#define HOST_POOL_SIZE 32/);
assert.match(hostCache[0], /struct host_entry \*host = NULL, \*prev;/);
assert.match(hostCache[0], /if \(hosts\.count < HOST_POOL_SIZE\) \{[\s\S]*?host = calloc\(1, sizeof\(\*host\)\);[\s\S]*?if \(host\)\s+hosts\.count\+\+;/);
assert.match(hostCache[0], /if \(!host\) \{[\s\S]*?if \(time_before\(host->time, time\)\)[\s\S]*?if \(!host\)\s+return NULL;/);
assert.match(hostCache[0], /STAILQ_INSERT_TAIL\(&hosts\.pool, host, link\);/);

const poolSize = 32;
const ttl = 3;
const entries = [];
let now = 1;

function acquire(mac, knownPort = false) {
    let entry = entries.find(candidate => candidate.mac === mac);
    if (entry)
        return entry;

    if (entries.length < poolSize) {
        entry = { mac, expires: knownPort ? now + ttl : 0 };
        entries.push(entry);
    } else {
        const expired = entries.findIndex(candidate => candidate.expires < now);
        if (expired < 0)
            return null;
        entry = entries[expired];
        entry.mac = mac;
        entry.expires = knownPort ? now + ttl : 0;
    }
    return entry;
}

for (let index = 0; index < 10000; index++) {
    const entry = acquire(`02:00:00:${(index >>> 16) & 255}:${(index >>> 8) & 255}:${index & 255}`);
    assert(entry, `spoofed entry ${index} is handled by allocation or recycling`);
    assert(entries.length <= poolSize, 'live entries remain within the pool limit');
}

entries.length = 0;
for (let index = 0; index < poolSize; index++)
    assert(acquire(`02:01:00:00:00:${index}`, true), `known-port entry ${index} fits in pool`);
assert.strictEqual(acquire('02:02:00:00:00:01', true), null, 'fresh entries are not recycled');

now += ttl + 1;
assert(acquire('02:aa:bb:cc:dd:ee', true), 'an expired entry is recycled');
assert.strictEqual(entries.length, poolSize, 'entry count stays bounded after expiry');

console.log('snooper host cache limit checks passed');
