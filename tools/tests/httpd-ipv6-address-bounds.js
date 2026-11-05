'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const arrays = fs.readFileSync(path.join(root, 'release/src/router/httpd/data_arrays.c'), 'utf8');

assert.match(web, /#define IPV6_CLIENT_ADDRS_MAX\s+128/);
assert.match(web, /append_joined_value\(buffer, len - 1, ","/);
assert.match(web, /formatted_len\s*=\s*vsnprintf\(buf, sizeof\(buf\), fmt, args\)/);
assert.match(web, /formatted_len\s*>=\s*\(int\)sizeof\(buf\)/);
assert.match(web, /address_count\s*>=\s*IPV6_CLIENT_ADDRS_MAX/);
assert.doesNotMatch(web, /p\s*\+=\s*snprintf\(p,\s*sizeof\(ipaddrs\)\s*\+/);
assert.doesNotMatch(web, /next\s*\+=\s*snprintf\(next,\s*sizeof\(dnsbuf\)\s*\+/);
assert.doesNotMatch(arrays, /p\s*\+=\s*snprintf\(p,\s*sizeof\(ipaddrs\)\s*\+/);
assert.doesNotMatch(arrays, /next\s*\+=\s*sprintf\(next/);
assert.match(web, /static int append_joined_value\(char \*buffer, size_t buffer_size/);
assert.match(arrays, /static int append_joined_value\(char \*buffer, size_t buffer_size/);

function appendJoinedValue(storage, used, capacity, separator, value) {
    const separatorBytes = Buffer.from(used ? separator : '');
    const valueBytes = Buffer.from(value);
    const remaining = capacity - used;
    if (separatorBytes.length >= remaining || valueBytes.length >= remaining - separatorBytes.length)
        return used;
    separatorBytes.copy(storage, used);
    valueBytes.copy(storage, used + separatorBytes.length);
    used += separatorBytes.length + valueBytes.length;
    storage[used] = 0;
    return used;
}

function renderAddresses(addresses) {
    const capacity = 8193;
    const storage = Buffer.alloc(capacity + 8, 0xa5);
    storage[0] = 0;
    let used = 0;
    for (const address of addresses) {
        const previousUsed = used;
        used = appendJoinedValue(storage, used, capacity, ', ', address);
        if (used === previousUsed && address.length)
            break;
    }
    assert.ok(storage.subarray(capacity).every((byte) => byte === 0xa5), 'append wrote beyond ipaddrs');
    return storage.toString('utf8', 0, used);
}

function buildClientRow(addresses) {
    const capacity = 8191;
    let row = 'client 00:11:22:33:44:55 ' + addresses[0];
    let count = 1;
    for (const address of addresses.slice(1)) {
        if (count >= 128)
            break;
        const next = row + ',' + address;
        if (Buffer.byteLength(next) >= capacity)
            break;
        row = next;
        count++;
    }
    const record = row + '\n';
    assert.ok(Buffer.byteLength(record) < 8192, 'save_file record lost its newline');
    return { record, count };
}

for (const [count, address] of [[1168, '2abc::'], [205, '2'.repeat(39)]]) {
    const rendered = renderAddresses(Array(count).fill(address));
    assert.ok(rendered.length < 8193);
    assert.equal(rendered.split(', ').every((entry) => entry === address), true);

    const row = buildClientRow(Array(count).fill(address));
    assert.equal(row.record.endsWith('\n'), true);
    assert.ok(row.count <= 128);
}

console.log('httpd IPv6 address aggregation bounds passed');