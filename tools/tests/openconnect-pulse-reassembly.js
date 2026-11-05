const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/openconnect/pulse.c'), 'utf8');
const connectStart = source.indexOf('int pulse_connect(struct openconnect_info *vpninfo)');
const connectEnd = source.indexOf('\n}\n', connectStart);
assert.notEqual(connectStart, -1, 'pulse_connect must exist');
const connect = source.slice(connectStart, connectEnd);

assert.match(connect,
    /ret = recv_ift_packet\(vpninfo, bytes \+ ii, MIN\(config_len - ii, TLS_RECORD_MAX\)\);/,
    'each config read must be capped by the remaining allocation');
assert.doesNotMatch(connect,
    /recv_ift_packet\(vpninfo, bytes \+ ii, MAX\(/,
    'the read length must not grow as the buffer fills');

const configLength = 16384;
const recordMax = 16384;
const serverRecords = [16000, 16384];
const readLimits = [];
let offset = 0;

for (const recordLength of serverRecords) {
    const readLimit = Math.min(configLength - offset, recordMax);
    const bytesRead = Math.min(recordLength, readLimit);
    readLimits.push(readLimit);
    assert.ok(bytesRead > 0);
    assert.ok(offset + bytesRead <= configLength,
        'the received bytes must remain within the allocated config buffer');
    offset += bytesRead;
    if (offset === configLength)
        break;
}

assert.deepEqual(readLimits, [16384, 384],
    'the second TLS read must be limited to the 384 bytes still allocated');
assert.equal(offset, configLength,
    'the split configuration packet must fill, but not exceed, its allocation');

console.log('openconnect-pulse-reassembly: config reads stay within the allocated buffer');