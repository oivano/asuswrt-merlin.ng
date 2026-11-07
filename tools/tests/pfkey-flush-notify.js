const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const sourcePath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/key/af_key.c';
const source = fs.readFileSync(path.join(root, sourcePath), 'utf8');

function functionBody(name, nextName) {
    const start = source.indexOf(`static int ${name}(`);
    const end = source.indexOf(`static int ${nextName}(`, start);
    assert.ok(start >= 0 && end > start, `${name}() present`);
    return source.slice(start, end);
}

const notifications = [
    ['key_notify_sa_flush', 'pfkey_flush', 'SADB_FLUSH'],
    ['key_notify_policy_flush', 'pfkey_spdflush', 'SADB_X_SPDFLUSH'],
];

for (const [name, nextName, messageType] of notifications) {
    const body = functionBody(name, nextName);
    const allocation = body.indexOf('skb_put(');
    const zeroHeader = body.indexOf('memset(hdr, 0, sizeof(*hdr));');
    const firstFieldWrite = body.indexOf('hdr->sadb_msg_');

    assert.ok(allocation >= 0, `${name}() allocates its message header`);
    assert.ok(zeroHeader > allocation, `${name}() zeroes the allocated header`);
    assert.ok(firstFieldWrite > zeroHeader, `${name}() zeroes before setting fields`);
    assert.ok(body.includes(`hdr->sadb_msg_type = ${messageType};`),
        `${name}() retains the flush message type`);
}

assert.match(functionBody('key_notify_policy_flush', 'pfkey_spdflush'),
    /hdr->sadb_msg_satype\s*=\s*SADB_SATYPE_UNSPEC;/,
    'policy flush declares its satype as unspecified');

console.log('PASS: PF_KEY flush notification headers are initialized before broadcast (source contract; not kernel execution)');