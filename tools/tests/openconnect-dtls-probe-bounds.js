const assert = require('assert');
const fs = require('fs');

const f5 = fs.readFileSync('release/src/router/openconnect/f5.c', 'utf8');
const fortinet = fs.readFileSync('release/src/router/openconnect/fortinet.c', 'utf8');

function functionBody(source, name) {
    const start = source.indexOf(`int ${name}(`);
    assert.notStrictEqual(start, -1, `${name} exists`);
    const end = source.indexOf('\n}', start);
    assert.notStrictEqual(end, -1, `${name} body ends`);
    return source.slice(start, end);
}

for (const [source, name, length, terminator] of [
    [f5, 'f5_dtls_catch_probe', 'pkt->len', 'pkt->data[pkt->len]'],
    [fortinet, 'fortinet_dtls_catch_svrhello', 'len', 'buf[len]'],
]) {
    const body = functionBody(source, name);
    const guard = body.indexOf(`${length} >= pkt->alloc_len - sizeof(*pkt)`);
    const store = body.indexOf(`${terminator} = 0`);
    assert(guard !== -1, `${name} checks available packet capacity`);
    assert(store !== -1, `${name} still terminates its input`);
    assert(guard < store, `${name} checks capacity before writing the terminator`);

    const capacity = 16384;
    const hasTerminatorRoom = receivedLength => receivedLength < capacity;
    assert.strictEqual(hasTerminatorRoom(capacity - 1), true);
    assert.strictEqual(hasTerminatorRoom(capacity), false);
}

console.log('OpenConnect DTLS probe buffer bounds: PASS');