const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const reply = read('release/src/router/samba-3.6.x_opwrt/source/source3/smbd/reply.c');
const pipes = read('release/src/router/samba-3.6.x_opwrt/source/source3/smbd/pipes.c');

function handler(source, signature) {
    const start = source.indexOf(signature);
    assert.notEqual(start, -1, `${signature} exists`);
    const end = source.indexOf('\n}\n', start);
    assert.notEqual(end, -1, `${signature} ends`);
    return source.slice(start, end + 2);
}

const cases = [
    [reply, 'void reply_writeunlock(', 3, 'req->buf + 3'],
    [reply, 'void reply_write(', 3, 'req->buf + 3'],
    [reply, 'void reply_writeclose(', 1, 'req->buf + 1'],
    [pipes, 'void reply_pipe_write(', 3, 'req->buf + 3'],
];

for (const [source, signature, offset, dataUse] of cases) {
    const body = handler(source, signature);
    const guard = `req->buflen < ${offset} || numtowrite > req->buflen - ${offset}`;
    assert.ok(body.includes(guard), `${signature} checks available payload bytes`);
    assert.ok(body.includes('NT_STATUS_INVALID_PARAMETER'), `${signature} rejects a short payload`);
    assert.ok(body.indexOf(guard) < body.indexOf(dataUse), `${signature} checks before using the payload`);

    const available = reqLen => Math.max(0, reqLen - offset);
    assert.equal(65535 <= available(offset + 3), false, `${signature} rejects 0xFFFF with 3 data bytes`);
    assert.equal(3 <= available(offset + 3), true, `${signature} accepts an exact 3-byte payload`);
    assert.equal(0 <= available(offset), true, `${signature} accepts a zero-length payload`);
    assert.equal(4 <= available(offset + 3), false, `${signature} rejects one byte beyond the payload`);
}

console.log('SMB1 file and pipe write payload bounds passed');
