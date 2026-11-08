const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const reply = fs.readFileSync(
    path.join(root, 'release/src/router/samba-3.6.x_opwrt/source/source3/smbd/reply.c'),
    'utf8'
);

const handler = (name, end) => {
    const start = reply.indexOf(`void ${name}(`);
    const finish = reply.indexOf(end, start);
    assert.ok(start >= 0 && finish > start, `${name} handler exists`);
    return reply.slice(start, finish);
};

for (const [name, end] of [
    ['reply_search', '/****************************************************************************\n Reply to a fclose'],
    ['reply_fclose', '/****************************************************************************\n Reply to an open.']
]) {
    const body = handler(name, end);
    const lengthGuard = body.indexOf('smbreq_bufrem(req, p) < 3');
    const lengthRead = body.indexOf('status_len = SVAL(p');
    const resumeGuard = body.indexOf('smbreq_bufrem(req, p) < 21');
    const resumeCopy = body.indexOf('memcpy(status,p,21)');

    assert.ok(lengthGuard >= 0 && lengthGuard < lengthRead, `${name} checks before reading status_len`);
    assert.ok(resumeGuard > lengthRead && resumeGuard < resumeCopy, `${name} checks before copying resume key`);
    assert.match(body.slice(lengthGuard, lengthRead), /reply_nterror\(req, NT_STATUS_INVALID_PARAMETER\)/);
    assert.match(body.slice(resumeGuard - 40, resumeGuard), /status_len != 0/);
    assert.match(body.slice(resumeGuard, resumeCopy), /reply_nterror\(req, NT_STATUS_INVALID_PARAMETER\)/);
}

const acceptsStatus = (bytesAfterPath, statusLength) => {
    if (bytesAfterPath < 3) return false;
    const resumeBytes = bytesAfterPath - 3;
    return statusLength === 0 || resumeBytes >= 21;
};

for (const length of [0, 1, 2]) assert.equal(acceptsStatus(length, 0), false);
assert.equal(acceptsStatus(3, 0), true);
assert.equal(acceptsStatus(3, 1), false);
assert.equal(acceptsStatus(23, 1), false);
assert.equal(acceptsStatus(24, 1), true);
assert.equal(acceptsStatus(24, 255), true);