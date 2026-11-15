const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const sourcePath = 'release/src/router/samba-3.6.x_opwrt/source/source3/smbd/';
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const security = read(`${sourcePath}../librpc/gen_ndr/security.h`);
const notify = read(`${sourcePath}notify.c`);
const smb1 = read(`${sourcePath}nttrans.c`);
const smb2 = read(`${sourcePath}smb2_notify.c`);

function constant(name) {
    const match = security.match(new RegExp(`#define ${name}\\s+\\(\\s*(0x[0-9a-fA-F]+)\\s*\\)`));
    assert.ok(match, `${name} constant exists`);
    return Number(match[1]);
}

const listAccess = constant('SEC_DIR_LIST');
const readAttributes = constant('SEC_FILE_READ_ATTRIBUTE');
const create = notify.match(/NTSTATUS change_notify_create\([\s\S]*?\n\{([\s\S]*?)\n\}/);
assert.ok(create, 'shared change_notify_create function exists');

const body = create[1];
const accessCheck = body.indexOf('if (!(fsp->access_mask & SEC_DIR_LIST))');
assert.ok(accessCheck >= 0, 'change notify checks the handle for directory-list access');
assert.ok(accessCheck < body.indexOf('TALLOC_ZERO_P'), 'denial precedes watch-buffer allocation');
assert.ok(accessCheck < body.indexOf('notify_add('), 'denial precedes watch registration');
assert.match(body.slice(accessCheck), /return NT_STATUS_ACCESS_DENIED;/,
    'handles without list access receive ACCESS_DENIED');

const canWatch = accessMask => (accessMask & listAccess) !== 0;
assert.equal(canWatch(readAttributes), false,
    'an attributes-only directory handle cannot register a change notification');
assert.equal(canWatch(listAccess), true,
    'a directory handle with list access can register a change notification');

for (const [name, handler] of [['SMB1', smb1], ['SMB2', smb2]]) {
    assert.match(handler, /status = change_notify_create\(\s*fsp,/,
        `${name} notify handler uses the shared authorization check`);
}

console.log('PASS: change notify requires SEC_DIR_LIST for SMB1 and SMB2; source contracts only, not compiled Samba or protocol execution');
