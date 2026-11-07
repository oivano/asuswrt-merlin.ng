const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = name => fs.readFileSync(path.join(root, name), 'utf8');
const base = 'release/src/router/samba-3.6.x_opwrt/source/source3/smbd/';
const globals = source(`${base}globals.h`);
const server = source(`${base}smb2_server.c`);
const read = source(`${base}smb2_read.c`);
const tcon = source(`${base}smb2_tcon.c`);
const sesssetup = source(`${base}smb2_sesssetup.c`);
const create = source(`${base}smb2_create.c`);

const functionBody = (text, signature, fromEnd = false) => {
    const start = fromEnd ? text.lastIndexOf(signature) : text.indexOf(signature);
    assert.notEqual(start, -1, `missing ${signature}`);
    const open = text.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < text.length; index++) {
        if (text[index] === '{') depth++;
        if (text[index] === '}' && --depth === 0) return text.slice(open, index + 1);
    }
    assert.fail(`unterminated ${signature}`);
};

const cancelPending = functionBody(server, 'bool smbd_smb2_request_cancel_pending(');
assert.match(cancelPending, /req = sconn->smb2\.requests/);
assert.match(cancelPending, /req->session != session/);
assert.match(cancelPending, /req->tcon != tcon/);
assert.match(cancelPending, /req->subreq != NULL && !tevent_req_cancel\(req->subreq\)/);
assert.match(cancelPending, /return all_cancelled/);
assert.match(globals, /uint64_t generation;/);
assert.match(globals, /smbd_smb2_request_cancel_pending/);

const processTdis = functionBody(tcon, 'NTSTATUS smbd_smb2_request_process_tdis(');
assert.ok(processTdis.indexOf('smbd_smb2_request_cancel_pending') < processTdis.indexOf('TALLOC_FREE(req->tcon)'));
assert.match(processTdis, /!smbd_smb2_request_cancel_pending[\s\S]*NT_STATUS_INTERNAL_ERROR/);

const sessionDestructor = functionBody(sesssetup, 'static int smbd_smb2_session_destructor(');
assert.ok(sessionDestructor.indexOf('smbd_smb2_request_cancel_pending') < sessionDestructor.indexOf('while (session->tcons.list)'));
assert.match(sessionDestructor, /if \(!smbd_smb2_request_cancel_pending[\s\S]*return -1/);
const processLogoff = functionBody(sesssetup, 'NTSTATUS smbd_smb2_request_process_logoff(');
assert.match(processLogoff, /smbd_smb2_session_destructor\(req->session\) != 0[\s\S]*NT_STATUS_INTERNAL_ERROR/);

const createSend = functionBody(create, 'static struct tevent_req *smbd_smb2_create_send(', true);
assert.match(createSend, /state->session = smb2req->session/);
assert.match(createSend, /state->tcon_generation = smb2req->tcon->generation/);
assert.match(createSend, /smb2req->session != state->session[\s\S]*smb2req->tcon->generation != state->tcon_generation[\s\S]*NT_STATUS_NETWORK_NAME_DELETED/);
assert.match(createSend, /smb1req->conn = smb2req->tcon->compat_conn/);
assert.match(createSend, /smb1req->tid = smb2req->tcon->compat_conn->cnum/);

const sendfileDestructor = functionBody(read, 'static int smb2_sendfile_send_data(');
const scheduleSendfile = functionBody(read, 'static NTSTATUS schedule_smb2_sendfile_read(');
const nextIncoming = functionBody(server,
    'static NTSTATUS smbd_smb2_request_next_incoming(', true);
const writevDone = functionBody(server,
    'static void smbd_smb2_request_writev_done(', true);
assert.match(globals, /bool sendfile_pending;/);
assert.ok(scheduleSendfile.indexOf('talloc_set_destructor(state_copy, smb2_sendfile_send_data)') <
    scheduleSendfile.indexOf('sendfile_pending = true'));
assert.ok(sendfileDestructor.indexOf('sendfile_pending = false') <
    sendfileDestructor.indexOf('return 0;'));
assert.ok(nextIncoming.indexOf('if (sconn->smb2.sendfile_pending)') <
    nextIncoming.indexOf('smbd_smb2_request_read_send'));
assert.ok(writevDone.indexOf('TALLOC_FREE(req)') <
    writevDone.indexOf('smbd_smb2_request_next_incoming(sconn)'));

const cancelForScope = (requests, session, tree) => requests.every(request => {
    if ((session !== null && request.session !== session) ||
        (tree !== null && request.tree !== tree)) return true;
    return !request.pending || request.cancel();
});
const originalTree = { generation: 4 };
const replacementTree = { generation: 5 };
const deferredCreate = { session: 'S1', tree: originalTree, pending: true, cancel: () => true };
assert.equal(cancelForScope([deferredCreate], null, originalTree), true);
assert.notEqual(replacementTree.generation, deferredCreate.tree.generation);
assert.equal(cancelForScope([
    deferredCreate,
    { session: 'S1', tree: originalTree, pending: true, cancel: () => false }
], 'S1', null), false);

console.log('SMB2 teardown cancellation and deferred CREATE identity checks passed');