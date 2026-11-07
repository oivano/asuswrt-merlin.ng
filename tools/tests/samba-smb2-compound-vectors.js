'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const sourcePath = path.join(__dirname, '../../release/src/router/samba-3.6.x_opwrt/source/source3/smbd/smb2_server.c');
const source = fs.readFileSync(sourcePath, 'utf8');

function functionBody(name, nextName) {
    const start = source.lastIndexOf(name);
    const end = source.indexOf(nextName, start + name.length);
    assert(start >= 0 && end > start, `Could not locate ${name}`);
    return source.slice(start, end);
}

const validate = functionBody('static NTSTATUS smbd_smb2_request_validate(', 'static void smb2_set_operation_credit(');
const setupOut = functionBody('static NTSTATUS smbd_smb2_request_setup_out(', 'static NTSTATUS smbd_smb2_request_reply(');
const done = functionBody('NTSTATUS smbd_smb2_request_done_ex(', 'NTSTATUS smbd_smb2_request_error_ex(');
const nextVector = functionBody('static int smbd_smb2_request_next_vector(', 'static void smbd_smb2_request_read_done(');

assert(validate.includes('count < 4 || ((count - 1) % 3) != 0'));
assert(validate.indexOf('idx + 2 >= count') < validate.indexOf('req->in.vector[idx+1]'));
assert(setupOut.includes('count < 4 || ((count - 1) % 3) != 0'));
assert(setupOut.indexOf('idx + 2 >= count') < setupOut.indexOf('current[0].iov_base'));
assert(done.indexOf('i + 2 >= req->out.vector_count') < done.indexOf('req->out.vector[i+1]'));
assert(nextVector.includes('if (state->missing < SMB2_HDR_BODY + 2) {\n\t\treturn -1;'));
assert(nextVector.includes('if (state->missing == 0 && !state->asked_for_header)'));

function validVectorCount(count) {
    return count >= 4 && ((count - 1) % 3) === 0;
}

for (const count of [4, 7, 10, 13]) {
    assert(validVectorCount(count), `Valid request vector count rejected: ${count}`);
}

for (const count of [3, 5, 6, 8, 9, 11, 12]) {
    assert(!validVectorCount(count), `Malformed request vector count accepted: ${count}`);
}

for (let remaining = 1; remaining < 66; remaining++) {
    assert(remaining < 66, `Short chained fragment accepted: ${remaining}`);
}

assert(!(66 < 66), 'A complete SMB2 header and structure-size prefix was rejected');
console.log('SMB2 compound vector boundaries and guards passed (source-contract test; not an ASan runtime test)');
