'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const nfs3 = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/nfsd/nfs3xdr.c'), 'utf8');
const nfs2 = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/nfsd/nfsxdr.c'), 'utf8');

function decoderBody(source, name, nextName) {
    const start = source.indexOf(`${name}(`);
    const end = source.indexOf(`\n${nextName}(`, start);
    assert.ok(start >= 0 && end > start, `could not locate ${name}`);
    return source.slice(start, end);
}

const write3 = decoderBody(nfs3, 'nfs3svc_decode_writeargs', 'nfs3svc_decode_createargs');
const write2 = decoderBody(nfs2, 'nfssvc_decode_writeargs', 'nfssvc_decode_createargs');
const symlink3 = decoderBody(nfs3, 'nfs3svc_decode_symlinkargs', 'nfs3svc_decode_mknodargs');

function assertGuardPrecedes(body, marker, name) {
    const guard = body.indexOf('(char *)p > (char *)rqstp->rq_arg.head[0].iov_base +');
    const operation = body.indexOf(marker);
    assert.ok(guard >= 0 && operation > guard, `${name}: request-head bounds guard must precede ${marker}`);
    assert.match(body.slice(guard, operation), /rq_arg\.head\[0\]\.iov_len[\s\S]*?return 0;/,
        `${name}: guard must reject a parsed header past the received head`);
}

assertGuardPrecedes(write3, 'hdr = (void*)p - rqstp->rq_arg.head[0].iov_base',
    'NFSv3 WRITE');
assertGuardPrecedes(write2, 'hdr = (void*)p - rqstp->rq_arg.head[0].iov_base',
    'NFSv2 WRITE');
assertGuardPrecedes(symlink3, 'avail = vec->iov_len - (old - (char*)vec->iov_base)',
    'NFSv3 SYMLINK');

console.log('NFSv2/v3 WRITE and NFSv3 SYMLINK request-head bounds passed');