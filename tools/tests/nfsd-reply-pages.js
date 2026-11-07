const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const nfs2 = fs.readFileSync(path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/fs/nfsd/nfsxdr.c'), 'utf8');
const nfs3 = fs.readFileSync(path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/fs/nfsd/nfs3xdr.c'), 'utf8');

function functionBody(source, name) {
    const start = source.indexOf(`\n${name}(`);
    assert.notEqual(start, -1, `${name} exists`);
    const open = source.indexOf('{', start);
    let depth = 1;
    for (let index = open + 1; index < source.length; index++) {
        if (source[index] === '{') depth++;
        if (source[index] === '}' && --depth === 0)
            return source.slice(open + 1, index);
    }
    assert.fail(`${name} has a closing brace`);
}

function assertSinglePageGuard(source, name) {
    const body = functionBody(source, name);
    assert.match(body,
        /if \(!rqstp->rq_respages\[rqstp->rq_resused\]\)\s*return 0;[\s\S]*?page_address\(rqstp->rq_respages\[rqstp->rq_resused\+\+\]\)/,
        `${name} checks the reply-page slot before page_address`);
}

function assertLoopPageGuard(source, name) {
    const body = functionBody(source, name);
    assert.match(body,
        /pn = rqstp->rq_resused;\s*if \(!rqstp->rq_respages\[pn\]\)\s*return 0;\s*rqstp->rq_resused\+\+;/,
        `${name} checks every reserved reply-page slot before incrementing rq_resused`);
}

assertSinglePageGuard(nfs2, 'nfssvc_decode_readlinkargs');
assertSinglePageGuard(nfs2, 'nfssvc_decode_readdirargs');
assertLoopPageGuard(nfs3, 'nfs3svc_decode_readargs');
assertSinglePageGuard(nfs3, 'nfs3svc_decode_symlinkargs');
assertSinglePageGuard(nfs3, 'nfs3svc_decode_readlinkargs');
assertSinglePageGuard(nfs3, 'nfs3svc_decode_readdirargs');
assertLoopPageGuard(nfs3, 'nfs3svc_decode_readdirplusargs');

console.log('nfsd reply-page guards: ok');