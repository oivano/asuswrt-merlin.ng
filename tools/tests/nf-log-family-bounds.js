#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const NFPROTO_NUMPROTO = 13;
const sourcePath = path.join(
    __dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/nf_log.c'
);
const source = fs.readFileSync(sourcePath, 'utf8');

function functionBody(signature) {
    const start = source.indexOf(signature);
    assert.notStrictEqual(start, -1, `missing function: ${signature}`);
    const opening = source.indexOf('{', start);
    let depth = 1;
    for (let index = opening + 1; index < source.length; index += 1) {
        if (source[index] === '{') depth += 1;
        if (source[index] === '}') depth -= 1;
        if (depth === 0) return source.slice(opening + 1, index);
    }
    assert.fail(`unterminated function: ${signature}`);
}

const bindBody = functionBody('int nf_log_bind_pf(');
const unbindBody = functionBody('void nf_log_unbind_pf(');

assert.match(bindBody, /if\s*\(pf\s*>=\s*NFPROTO_NUMPROTO\)\s*return\s+-EINVAL\s*;/);
assert.match(unbindBody, /if\s*\(pf\s*>=\s*NFPROTO_NUMPROTO\)\s*return\s*;/);

for (const body of [bindBody, unbindBody]) {
    const guard = body.indexOf('pf >= NFPROTO_NUMPROTO');
    const lock = body.indexOf('mutex_lock(&nf_log_mutex)');
    assert(guard !== -1 && lock !== -1 && guard < lock, 'family guard must precede the mutex and indexed access');
}

assert.strictEqual(NFPROTO_NUMPROTO - 1 >= NFPROTO_NUMPROTO, false);
for (const family of [NFPROTO_NUMPROTO, 200, 255]) {
    assert.strictEqual(family >= NFPROTO_NUMPROTO, true);
}

console.log('nf_log family bounds checks passed');