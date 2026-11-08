const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const sourcePath = path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/xfrm/xfrm_user.c');
const source = fs.readFileSync(sourcePath, 'utf8');

function functionBody(name) {
    const signature = source.search(new RegExp(`static (?:int|void) ${name}\\(`));
    assert.notStrictEqual(signature, -1, `missing ${name}`);
    const open = source.indexOf('{', signature);
    let depth = 0;
    for (let index = open; index < source.length; index++) {
        if (source[index] === '{') depth++;
        if (source[index] === '}' && --depth === 0)
            return source.slice(open + 1, index);
    }
    throw new Error(`unterminated ${name}`);
}

for (const [doneName, walkDone, dumpName, walkInit] of [
    ['xfrm_dump_sa_done', 'xfrm_state_walk_done',
        'xfrm_dump_sa', 'xfrm_state_walk_init'],
    ['xfrm_dump_policy_done', 'xfrm_policy_walk_done',
        'xfrm_dump_policy', 'xfrm_policy_walk_init'],
]) {
    const done = functionBody(doneName);
    assert.match(done,
        new RegExp(`if \\(cb->args\\[0\\]\\)\\s*${walkDone}\\(walk\\);`),
        `${doneName} must skip teardown until its dump walk has started`);

    const dump = functionBody(dumpName);
    const started = dump.indexOf('cb->args[0] = 1;');
    const initialized = dump.indexOf(`${walkInit}(walk`);
    assert(started !== -1 && initialized !== -1 && started < initialized,
        `${dumpName} must mark the walk started before initializing it`);
}

const attachAuth = functionBody('attach_auth');
assert.match(attachAuth,
    /p = kzalloc\(sizeof\(\*p\) \+ \(ualg->alg_key_len \+ 7\) \/ 8, GFP_KERNEL\);/,
    'stored auth algorithm names must have zero-filled tails');

const copyAuth = functionBody('copy_to_user_auth');
assert.match(copyAuth,
    /memset\(algo->alg_name, 0, sizeof\(algo->alg_name\)\);\s*strlcpy\(algo->alg_name, auth->alg_name, sizeof\(algo->alg_name\)\);/,
    'reply algorithm names must be bounded and zero-padded');

const copyState = functionBody('copy_to_user_state');
assert.match(copyState, /memset\(p, 0, sizeof\(\*p\)\);\s*memcpy\(&p->id,/,
    'SA reply padding must be initialized before fields are copied');

const copyPolicy = functionBody('copy_to_user_policy');
assert.match(copyPolicy, /memset\(p, 0, sizeof\(\*p\)\);\s*memcpy\(&p->sel,/,
    'policy reply padding must be initialized before fields are copied');

const copyTemplates = functionBody('copy_to_user_tmpl');
assert.match(copyTemplates,
    /memset\(vec, 0, sizeof\(vec\)\);\s*for \(i = 0; i < xp->xfrm_nr; i\+\+\)/,
    'template reply padding must be initialized before fields are copied');

console.log('xfrm dump and reply checks passed');
