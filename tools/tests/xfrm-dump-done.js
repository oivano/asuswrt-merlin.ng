const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const sourcePath = path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/xfrm/xfrm_user.c');
const source = fs.readFileSync(sourcePath, 'utf8');

function functionBody(name) {
    const signature = source.search(new RegExp(`static int ${name}\\(`));
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

console.log('xfrm dump done checks passed');
