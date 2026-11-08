const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const sourcePath = path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/fs/eventpoll.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const fsHeader = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/include/linux/fs.h'), 'utf8');

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

assert.match(source, /#define EP_MAX_NESTS 4/);
assert.match(source, /ep_path_limits\[EP_PATH_ARR_SIZE\].*1000, 500, 100, 50, 10/s);
assert.match(source, /struct ep_loop_check_data[\s\S]*struct rb_root files;/);
assert.match(source, /static struct nested_calls poll_loop_ncalls;/);
const init = source.slice(source.indexOf('static int __init eventpoll_init'));
assert.match(init, /ep_nested_calls_init\(&poll_loop_ncalls\);/);
assert.match(source, /ep->file = file;/);
assert.doesNotMatch(source, /f_tfile_llink/,
    'file layout must not gain a check-list link');
assert.doesNotMatch(fsHeader, /f_tfile_llink/);

const loopCheck = functionBody('ep_loop_check_proc');
assert.match(loopCheck, /ep == data->target \|\| depth > EP_MAX_NESTS/);
assert.match(functionBody('ep_loop_check'), /ancestor_depth \+ 1 \+ data->max_depth >\s*EP_MAX_NESTS/);
assert.match(functionBody('ep_reverse_path_check'), /ep_call_nested/);
assert.match(functionBody('ep_path_count_inc'), /ep_path_limits\[nests\]/);
assert.match(functionBody('ep_loop_check_clear'), /visited = 0/);
assert.match(functionBody('ep_loop_check_clear'), /list_del_init/);

const insert = functionBody('ep_insert');
assert.match(insert, /if \(ep_reverse_path_check\(check\)\)\s*goto error_remove_epi/);
assert.match(insert, /error_remove_epi:[\s\S]*list_del_init\(&epi->fllink\)[\s\S]*rb_erase\(&epi->rbn/);

const ctlStart = source.indexOf('SYSCALL_DEFINE4(epoll_ctl');
const ctlEnd = source.indexOf('SYSCALL_DEFINE4(epoll_wait', ctlStart);
assert.notStrictEqual(ctlStart, -1, 'missing epoll_ctl syscall');
assert.notStrictEqual(ctlEnd, -1, 'missing epoll_wait syscall');
const ctl = source.slice(ctlStart, ctlEnd);
assert(ctl.indexOf('mutex_lock(&epmutex)') < ctl.indexOf('ep_loop_check(ep, tfile'));
assert(ctl.indexOf('ep_loop_check(ep, tfile') < ctl.indexOf('ep_insert(ep, &epds, tfile, fd, &check)'));
assert.match(ctl, /ep_loop_check_cleanup\(&check\)[\s\S]*mutex_unlock\(&epmutex\)/);

function canAdd(graph, parent, target, maxDepth = 4) {
    const reverse = new Map();
    for (const [node, children] of Object.entries(graph)) {
        for (const child of children)
            reverse.set(child, [...(reverse.get(child) || []), node]);
    }
    let ancestorDepth = 0;
    const ancestorQueue = [[parent, 0]];
    const bestAncestor = new Map();
    while (ancestorQueue.length) {
        const [node, depth] = ancestorQueue.shift();
        if ((bestAncestor.get(node) ?? -1) >= depth) continue;
        bestAncestor.set(node, depth);
        ancestorDepth = Math.max(ancestorDepth, depth);
        if (depth > maxDepth) return false;
        for (const outer of reverse.get(node) || [])
            ancestorQueue.push([outer, depth + 1]);
    }
    let descendantDepth = 0;
    const queue = [[target, 0]];
    const bestDescendant = new Map();
    while (queue.length) {
        const [node, depth] = queue.shift();
        if (node === parent || depth > maxDepth) return false;
        if ((bestDescendant.get(node) ?? -1) >= depth) continue;
        bestDescendant.set(node, depth);
        descendantDepth = Math.max(descendantDepth, depth);
        for (const child of graph[node] || [])
            queue.push([child, depth + 1]);
    }
    return ancestorDepth + 1 + descendantDepth <= maxDepth;
}

assert.strictEqual(canAdd({ e2: ['e1'], e1: [] }, 'e1', 'e2'), false,
    'reported e2 -> e1; e1 -> e2 cycle must be rejected');
assert.strictEqual(canAdd({ a: ['b'] }, 'a', 'c'), true,
    'acyclic nesting within the limit must remain valid');
assert.strictEqual(canAdd({ a: ['b'], b: ['c'], c: ['d'] }, 'd', 'e'), true,
    'four nested epoll edges must remain valid');
assert.strictEqual(canAdd({ a: ['b'], b: ['c'], c: ['d'], d: ['e'] }, 'e', 'f'), false,
    'a fifth nested epoll edge must be rejected');

console.log('epoll nesting checks passed');