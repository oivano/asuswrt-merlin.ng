const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36');
const xt = fs.readFileSync(path.join(kernel, 'net/netfilter/x_tables.c'), 'utf8');
const ebt = fs.readFileSync(path.join(kernel, 'net/bridge/netfilter/ebtables.c'), 'utf8');
const xtMax = 29;
const ebtMax = 32;

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing ${signature}`);
    const open = source.indexOf('{', start);
    assert(open >= 0, `missing body for ${signature}`);
    let depth = 1;
    for (let i = open + 1; i < source.length; i++) {
        if (source[i] === '{') depth++;
        if (source[i] === '}' && --depth === 0) return source.slice(open + 1, i);
    }
    assert.fail(`unterminated body for ${signature}`);
}

function assertBoundedBefore(body, operation, label) {
    const guard = body.indexOf('strnlen(name, XT_EXTENSION_MAXNAMELEN)');
    assert(guard >= 0, `${label} must bound extension names`);
    const rejection = body.indexOf('return ERR_PTR(-EINVAL);', guard);
    assert(rejection > guard, `${label} must reject unterminated names`);
    const use = body.indexOf(operation);
    assert(use < 0 || rejection < use, `${label} must reject before ${operation}`);
}

for (const [signature, operation] of [
    ['struct xt_match *xt_find_match(', 'strcmp('],
    ['xt_request_find_match(uint8_t', 'try_then_request_module('],
    ['struct xt_target *xt_find_target(', 'strcmp('],
    ['struct xt_target *xt_request_find_target(', 'try_then_request_module('],
]) {
    assertBoundedBefore(functionBody(xt, signature), operation, signature);
}

const revision = functionBody(xt, 'int xt_find_revision(');
const revisionGuard = revision.indexOf('strnlen(name, XT_EXTENSION_MAXNAMELEN)');
assert(revisionGuard >= 0, 'revision lookup must bound extension names');
assert(revision.indexOf('*err = -EINVAL;', revisionGuard) > revisionGuard);
assert(revision.indexOf('mutex_lock_interruptible', revisionGuard) > revisionGuard);
assert(revision.indexOf('strcmp(', revisionGuard) < 0 ||
    revision.indexOf('strcmp(', revisionGuard) > revision.indexOf('mutex_lock_interruptible', revisionGuard));

function assertTableNameTerminated(signature, variable) {
    const body = functionBody(ebt, signature);
    const pattern = new RegExp(
        `if\\s*\\(\\s*copy_from_user\\(\\s*&${variable},\\s*user,\\s*sizeof\\(${variable}\\)\\s*\\)\\s*(?:!=\\s*0)?\\s*\\)\\s*return\\s+-EFAULT;\\s*${variable}\\.name\\[EBT_TABLE_MAXNAMELEN\\s*-\\s*1\\]\\s*=\\s*'\\\\0';`);
    assert.match(body, pattern, `${signature} must terminate copied table name`);
}

for (const [signature, variable] of [
    ['static int do_replace(', 'tmp'],
    ['static int update_counters(', 'hlp'],
    ['static int do_ebt_get_ctl(', 'tmp'],
    ['static int compat_copy_ebt_replace_from_user(', 'tmp'],
    ['static int compat_update_counters(', 'hlp'],
    ['static int compat_do_ebt_get_ctl(', 'tmp'],
]) {
    assertTableNameTerminated(signature, variable);
}

function hasTerminator(bytes, limit) {
    return bytes.slice(0, limit).includes(0);
}

assert.equal(xtMax, 29);
assert.equal(ebtMax, 32);
assert.equal(hasTerminator([...Buffer.alloc(28, 0x41), 0], xtMax), true);
assert.equal(hasTerminator(Buffer.alloc(xtMax, 0x41), xtMax), false);
assert.equal(hasTerminator(Buffer.alloc(ebtMax, 0x41), ebtMax), false);

console.log('xt-extension-name-bounds: ok');