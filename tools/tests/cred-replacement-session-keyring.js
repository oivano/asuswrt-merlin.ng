const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const credPath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/kernel/cred.c';
const cred = fs.readFileSync(path.join(root, credPath), 'utf8');

const functionStart = cred.indexOf('int copy_creds(struct task_struct *p, unsigned long clone_flags)');
const functionEnd = cred.indexOf('/**', functionStart);
assert.ok(functionStart >= 0 && functionEnd > functionStart, 'copy_creds() is present');

const copyCreds = cred.slice(functionStart, functionEnd);
const reset = copyCreds.indexOf('p->replacement_session_keyring = NULL;');
const firstReturn = copyCreds.indexOf('return ');
assert.ok(reset >= 0 && firstReturn > reset,
    'new task clears the inherited pending keyring before any early return');
assert.match(copyCreds.slice(0, reset), /#ifdef CONFIG_KEYS\s*$/,
    'pending keyring reset is guarded by CONFIG_KEYS');

console.log('PASS: copy_creds clears the inherited replacement session keyring before returning');