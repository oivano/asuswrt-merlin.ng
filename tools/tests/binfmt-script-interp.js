const assert = require('assert');
const fs = require('fs');
const path = require('path');

const kernel = path.join(__dirname, '../../release/src-rt-6.x.4708/linux/linux-2.6.36');
const exec = fs.readFileSync(path.join(kernel, 'fs/exec.c'), 'utf8');
const script = fs.readFileSync(path.join(kernel, 'fs/binfmt_script.c'), 'utf8');
const misc = fs.readFileSync(path.join(kernel, 'fs/binfmt_misc.c'), 'utf8');
const header = fs.readFileSync(path.join(kernel, 'include/linux/binfmts.h'), 'utf8');

assert.match(header, /extern int bprm_change_interp\(char \*interp, struct linux_binprm \*bprm\);/);
assert.match(exec, /if \(bprm->interp != bprm->filename\)\s*kfree\(bprm->interp\);\s*kfree\(bprm\);/);
assert.match(exec, /int bprm_change_interp\(char \*interp, struct linux_binprm \*bprm\)[\s\S]*?char \*new_interp = kstrdup\(interp, GFP_KERNEL\);[\s\S]*?if \(!new_interp\)\s*return -ENOMEM;[\s\S]*?if \(bprm->interp != bprm->filename\)\s*kfree\(bprm->interp\);[\s\S]*?bprm->interp = new_interp;/);
assert.match(exec, /EXPORT_SYMBOL\(bprm_change_interp\);/);
assert.match(script, /bprm_change_interp\(interp, bprm\)/);
assert.match(misc, /bprm_change_interp\(iname, bprm\)/);
assert.doesNotMatch(script, /bprm->interp\s*=\s*interp/);
assert.doesNotMatch(misc, /bprm->interp\s*=\s*iname/);

console.log('binfmt interpreter ownership checks passed');