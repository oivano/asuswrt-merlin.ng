const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const linux = 'release/src-rt-6.x.4708/linux/linux-2.6.36';
const elf = fs.readFileSync(path.join(root, linux, 'fs/binfmt_elf.c'), 'utf8');
const exec = fs.readFileSync(path.join(root, linux, 'fs/exec.c'), 'utf8');
const cred = fs.readFileSync(path.join(root, linux, 'kernel/cred.c'), 'utf8');
const proc = fs.readFileSync(path.join(root, linux, 'fs/proc/base.c'), 'utf8');

const loadSignature = 'static int load_elf_binary(struct linux_binprm *bprm, struct pt_regs *regs)';
const loadStart = elf.indexOf(loadSignature, elf.indexOf(loadSignature) + 1);
const loadEnd = elf.indexOf('/* This is really simpleminded', loadStart);
assert.ok(loadStart >= 0 && loadEnd > loadStart, 'load_elf_binary() is present');
const load = elf.slice(loadStart, loadEnd);
const setupExec = load.indexOf('setup_new_exec(bprm);');
const installCreds = load.indexOf('install_exec_creds(bprm);');
const setupStack = load.indexOf('setup_arg_pages(');
const mapElf = load.indexOf('elf_map(');
const mapInterp = load.indexOf('load_elf_interp(');

assert.ok(setupExec >= 0 && installCreds > setupExec,
    'ELF credentials are installed after the point of no return');
assert.ok(installCreds < setupStack && installCreds < mapElf && installCreds < mapInterp,
    'ELF credentials are installed before stack and image layout publication');
assert.equal((load.match(/install_exec_creds\(bprm\);/g) || []).length, 1,
    'load_elf_binary() installs credentials exactly once');

const commitStart = cred.indexOf('int commit_creds(struct cred *new)');
const commitEnd = cred.indexOf('EXPORT_SYMBOL(commit_creds);', commitStart);
assert.ok(commitStart >= 0 && commitEnd > commitStart, 'commit_creds() is present');
const commit = cred.slice(commitStart, commitEnd);
assert.ok(commit.indexOf('set_dumpable(task->mm, suid_dumpable);') >= 0 &&
    commit.indexOf('set_dumpable(task->mm, suid_dumpable);') < commit.indexOf('rcu_assign_pointer(task->real_cred, new);'),
    'dumpability is restricted before new credentials are published');

const installStart = exec.indexOf('void install_exec_creds(struct linux_binprm *bprm)');
const installEnd = exec.indexOf('EXPORT_SYMBOL(install_exec_creds);', installStart);
const freeStart = exec.indexOf('void free_bprm(struct linux_binprm *bprm)');
const freeEnd = exec.indexOf('/*\n * install the new credentials', freeStart);
assert.ok(installStart >= 0 && installEnd > installStart && freeStart >= 0 && freeEnd > freeStart,
    'exec credential cleanup functions are present');
const install = exec.slice(installStart, installEnd);
const freeBprm = exec.slice(freeStart, freeEnd);
assert.ok(install.indexOf('bprm->cred = NULL;') < install.indexOf('mutex_unlock(&current->cred_guard_mutex);'),
    'credential ownership is cleared before install_exec_creds() unlocks');
assert.match(freeBprm, /if \(bprm->cred\)\s*\{[\s\S]*?mutex_unlock\(&current->cred_guard_mutex\);/,
    'free_bprm() only unlocks while it still owns uncommitted credentials');

const auxvStart = proc.indexOf('static int proc_pid_auxv(struct task_struct *task, char *buffer)');
const auxvEnd = proc.indexOf('#ifdef CONFIG_KALLSYMS', auxvStart);
assert.ok(auxvStart >= 0 && auxvEnd > auxvStart, 'proc_pid_auxv() is present');
const auxv = proc.slice(auxvStart, auxvEnd);
assert.ok(auxv.indexOf('mutex_lock_killable(&task->cred_guard_mutex)') <
    auxv.indexOf('get_task_mm(task)') &&
    auxv.indexOf('ptrace_may_access(task, PTRACE_MODE_READ)') < auxv.indexOf('memcpy(buffer, mm->saved_auxv, res);'),
    'auxv reads synchronize with exec and recheck access on every read');

console.log('PASS: ELF credentials precede layout publication; auxv reads recheck access');