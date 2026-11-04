const assert = require('assert');
const fs = require('fs');

const kernelRoot = 'release/src-rt-6.x.4708/linux/linux-2.6.36';
const source = fs.readFileSync(
  `${kernelRoot}/arch/arm/kernel/sys_oabi-compat.c`,
  'utf8'
);
const semHeader = fs.readFileSync(`${kernelRoot}/include/linux/sem.h`, 'utf8');
const target = fs.readFileSync('release/src-rt/target.mak', 'utf8');

const functionStart = source.indexOf('asmlinkage long sys_oabi_semtimedop(');
const functionEnd = source.indexOf('\nasmlinkage long sys_oabi_semop(', functionStart);
assert(functionStart >= 0 && functionEnd > functionStart, 'semtimedop wrapper exists');

const wrapper = source.slice(functionStart, functionEnd);
const maxOps = Number(semHeader.match(/^#define SEMOPM\s+(\d+)/m)?.[1]);
assert(Number.isInteger(maxOps) && maxOps > 0, 'SEMOPM is defined');

const boundCheck = wrapper.indexOf('nsops < 1 || nsops > SEMOPM');
const allocation = wrapper.indexOf('kmalloc(sizeof(*sops) * nsops');
assert(boundCheck >= 0 && allocation > boundCheck, 'count is bounded before allocation');
assert(target.includes('EXTRA_KERNEL_CONFIGS="CONFIG_OABI_COMPAT=n"'), 'DSL disables OABI');

const readFailure = wrapper.indexOf('if (__get_user(sops[i].sem_num');
const stopOnFault = wrapper.indexOf('break;', readFailure);
const advanceUserBuffer = wrapper.indexOf('tsops++;', readFailure);
assert(readFailure >= 0 && stopOnFault > readFailure, 'copy stops on a user-read fault');
assert(advanceUserBuffer > stopOnFault, 'buffer advances only after successful reads');

const rejects = (count) => count < 1 || count > maxOps;
for (const [count, expected] of [
  [0, true],
  [1, false],
  [maxOps, false],
  [maxOps + 1, true],
  [0x2aaaaaab, true]
]) {
  assert.strictEqual(rejects(count), expected, `nsops=${count}`);
}

console.log('OABI semtimedop source contracts passed');
