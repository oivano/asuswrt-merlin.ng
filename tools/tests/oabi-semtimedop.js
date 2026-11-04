const assert = require('assert');
const fs = require('fs');

const kernelRoot = 'release/src-rt-6.x.4708/linux/linux-2.6.36';
const source = fs.readFileSync(
  `${kernelRoot}/arch/arm/kernel/sys_oabi-compat.c`,
  'utf8'
);
const semHeader = fs.readFileSync(`${kernelRoot}/include/linux/sem.h`, 'utf8');
const baseConfig = fs.readFileSync(`${kernelRoot}/config_base.6a`, 'utf8');
const makefile = fs.readFileSync('release/src-rt/Makefile', 'utf8');
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

const noConfigEntry = target.match(/^export DSL-AC68U \+= EXTRA_KERNEL_CONFIGS=(\S+)$/m)?.[1];
assert(noConfigEntry, 'DSL OABI kernel override is present');
assert(
  makefile.includes('EXTRA_KERNEL_NO_CONFIGS := $(subst =n,,$(subst =N,,$(EXTRA_KERNEL_NO_CONFIGS_1)))'),
  'Makefile strips the negative assignment suffix'
);
const extraKernelConfig = makefile.match(/define extraKernelConfig\n([\s\S]*?)\nendef/);
assert(extraKernelConfig, 'extraKernelConfig macro exists');
assert(
  extraKernelConfig[1].includes('sed -i "/CONFIG_$${c}/d" $(1);') &&
    extraKernelConfig[1].includes('echo "# CONFIG_$${c} is not set" >>$(1);'),
  'negative config macro deletes and disables the symbol'
);

const [option, state, ...extraParts] = noConfigEntry.split('=');
assert.strictEqual(state.toLowerCase(), 'n', 'DSL override disables OABI');
assert.deepStrictEqual(extraParts, [], 'DSL override is an unquoted Make option');
const configSymbol = `CONFIG_${option}`;
const generatedConfig = baseConfig
  .split(/\r?\n/)
  .filter((line) => !line.includes(configSymbol))
  .concat(`# ${configSymbol} is not set`)
  .join('\n');
assert(
  /^# CONFIG_OABI_COMPAT is not set$/m.test(generatedConfig),
  'generated kernel config disables OABI_COMPAT'
);
assert(!/^CONFIG_OABI_COMPAT=y$/m.test(generatedConfig), 'generated config has no enabled OABI');
assert(!/^CONFIG_CONFIG_.*$/m.test(generatedConfig), 'generated config has no double-prefixed symbols');

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
