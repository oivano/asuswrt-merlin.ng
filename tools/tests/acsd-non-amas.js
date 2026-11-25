const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const symbols = file => execFileSync('readelf', ['-Ws', path.join(root, file)], { encoding: 'utf8' });

const shared = read('release/src/router/shared/misc.c');
const makefile = read('release/src/router/shared/Makefile');
const target = read('release/src-rt/target.mak');
const daemonSymbols = symbols('release/src/router/acsd_arm/prebuilt/acsd');
const providerSymbols = symbols('release/src/router/shared/prebuild/DSL-AC68U/amas_utils.o');

assert.match(daemonSymbols, /\bFUNC\s+GLOBAL\s+DEFAULT\s+UND\s+acsd_amasinfo\b/);
assert.match(providerSymbols, /\bFUNC\s+GLOBAL\s+DEFAULT\s+\d+\s+acsd_amasinfo\b/);
assert.match(makefile, /OBJS\s*\+=\s*misc\.o\b/);
assert.match(target, /export RT-AC68U_BASE\s*:=[\s\S]*?\bBCMWL6=y\b/);
assert.match(target, /DSL-AC68U-NONE\s*:=[\s\S]*?\bAMAS=y\b/);
assert.match(target, /export DSL-AC68U\s*:=\s*\$\(filter-out\s+\$\(DSL-AC68U-NONE\),\$\(RT-AC68U_BASE\)\)/);
assert.match(shared, /#if defined\(RTCONFIG_BCMWL6\) && !defined\(RTCONFIG_AMAS\)\s+void acsd_amasinfo\(const char \*ifname, unsigned short chanspec\)\s*\{\s*\(void\)ifname;\s*\(void\)chanspec;\s*\}\s*#endif/);

console.log('acsd non-AMAS compatibility source and binary contracts passed');