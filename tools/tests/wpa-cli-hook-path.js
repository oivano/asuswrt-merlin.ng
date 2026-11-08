const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const install = read('release/src/router/rc/Makefile');
const auth = read('release/src/router/rc/auth.c');
const wan = read('release/src/router/rc/wan.c');
const hook = '/usr/libexec/rc-hooks/wpa_cli';

assert.match(install, /install -d -m 0755 \$\(INSTALLDIR\)\/usr\/libexec\/rc-hooks/);
assert.match(install, /ln -sf \/sbin\/rc \$\(INSTALLDIR\)\/usr\/libexec\/rc-hooks\/wpa_cli/);
assert.ok(auth.includes(`"-a", "${hook}"`), 'wpa_cli uses the installed rc hook');
assert.doesNotMatch(auth, /\/tmp\/wpa_cli/);
assert.doesNotMatch(wan, /\/tmp\/wpa_cli/);

console.log('PASS: wpa_cli action hook is installed in root-controlled rc-hooks, not /tmp');
