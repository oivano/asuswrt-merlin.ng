#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const scriptPath = path.join(__dirname, '../../release/src/router/httpd/gencert.sh');
const source = fs.readFileSync(scriptPath, 'utf8');

assert.match(source, /CSR_DIR=\$\(mktemp -d \/tmp\/gencert\.XXXXXX\) \|\| exit 1/);
assert.match(source, /CSR_FILE=\$\{CSR_DIR\}\/https_srv\.csr/);
assert.match(source, /trap cleanup_csr 0/);
assert.match(source, /-batch -out "\$\{CSR_FILE\}" -key \$\{HTTPD_GEN_KEY\}/);
assert.match(source, /-extfile ssl_server\.ext -in "\$\{CSR_FILE\}"/);
assert.doesNotMatch(source, /\/tmp\/https_srv\.csr/);

const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'gencert-csr-test-'));
try {
    const target = path.join(tempRoot, 'sentinel');
    const plantedPath = path.join(tempRoot, 'https_srv.csr');
    fs.writeFileSync(target, 'preserve this target\n');
    fs.symlinkSync(target, plantedPath);

    const setup = source.match(/CSR_DIR=\$\(mktemp -d \/tmp\/gencert\.XXXXXX\) \|\| exit 1[\s\S]*?trap cleanup_csr 0/);
    assert(setup, 'private CSR directory setup and cleanup must be present');
    const isolatedSetup = setup[0].replace('/tmp/gencert.XXXXXX', `${tempRoot}/gencert.XXXXXX`);
    const result = spawnSync('/bin/sh', ['-c', `${isolatedSetup}\nprintf 'generated CSR\\n' > "$CSR_FILE"\ntest -f "$CSR_FILE" && test ! -L "$CSR_FILE" && test "$(cat "$CSR_FILE")" = "generated CSR"`], { encoding: 'utf8' });

    assert.strictEqual(result.status, 0, result.stderr || result.stdout);
    assert.strictEqual(fs.readFileSync(target, 'utf8'), 'preserve this target\n');
    assert(fs.lstatSync(plantedPath).isSymbolicLink());
    assert.deepStrictEqual(fs.readdirSync(tempRoot).sort(), ['https_srv.csr', 'sentinel']);
} finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
}

console.log('gencert CSR symlink regression passed');