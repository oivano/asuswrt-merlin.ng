const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const helperPath = path.join(root, 'release/src/router/others/chpasswd.sh');
const helper = fs.readFileSync(helperPath, 'utf8');

assert.match(helper, /printf\s+'%s\\n'\s+"\$1:\$2"\s*\|\s*chpasswd/);
assert.doesNotMatch(helper, /\/tmp\/tmpchpw/);

const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'chpasswd-pipe-'));
try {
    const binDirectory = path.join(temporaryDirectory, 'bin');
    fs.mkdirSync(binDirectory);
    const capturedInput = path.join(temporaryDirectory, 'input');
    const stub = path.join(binDirectory, 'chpasswd');
    fs.writeFileSync(stub, '#!/bin/sh\ncat > "$CAPTURED_INPUT"\n', { mode: 0o700 });

    const plantedPath = path.join(temporaryDirectory, 'tmpchpw');
    fs.writeFileSync(plantedPath, 'attacker-controlled sentinel\n');
    const result = spawnSync('/bin/sh', [helperPath, 'admin', 'new password'], {
        encoding: 'utf8',
        env: {
            ...process.env,
            PATH: `${binDirectory}:${process.env.PATH}`,
            CAPTURED_INPUT: capturedInput
        }
    });
    assert.ifError(result.error);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.readFileSync(capturedInput, 'utf8'), 'admin:new password\n');
    assert.equal(fs.readFileSync(plantedPath, 'utf8'), 'attacker-controlled sentinel\n');
    console.log('PASS: chpasswd receives credentials via stdin without touching a planted path');
} finally {
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
}
