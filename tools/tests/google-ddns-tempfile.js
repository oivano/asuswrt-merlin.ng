const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const scriptPath = path.join(root, 'release/src/router/rom/webs_scripts/GoogleDNS_Update.sh');
const script = fs.readFileSync(scriptPath, 'utf8');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const cacheStart = services.indexOf('#define DDNS_CACHE_DIR');
const cacheEnd = services.indexOf('#endif', cacheStart);
const cache = services.slice(cacheStart, cacheEnd);

assert.doesNotMatch(script, /GDN_RESULT|RESULT_PATH/);
assert.match(script, /result=\$\(wget -S .* -O -\)/);
assert.match(cache, /#define DDNS_CACHE_DIR "\/tmp\/ddns-private"/);
assert.match(cache, /open\(DDNS_CACHE_DIR, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(cache, /st\.st_uid != 0.*st\.st_gid != 0.*fchmod\(fd, 0700\)/s);
assert.match(cache, /openat\(dirfd, "ddns\.cache",\s*O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW/);
assert.match(cache, /S_ISREG\(st\.st_mode\).*st\.st_uid != 0.*st\.st_nlink != 1/s);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'google-ddns-tempfile-'));
try {
    const bin = path.join(temporary, 'bin');
    fs.mkdirSync(bin);
    const victim = path.join(temporary, 'victim');
    const planted = path.join(temporary, 'GDN_RESULT');
    const wgetArgs = path.join(temporary, 'wget-args');
    const commandLog = path.join(temporary, 'commands');
    fs.writeFileSync(victim, 'preserve me');
    fs.symlinkSync(victim, planted);

    const commands = {
        wget: '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$MOCK_WGET_ARGS"\nprintf \'%s\\n\' "$MOCK_WGET_RESPONSE"\nexit "${MOCK_WGET_STATUS:-0}"\n',
        nvram: '#!/bin/sh\nprintf \'nvram %s\\n\' "$*" >> "$MOCK_COMMAND_LOG"\n',
        ddns_updated: '#!/bin/sh\nprintf \'ddns_updated\\n\' >> "$MOCK_COMMAND_LOG"\n',
        sleep: '#!/bin/sh\nexit 0\n'
    };
    for (const [name, content] of Object.entries(commands)) {
        const commandPath = path.join(bin, name);
        fs.writeFileSync(commandPath, content, { mode: 0o700 });
        fs.chmodSync(commandPath, 0o700);
    }

    const runUpdate = (response, expected, wgetStatus = '0') => {
        fs.writeFileSync(commandLog, '');
        const result = spawnSync('/bin/bash', [scriptPath, 'user', 'password', 'host.example', '192.0.2.1'], {
            encoding: 'utf8',
            env: {
                ...process.env,
                PATH: `${bin}${path.delimiter}${process.env.PATH}`,
                MOCK_COMMAND_LOG: commandLog,
                MOCK_WGET_ARGS: wgetArgs,
                MOCK_WGET_RESPONSE: response,
                MOCK_WGET_STATUS: wgetStatus
            }
        });
        assert.ifError(result.error);
        assert.equal(result.status, 0, result.stderr);
        assert.deepEqual(fs.readFileSync(commandLog, 'utf8').trim().split('\n'), expected);
        const args = fs.readFileSync(wgetArgs, 'utf8').trim().split('\n');
        const outputOption = args.indexOf('-O');
        assert.notEqual(outputOption, -1);
        assert.equal(args[outputOption + 1], '-');
        assert.equal(fs.readFileSync(victim, 'utf8'), 'preserve me');
        assert.equal(fs.lstatSync(planted).isSymbolicLink(), true);
    };

    runUpdate('good 192.0.2.1', [
        'nvram set ddns_return_code=200',
        'nvram set ddns_return_code_chk=200',
        'ddns_updated'
    ]);
    runUpdate('nochg 192.0.2.1', [
        'nvram set ddns_return_code=no_change',
        'nvram set ddns_return_code_chk=no_change',
        'ddns_updated'
    ]);
    runUpdate('badauth', [
        'nvram set ddns_return_code=auth_fail',
        'nvram set ddns_return_code_chk=auth_fail'
    ]);
    runUpdate('unexpected response', [
        'nvram set ddns_return_code=unknown_error',
        'nvram set ddns_return_code_chk=unknown_error'
    ], '1');
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}

console.log('google-ddns-tempfile: response capture and private cache checks passed');
