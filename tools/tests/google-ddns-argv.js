const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const updaterPath = path.join(root, 'release/src/router/rom/webs_scripts/GoogleDNS_Update.sh');
const updater = fs.readFileSync(updaterPath, 'utf8');
assert.match(services, /eval\("GoogleDNS_Update\.sh", host, wan_ip\)/);
assert.doesNotMatch(services, /eval\("GoogleDNS_Update\.sh", user, passwd/);
assert.match(updater, /nvram get ddns_username_x/);
assert.match(updater, /nvram get ddns_passwd_x/);
assert.match(updater, /wget --config="\$wget_config"/);
assert.doesNotMatch(updater, /https:\/\/\$[^/]*@domains\.google\.com/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'google-ddns-argv-'));
const bin = path.join(temporary, 'bin');
fs.mkdirSync(bin);
const argsFile = path.join(temporary, 'wget-args');
const configFile = path.join(temporary, 'wget-config');
const modeFile = path.join(temporary, 'wget-mode');
const username = 'google:user@example';
const password = "x# y'!secret";
const shellQuote = value => `'${value.replace(/'/g, "'\\''")}'`;

try {
    fs.writeFileSync(path.join(bin, 'nvram'), `#!/bin/sh
case "$2" in
    ddns_username_x) printf '%s\\n' ${shellQuote(username)} ;;
    ddns_passwd_x) printf '%s\\n' ${shellQuote(password)} ;;
esac
`, { mode: 0o755 });
    fs.writeFileSync(path.join(bin, 'wget'), `#!/bin/sh
printf '%s\\n' "$@" > "$DDNS_TEST_ARGS"
for arg do
    case "$arg" in
        --config=*) config=\${arg#--config=} ;;
    esac
done
[ -n "$config" ] || exit 91
stat -c '%a' "$config" > "$DDNS_TEST_MODE" || exit 92
cat "$config" > "$DDNS_TEST_CONFIG" || exit 93
printf 'good 203.0.113.8\\n'
`, { mode: 0o755 });

    const result = childProcess.spawnSync('/bin/sh', [updaterPath, 'example.test', '203.0.113.8'], {
        encoding: 'utf8',
        env: {
            ...process.env,
            PATH: `${bin}${path.delimiter}${process.env.PATH}`,
            DDNS_TEST_ARGS: argsFile,
            DDNS_TEST_CONFIG: configFile,
            DDNS_TEST_MODE: modeFile
        }
    });
    assert.equal(result.status, 0, result.stderr);

    const args = fs.readFileSync(argsFile, 'utf8');
    assert.match(args, /https:\/\/domains\.google\.com\/nic\/update\?hostname=example\.test&myip=203\.0\.113\.8/);
    assert.doesNotMatch(args, /google:user@example|x# y'!secret/);
    assert.equal(fs.readFileSync(configFile, 'utf8'), `httpuser = ${username}\nhttppassword = ${password}\n`);
    assert.equal(fs.readFileSync(modeFile, 'utf8').trim(), '600');

    const configArg = args.split('\n').find(arg => arg.startsWith('--config='));
    assert.ok(configArg);
    const configPath = configArg.slice('--config='.length);
    assert.equal(fs.existsSync(configPath), false);
    assert.equal(fs.existsSync(path.dirname(configPath)), false);
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}

console.log('google-ddns-argv: credentials stay out of argv and private config is removed');