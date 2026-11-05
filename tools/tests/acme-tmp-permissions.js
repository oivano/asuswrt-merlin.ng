const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const common = read('release/src/router/rc/common.c');
const init = read('release/src/router/rc/init.c');
const acme = read('release/src/router/acme.sh/acme.sh');
const hook = read('release/src/router/acme.sh/dnsapi/dns_asusapi.sh');
const clients = [
    read('release/src/router/inadyn/plugins/asuscomm.c'),
    read('release/src/router/inadyn/plugins/asuscommv2.c')
];
const extractFunction = name => {
    const match = acme.match(new RegExp(`^${name}\\(\\) \\{[\\s\\S]*?^\\}`, 'm'));
    assert.ok(match, `${name} function exists`);
    return match[0];
};
const base64urlValidator = extractFunction('_is_base64url');
const httpsUrlValidator = extractFunction('_is_safe_https_url');
const startserver = extractFunction('_startserver');
const stopserver = extractFunction('_stopserver');

const prepare = common.slice(common.indexOf('static int le_status_fd_secure'), common.indexOf('int le_fw_script_is_safe'));
const wrapper = common.slice(common.indexOf('int le_acme_main_safe'), common.indexOf('#endif', common.indexOf('int le_acme_main_safe')));
assert.match(prepare, /O_WRONLY \| O_NOFOLLOW \| O_NONBLOCK/);
assert.match(prepare, /O_CREAT \| O_EXCL \| O_NOFOLLOW/);
assert.match(prepare, /st\.st_uid != 0/);
assert.match(prepare, /st\.st_nlink != 1/);
assert.match(prepare, /fchmod\(fd, 0600\)/);
assert.match(prepare, /fchmod\(fd, 0700\)/);
assert.match(prepare, /le_status_file_prepare\("\/tmp\/acme_err"\)/);
assert.ok(wrapper.indexOf('le_workdir_prepare()') < wrapper.indexOf('le_acme_main(argc, argv)'));
assert.ok(init.indexOf('le_workdir_prepare()') < init.indexOf('start_services();'));
assert.match(acme, /echo -n "\$errordetail" > \/tmp\/acme_err/);
assert.match(startserver, /_response_file="\/tmp\/\.le\/acme-http-\$\$"/);
assert.match(startserver, /set -C; : >"\$_response_file"/);
assert.match(startserver, /SYSTEM:"sleep 1; cat \$_response_file"/);
assert.doesNotMatch(startserver, /SYSTEM:[^\n]*\$content/);
assert.doesNotMatch(startserver, /printf -- '\$content'/);
assert.match(stopserver, /rm -f "\$_response_file"/);
assert.ok(acme.indexOf('if ! _is_base64url "$token";') < acme.indexOf('keyauthorization="$token.$thumbprint"'));
assert.ok(acme.indexOf('if ! _is_safe_https_url "$Le_OrderFinalize";') < acme.indexOf('_savedomainconf "Le_OrderFinalize"'));
assert.ok(acme.indexOf('if [ "$Le_LinkOrder" ] && ! _is_safe_https_url "$Le_LinkOrder";') < acme.indexOf('_savedomainconf "Le_LinkOrder"'));
assert.ok(acme.indexOf('if ! _is_safe_https_url "$Le_LinkCert";') < acme.indexOf('if ! _send_signed_request "$Le_LinkCert";'));
assert.ok(acme.indexOf('if ! _is_safe_https_url "$uri";') < acme.indexOf('_savedomainconf "Le_Vlist"'));
assert.ok(acme.indexOf('if ! _is_safe_https_url "$Le_LinkIssuer";') < acme.indexOf('_savedomainconf "Le_LinkIssuer"'));
assert.match(hook, /echo -n "\$txtvalue" > \/tmp\/\.le\/acme\.txt/);
assert.doesNotMatch(hook, /\/tmp\/acme\.txt/);
for (const client of clients)
    assert.match(client, /open\("\/tmp\/\.le\/acme\.txt", O_RDONLY\)/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'acme-tmp-permissions-'));
let responseFile;
try {
    const victim = path.join(temporary, 'victim');
    const status = path.join(temporary, 'acme_err');
    fs.writeFileSync(victim, 'preserve me');
    fs.symlinkSync(victim, status);

    let descriptor;
    try {
        descriptor = fs.openSync(status, fs.constants.O_WRONLY |
            fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    } catch (error) {
        assert.ok(['ELOOP', 'ENOENT'].includes(error.code));
    }
    if (descriptor !== undefined)
        fs.closeSync(descriptor);
    fs.unlinkSync(status);
    descriptor = fs.openSync(status, fs.constants.O_WRONLY | fs.constants.O_CREAT |
        fs.constants.O_EXCL | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
    fs.closeSync(descriptor);
    assert.equal(fs.readFileSync(victim, 'utf8'), 'preserve me');
    assert.equal(fs.lstatSync(status).isFile(), true);

    const marker = path.join(temporary, 'pwned');
    const maliciousTokens = [
        `x;touch$IFS${marker};x`,
        `';touch ${marker};'`
    ];
    const maliciousUrl = `https://acme.example/order/' ; touch ${marker};#`;
    const shellQuote = value => `'${value.replace(/'/g, `'"'"'`)}'`;
    const validationScript = [
        base64urlValidator,
        httpsUrlValidator,
        `_is_base64url ${shellQuote('AbC_09-')} || exit 1`,
        ...maliciousTokens.map(value => `if _is_base64url ${shellQuote(value)}; then exit 2; fi`),
        `_is_safe_https_url ${shellQuote('https://acme-v02.api.letsencrypt.org/acme/order/123/456')} || exit 3`,
        `if _is_safe_https_url ${shellQuote(maliciousUrl)}; then exit 4; fi`,
        `if _is_safe_https_url ${shellQuote('http://acme.example/order/123')}; then exit 5; fi`
    ].join('\n');
    let result = spawnSync('/bin/sh', ['-c', validationScript], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(fs.existsSync(marker), false);

    const socatCapture = path.join(temporary, 'socat-args');
    const responsePath = path.join(temporary, 'response-path');
    const sandboxStartserver = startserver.replace('/tmp/.le/acme-http-', `${temporary}/acme-http-`);
    const serverScript = [
        base64urlValidator,
        sandboxStartserver,
        stopserver,
        '_debug() { :; }',
        '_err() { :; }',
        'socat() { printf "%s\\n" "$@" >"$ACME_TEST_CAPTURE"; }',
        'Le_HTTPPort=80',
        `_startserver ${shellQuote('safe-token.thumbprint')} '' || exit 10`,
        'wait "$serverproc" || exit 11',
        'printf "%s" "$_response_file" >"$ACME_TEST_RESPONSE_PATH"',
        ...maliciousTokens.map(value => `if _startserver ${shellQuote(value)} ''; then exit 12; fi`)
    ].join('\n');
    result = spawnSync('/bin/sh', ['-c', serverScript], {
        encoding: 'utf8',
        env: { ...process.env, ACME_TEST_CAPTURE: socatCapture, ACME_TEST_RESPONSE_PATH: responsePath }
    });
    assert.equal(result.status, 0, result.stderr);
    responseFile = fs.readFileSync(responsePath, 'utf8');
    const generatedResponseFile = responseFile;
    const socatArgs = fs.readFileSync(socatCapture, 'utf8').trimEnd().split('\n');
    const challenge = 'safe-token.thumbprint';
    assert.ok(socatArgs.includes(`SYSTEM:sleep 1; cat ${generatedResponseFile}`));
    assert.equal(socatArgs.some(argument => argument.includes(challenge)), false);
    assert.equal(fs.statSync(generatedResponseFile).mode & 0o777, 0o600);
    assert.equal(fs.readFileSync(generatedResponseFile, 'utf8'),
        `HTTP/1.0 200 OK\r\nContent-Length: ${Buffer.byteLength(challenge)}\r\n\r\n${challenge}`);
    fs.rmSync(generatedResponseFile, { force: true });
    responseFile = undefined;
    assert.equal(fs.existsSync(generatedResponseFile), false);
    assert.equal(fs.existsSync(marker), false);

    fs.writeFileSync(status, 'existing error');
    assert.equal(fs.readFileSync(status, 'utf8'), 'existing error');
} finally {
    if (responseFile)
        fs.rmSync(responseFile, { force: true });
    fs.rmSync(temporary, { recursive: true, force: true });
}

console.log('acme-tmp-permissions: source contracts and planted-symlink check passed');