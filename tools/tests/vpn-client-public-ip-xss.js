const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const tunnelScript = read('release/src/router/rom/apps_scripts/gettunnelip.sh');
const webSource = read('release/src/router/httpd/web.c');
const ajaxSource = read('release/src/router/www/ajax_vpn_status.asp');
const clientPage = read('release/src/router/www/Advanced_OpenVPNClient_Content.asp');
const statusPage = read('release/src/router/www/Advanced_VPNStatus.asp');

assert.match(tunnelScript, /https:\/\/\$server/);
assert.doesNotMatch(tunnelScript, /--insecure|--disable-epsv|curl[^\n]*\s-k(?:\s|$)/);
assert.match(tunnelScript, /nvram set "vpn_client\$\{INSTANCE\}_rip=\$result"/);
assert.match(webSource, /if\(escape_backslash \|\| from_app != 0\)/);
assert.match(webSource, /\{ "nvram_get_js", ej_nvram_get_js\}/);
assert.equal((ajaxSource.match(/nvram_get_js\("vpn_client[1-5]_rip"\)/g) || []).length, 5);
assert.match(clientPage, /htmlEnDeCode\.htmlEncode\(remoteip\)/);
assert.match(statusPage, /htmlEnDeCode\.htmlEncode\(ripaddress\)/);

const ipv4Function = tunnelScript.match(/is_ipv4\(\) \{[^]*?\n\}/);
assert(ipv4Function, 'IPv4 validator exists');
const validate = value => childProcess.spawnSync('/bin/sh', ['-c', `${ipv4Function[0]}\nis_ipv4 "$1"`, 'sh', value]).status === 0;
for (const value of ['203.0.113.9', '0.0.0.0', '255.255.255.255'])
    assert.equal(validate(value), true, `${value} is accepted`);
for (const value of ['', '256.0.0.1', '1.2.3', '01.2.3.4', '1.2.3.4\n5.6.7.8', '\\x3cimg\\x20src=x\\x20onerror=alert(1)\\x3e'])
    assert.equal(validate(value), false, `${JSON.stringify(value)} is rejected`);

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vpn-public-ip-'));
try {
    const binDir = path.join(tempDir, 'bin');
    fs.mkdirSync(binDir);
    const curlPath = path.join(tempDir, 'curl');
    const scriptPath = path.join(tempDir, 'gettunnelip.sh');
    const capturePath = path.join(tempDir, 'nvram-args');
    fs.writeFileSync(curlPath, '#!/bin/sh\nprintf "%s\\n" "$@" >> "$CURL_ARGS"\nprintf "%s\\n" "$CURL_RESPONSE"\n');
    fs.chmodSync(curlPath, 0o755);
    fs.writeFileSync(path.join(binDir, 'nvram'), '#!/bin/sh\nprintf "%s\\n" "$#" "$1" "$2" > "$NVRAM_ARGS"\n');
    fs.chmodSync(path.join(binDir, 'nvram'), 0o755);
    fs.writeFileSync(scriptPath, tunnelScript.replace('/usr/sbin/curl', curlPath));

    const run = response => {
        fs.writeFileSync(path.join(tempDir, 'curl-args'), '');
        childProcess.execFileSync('/bin/sh', [scriptPath, '1', 'openvpn', 'http'], {
            env: {
                ...process.env,
                PATH: `${binDir}:/usr/bin:/bin`,
                CURL_ARGS: path.join(tempDir, 'curl-args'),
                CURL_RESPONSE: response,
                NVRAM_ARGS: capturePath
            }
        });
        return {
            curlArgs: fs.readFileSync(path.join(tempDir, 'curl-args'), 'utf8').trim().split('\n'),
            nvramArgs: fs.readFileSync(capturePath, 'utf8').trim().split('\n')
        };
    };

    const malicious = run('\\x3cimg\\x20src=x\\x20onerror=alert(1)\\x3e');
    assert(malicious.curlArgs.includes('https://api.ipify.org'));
    assert.deepEqual(malicious.nvramArgs, ['2', 'set', 'vpn_client1_rip=unknown']);
    assert.deepEqual(run('203.0.113.9').nvramArgs, ['2', 'set', 'vpn_client1_rip=203.0.113.9']);
} finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
}

console.log('PASS: tunnel public-IP fetch requires HTTPS and valid IPv4, NVRAM receives one safe value, JS backslashes are escaped, and both HTML sinks encode the decoded value (script/model checks; not compiled C or browser/hardware validation)');