const assert = require('node:assert/strict');
const { spawn, execFileSync } = require('node:child_process');
const fs = require('node:fs');
const https = require('node:https');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/rc/asus_ddns.c'), 'utf8');
const acquire = source.slice(source.indexOf('static int _acquire_token('), source.indexOf('static int _check_response('));
assert.match(acquire, /^static int _acquire_token\(const char \*res_path\)/);
assert.doesNotMatch(source, /check_CA/);
assert.match(source, /ret = _acquire_token\(ASUSDDNS_REQ_TOKEN_RES\);/);
assert.match(acquire, /CURLOPT_PROTOCOLS, CURLPROTO_HTTPS/);
assert.doesNotMatch(acquire, /CURLOPT_FOLLOWLOCATION/);
const caPath = acquire.match(/CURLOPT_CAINFO, "([^"]+)"/)[1];
assert.equal(caPath, '/etc/ssl/certs/ca-certificates.crt');
for (const [option, value] of [['SSL_VERIFYHOST', '2L'], ['SSL_VERIFYPEER', '1L']]) {
    const settings = [...acquire.matchAll(new RegExp(`curl_easy_setopt\\(curl, CURLOPT_${option}, ([^)]+)\\)`, 'g'))];
    assert.equal(settings.length, 1, `${option} must have exactly one setting`);
    assert.equal(settings[0][1], value);
    assert(acquire.indexOf(settings[0][0]) < acquire.indexOf('curl_easy_perform(curl)'));
}
assert(acquire.indexOf('CURLOPT_CAINFO') < acquire.indexOf('curl_easy_perform(curl)'));
const update = source.slice(source.indexOf('int update_asus_ddns_token()'));
assert.match(update, /if\(ret == ASUSDDNS_ERR_SUCCESS\)\s*\{\s*nvram_set_int\("asusddns_token_state", _check_response/);
assert.match(acquire, /ret = ASUSDDNS_ERR_CURL_ERR;\s*unlink\(res_path\);/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'asus-ddns-tls-'));
const credentials = JSON.stringify({ cusid: 'test-cusid', userticket: 'test-ticket' });

function certificate(name, hostname) {
    const key = path.join(temporary, `${name}.key`);
    const cert = path.join(temporary, `${name}.crt`);
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256',
        '-days', '1', '-subj', `/CN=${hostname}`, '-addext', `subjectAltName=DNS:${hostname}`,
        '-keyout', key, '-out', cert], { stdio: 'ignore' });
    return { key: fs.readFileSync(key), cert: fs.readFileSync(cert), ca: cert };
}

async function request(identity, ca, hostname, expectedCode) {
    const posts = [];
    const server = https.createServer(identity, (incoming, response) => {
        let body = '';
        incoming.setEncoding('utf8');
        incoming.on('data', chunk => { body += chunk; });
        incoming.on('end', () => {
            posts.push(body);
            response.setHeader('Connection', 'close');
            response.end('{"status":0,"ddnstoken":"test-token","expiretime":"9999999999"}');
        });
    });
    server.on('tlsClientError', () => {});
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
        const port = server.address().port;
        const result = await new Promise((resolve, reject) => {
            const child = spawn('curl', ['--disable', '--silent', '--show-error', '--noproxy', '*',
                '--proto', '=https', '--cacert', ca, '--resolve', `${hostname}:${port}:127.0.0.1`,
                '--connect-timeout', '3', '--max-time', '5', '--data-binary', credentials,
                `https://${hostname}:${port}/ddnsv2/acquireToken.php`]);
            let stderr = '';
            child.stderr.on('data', chunk => { stderr += chunk; });
            child.stdout.resume();
            child.on('error', reject);
            child.on('close', code => resolve({ code, stderr }));
        });
        assert.equal(result.code, expectedCode, result.stderr);
        assert.deepEqual(posts, expectedCode === 0 ? [credentials] : [],
            'TLS rejection must occur before the credential POST reaches the server');
    } finally {
        await new Promise(resolve => server.close(resolve));
    }
}

async function main() {
    try {
        const valid = certificate('valid', 'ns1.asuscomm.com');
        const wrongHost = certificate('wrong-host', 'not-asus.invalid');
        const untrusted = certificate('untrusted', 'ns1.asuscomm.com');
        await request(valid, valid.ca, 'ns1.asuscomm.com', 0);
        await request(untrusted, valid.ca, 'ns1.asuscomm.com', 60);
        await request(wrongHost, wrongHost.ca, 'ns1.asuscomm.com', 60);
        await request(valid, path.join(temporary, 'missing-ca.crt'), 'ns1.asuscomm.com', 77);
        await request(valid, valid.ca, 'ns1.asuscomm.cn', 60);
        console.log('ASUS DDNS TLS source contracts and local curl handshake checks passed (not firmware execution)');
    } finally {
        fs.rmSync(temporary, { recursive: true, force: true });
    }
}

main().catch(error => {
    console.error(error);
    process.exitCode = 1;
});