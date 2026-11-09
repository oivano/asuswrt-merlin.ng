const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.resolve(__dirname, '../..');
const ministun = fs.readFileSync(path.join(root, 'release/src/router/ministun/ministun.c'), 'utf8');
const getrealipPath = path.join(root, 'release/src/router/rom/apps_scripts/getrealip.sh');
const getrealip = fs.readFileSync(getrealipPath, 'utf8');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');

assert.match(ministun, /open\("\/dev\/urandom",\s*O_RDONLY\)/);
assert.doesNotMatch(ministun, /srandom\s*\(|random\s*\(/);
assert.match(ministun, /src->sin_addr\.s_addr\s*!=\s*dst->sin_addr\.s_addr/);
assert.match(ministun, /src->sin_port\s*!=\s*dst->sin_port/);
assert.match(ministun, /STUN_RESPONSE,\s*STUN_BINDING/);
assert.match(ministun, /memcmp\(&reply->id,\s*&req->id,\s*sizeof\(req->id\)\)/);
assert.match(ministun, /if\s*\(res\s*<=\s*0\s*\|\|\s*!stun_response_matches[\s\S]*?continue;/);
assert.match(ministun, /deadline\.tv_sec[\s\S]*?remaining\s*<=\s*0/);

function responseMatches(request, response, source, server) {
    return source.address === server.address && source.port === server.port &&
        response.type === 0x0101 && response.cookie === request.cookie &&
        response.id === request.id && response.length === response.payloadLength;
}

const request = { cookie: 0x2112a442, id: 'random-96-bit-id' };
const validResponse = {
    type: 0x0101, cookie: request.cookie, id: request.id, length: 8, payloadLength: 8
};
const server = { address: '192.0.2.10', port: 3478 };
assert.strictEqual(responseMatches(request, validResponse, server, server), true);
assert.strictEqual(responseMatches(request, { ...validResponse, id: 'wrong-id' }, server, server), false);
assert.strictEqual(responseMatches(request, { ...validResponse, type: 0x0011 }, server, server), false);
assert.strictEqual(responseMatches(request, validResponse, { address: server.address, port: 3479 }, server), false);

assert.match(getrealip, /is_public_ipv4\s*\(\)/);
assert.strictEqual((getrealip.match(/! is_public_ipv4 \"\$result\"/g) || []).length, 2);
assert.match(services, /upnp_realip_is_public\(ext_ip\)/);
assert.match(services, /if\s*\(upnp_realip_is_public\(ext_ip\)\)\s*fprintf\(f,\s*"ext_ip=/);

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'ministun-validation-'));
const bin = path.join(temp, 'bin');
fs.mkdirSync(bin);
fs.writeFileSync(path.join(bin, 'nvram'), `#!/bin/sh
case "$1" in
get)
  case "$2" in
    wans_mode) echo "$STUN_MODE" ;;
    wan0_primary) echo 1 ;;
    wan0_state_t) echo 2 ;;
    wan0_sbstate_t) echo 0 ;;
    wan0_auxstate_t) echo 0 ;;
    wan0_proto) echo dhcp ;;
    wan0_ifname) echo eth0 ;;
  esac
  ;;
set) printf '%s\\n' "$2" >> "$NVRAM_LOG" ;;
esac
`);
fs.writeFileSync(path.join(bin, 'ministun'), '#!/bin/sh\nprintf "%s\\n" "$STUN_RESULT"\n');
fs.chmodSync(path.join(bin, 'nvram'), 0o755);
fs.chmodSync(path.join(bin, 'ministun'), 0o755);

function runProbe(result, mode = '') {
    const log = path.join(temp, 'nvram.log');
    fs.writeFileSync(log, '');
    const run = spawnSync('/bin/sh', [getrealipPath], {
        encoding: 'utf8',
        env: {
            ...process.env,
            PATH: `${bin}:/usr/bin:/bin`,
            NVRAM_LOG: log,
            STUN_RESULT: result,
            STUN_MODE: mode
        }
    });
    assert.strictEqual(run.status, 0, run.stderr);
    return fs.readFileSync(log, 'utf8');
}

for (const mode of ['', 'lb']) {
    for (const address of [
        '0.0.0.0', '10.1.2.3', '100.64.0.1', '127.0.0.1', '169.254.1.2',
        '172.31.255.1', '192.0.2.1', '192.168.1.1', '198.19.1.1',
        '198.51.100.4', '203.0.113.8', '224.0.0.1', '240.0.0.1', '1.2.3.999', '1.2.3'
    ]) {
        const log = runProbe(address, mode);
        assert.match(log, /wan0_realip_state=1\n/);
        assert.match(log, /wan0_realip_ip=\n$/);
    }
    const publicLog = runProbe('8.8.8.8', mode);
    assert.match(publicLog, /wan0_realip_state=2\n/);
    assert.match(publicLog, /wan0_realip_ip=8\.8\.8\.8\n/);
}

fs.rmSync(temp, { recursive: true, force: true });
console.log('ministun response validation checks passed');