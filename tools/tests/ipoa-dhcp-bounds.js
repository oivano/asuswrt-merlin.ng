const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const wan = fs.readFileSync(path.join(root, 'release/src/router/rc/wan.c'), 'utf8');
const udhcpc = fs.readFileSync(path.join(root, 'release/src/router/rc/udhcpc.c'), 'utf8');

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert.ok(start >= 0, `missing ${signature}`);
    const open = source.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < source.length; index++) {
        if (source[index] === '{') depth++;
        if (source[index] === '}' && --depth === 0) return source.slice(open + 1, index);
    }
    assert.fail(`unterminated ${signature}`);
}

for (const name of ['start_ipoa(int unit)', 'stop_ipoa(int unit)']) {
    const body = functionBody(wan, name);
    assert.match(body, /ipoa_get_static_config\(unit,/);
    assert.doesNotMatch(body, /strcpy\s*\(/);
}
assert.match(functionBody(wan, 'ipoa_read_static_ipv4('), /inet_pton\(AF_INET, value, &parsed\)/);
assert.match(functionBody(wan, 'ipoa_read_static_ipv4('), /wan%d_%s_x/);
assert.match(wan, /start_ipoa\(unit\)/);
assert.match(wan, /stop_ipoa\(unit\)/);

const bound = functionBody(udhcpc, 'bound(int renew)');
assert.match(bound, /nvram_set_env_ipv4\([^;]+"subnet"\)/);
assert.match(bound, /nvram_set_env_ipv4\([^;]+"router"\)/);
assert.doesNotMatch(bound, /nvram_set_env\([^;]+"subnet"\)/);
assert.doesNotMatch(bound, /nvram_set_env\([^;]+"router"\)/);
assert.match(functionBody(udhcpc, 'first_ipv4_address('), /inet_pton\(AF_INET, token, &parsed\)/);

function firstIpv4Address(list) {
    for (const token of list.trim().split(/\s+/)) {
        if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(token) &&
            token.split('.').every(part => Number(part) <= 255)) return token;
    }
    return '';
}

const routers = Array.from({length: 63}, (_, index) => `10.20.${index >> 8}.${index & 255}`).join(' ');
assert.ok(routers.length > 32);
assert.equal(firstIpv4Address(routers), '10.20.0.0');
assert.equal(firstIpv4Address('bad 192.0.2.1 198.51.100.1'), '192.0.2.1');
assert.equal(firstIpv4Address('999.1.1.1 not-an-address'), '');
assert.equal(firstIpv4Address('255.255.255.252'), '255.255.255.252');

console.log('PASS: IPoA uses validated per-unit static IPv4 values; DHCP gateway/netmask storage selects one IPv4 token (source contracts and model only)');