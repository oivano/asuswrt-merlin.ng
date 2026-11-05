const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const config = fs.readFileSync(path.join(root, 'release/src/router/libovpn/openvpn_config.c'), 'utf8');
const options = fs.readFileSync(path.join(root, 'release/src/router/libovpn/openvpn_options.c'), 'utf8');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');

const functionBody = (source, signature) => {
    const start = source.indexOf(signature);
    assert(start >= 0, `missing function ${signature}`);
    const open = source.indexOf('{', start);
    let depth = 1;
    for (let cursor = open + 1; cursor < source.length; cursor++) {
        if (source[cursor] === '{') depth++;
        if (source[cursor] === '}' && --depth === 0) return source.slice(open + 1, cursor);
    }
    assert.fail(`unterminated function ${signature}`);
};

const validator = functionBody(config, 'static int ovpn_pem_material_valid(');
const setter = functionBody(config, 'int set_ovpn_key(');
const uploadSetter = functionBody(config, 'int _set_crt_parsed(');
const encoder = functionBody(web, 'static void ovpn_write_js_string(');
const emitter = functionBody(web, '_get_vpn_crt_value(');
const uploadHandler = functionBody(web, 'do_vpnupload_cgi(char *url, FILE *stream)');

assert.match(validator, /-----BEGIN /);
assert.match(validator, /-----END /);
assert.match(validator, /memcmp\(line \+ 9, label, end_label_len\)/);
assert.match(validator, /"Proc-Type"/);
assert.match(validator, /"DEK-Info"/);
assert.match(validator, /\*p == '\+'/);
assert.match(validator, /\*p == '\/'/);
assert.match(validator, /\*p == '='/);
assert.match(setter, /ovpn_pem_material_valid\(data\)/);
assert(setter.indexOf('ovpn_pem_material_valid(data)') < setter.indexOf('fopen(filename, "w")'));
assert.match(uploadSetter, /ovpn_pem_material_valid\(data\)/);
assert(uploadSetter.indexOf('ovpn_pem_material_valid(data)') < uploadSetter.indexOf('f_write('));
assert.match(options, /set_ovpn_key\(OVPN_TYPE_CLIENT, unit, OVPN_CLIENT_CA, p\[2\], NULL\) != 0\)[\s\S]*?return VPN_UPLOAD_NEED_CA_CERT/);
assert.match(options, /set_ovpn_key\(OVPN_TYPE_CLIENT, unit, OVPN_CLIENT_STATIC, p\[2\], NULL\) != 0\)[\s\S]*?return VPN_UPLOAD_NEED_STATIC/);
assert.equal((uploadHandler.match(/set_ovpn_key\([^;]+\) != 0/g) || []).length, 7);
assert.equal((uploadHandler.match(/nvram_set\("vpn_upload_state", "err"\)/g) || []).length, 9);

for (const escape of [
    /case '\\\\': websWrite\(wp, "\\\\\\\\"\)/,
    /websWrite\(wp, "\\\\'"\)/,
    /case '"': websWrite\(wp, "\\\\\\""\)/,
    /case '<': websWrite\(wp, "\\\\u003c"\)/,
    /case '>': websWrite\(wp, "\\\\u003e"\)/,
    /case '&': websWrite\(wp, "\\\\u0026"\)/,
    /\\\\u2028/,
    /\\\\u2029/,
    /\*p < 0x20 \|\| \*p == 0x7f/
]) assert.match(encoder, escape);
assert.match(emitter, /ovpn_write_js_string\(wp, buf\)/);
assert.doesNotMatch(emitter, /&#%d/);

const pemCases = [
    ['-----BEGIN CERTIFICATE-----\nQUJDREVGR0g=\n-----END CERTIFICATE-----\n', true],
    ['-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0123456789ABCDEF\n\nQUJDREVGR0g=\n-----END RSA PRIVATE KEY-----\n', true],
    ['-----BEGIN OpenVPN Static key V1-----\n0123456789abcdef\n-----END OpenVPN Static key V1-----\n', true],
    ['-----BEGIN CERTIFICATE-----\nQUJD\n-----END PRIVATE KEY-----\n', false],
    ['-----BEGIN CERTIFICATE-----\nQUJD\n\'];alert(1);//\n-----END CERTIFICATE-----\n', false],
    ['-----BEGIN CERTIFICATE-----\nQUJD\\\n-----END CERTIFICATE-----\n', false],
    ['-----BEGIN CERTIFICATE-----\nQUJD;alert(1)\n-----END CERTIFICATE-----\n', false],
    ['-----BEGIN CERTIFICATE-----\nscript: 1\nQUJD\n-----END CERTIFICATE-----\n', false],
    ['-----BEGIN CERTIFICATE-----\nQUJD\ntrailing text\n-----END CERTIFICATE-----\n', false],
    ['-----BEGIN CERTIFICATE-----\nQUJD\n', false]
];

const isPemMaterial = text => {
    let label = null;
    let bodySeen = false;
    let headerAllowed = false;
    let blocks = 0;
    for (let line of text.split('\n')) {
        if (line.endsWith('\r')) line = line.slice(0, -1);
        if (/[\x00-\x1f\x7f-\uffff]/.test(line)) return false;
        if (!line) continue;
        if (label === null) {
            const begin = line.match(/^-----BEGIN ([A-Za-z0-9][A-Za-z0-9 -]*[A-Za-z0-9])-----$/);
            if (!begin) return false;
            label = begin[1];
            bodySeen = false;
            headerAllowed = true;
        } else if (line === `-----END ${label}-----`) {
            if (!bodySeen) return false;
            label = null;
            blocks++;
        } else if (headerAllowed && /^(?:Proc-Type|DEK-Info): [A-Za-z0-9 ,._+\/=\-]*$/.test(line)) {
            continue;
        } else {
            headerAllowed = false;
            if (!/^[A-Za-z0-9+/=]+$/.test(line)) return false;
            bodySeen = true;
        }
    }
    return label === null && blocks > 0;
};

for (const [material, expected] of pemCases)
    assert.equal(isPemMaterial(material), expected, JSON.stringify(material));

const jsString = value => `"${Array.from(value, char => {
    const code = char.codePointAt(0);
    if (char === '\\') return '\\\\';
    if (char === "'") return "\\'";
    if (char === '"') return '\\"';
    if (char === '<') return '\\u003c';
    if (char === '>') return '\\u003e';
    if (char === '&') return '\\u0026';
    if (char === '\b') return '\\b';
    if (char === '\f') return '\\f';
    if (char === '\n') return '\\n';
    if (char === '\r') return '\\r';
    if (char === '\t') return '\\t';
    if (code === 0x2028) return '\\u2028';
    if (code === 0x2029) return '\\u2029';
    if (code < 0x20 || code === 0x7f) return `\\u${code.toString(16).padStart(4, '0')}`;
    return char;
}).join('')}"`;

const payload = "-----BEGIN CERTIFICATE-----\n'];alert(1);//\n-----END CERTIFICATE-----\n";
assert.equal(isPemMaterial(payload), false);
const context = { alert: () => { throw new Error('injected script executed'); } };
vm.createContext(context);
vm.runInContext(`var vpn_crt_client1_ca = [${jsString(payload)}];`, context);
assert.equal(context.vpn_crt_client1_ca[0], payload);
for (const [material, expected] of pemCases.filter(([, valid]) => valid))
    assert.equal(vm.runInNewContext(jsString(material)), material);

console.log('PASS: OpenVPN key material validation and JavaScript string escaping contracts');