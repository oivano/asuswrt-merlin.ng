const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const optionsPath = path.join(root, 'release/src/router/libovpn/openvpn_options.c');
const setupPath = path.join(root, 'release/src/router/libovpn/openvpn_setup.c');
const headerPath = path.join(root, 'release/src/router/libovpn/openvpn_options.h');
const uiPaths = [
    'release/src/router/www/Advanced_VPNClient_Content.asp',
    'release/src/router/www/Advanced_VPNClientFusion_Content.asp',
    'release/src/router/www/Advanced_OpenVPNClient_Content.asp'
].map(file => path.join(root, file));
const optionsSource = fs.readFileSync(optionsPath, 'utf8');
const setupSource = fs.readFileSync(setupPath, 'utf8');
const headerSource = fs.readFileSync(headerPath, 'utf8');
const uiSources = uiPaths.map(file => fs.readFileSync(file, 'utf8'));

const policy = optionsSource.match(/ovpn_option_is_unsafe\(const char \*option\)\s*\{([\s\S]*?)\n\}/);
assert(policy, 'unsafe OpenVPN option classifier exists');
const blocked = [...policy[1].matchAll(/"([^"]+)"/g)].map(match => match[1]);
const prefixes = [];
if (policy[1].includes('!strncmp(option, "management", 10)')) prefixes.push('management');
if (policy[1].includes('!strncmp(option, "log", 3)')) prefixes.push('log');

function isUnsafe(option) {
    if (option.startsWith('--')) option = option.slice(2);
    return blocked.includes(option) || prefixes.some(prefix => option.startsWith(prefix));
}

for (const option of [
    'up', 'down', 'route-up', 'route-pre-down', 'ipchange', 'tls-verify',
    'auth-user-pass-verify', 'client-connect', 'client-disconnect', 'learn-address',
    'plugin', 'script-security', 'management', 'management-client', 'log',
    'log-append', 'status', 'writepid', 'chroot', 'setenv', 'setenv-safe',
    'config', 'cd', 'daemon', 'dev-node', 'iproute', 'pkcs12', 'askpass',
    'tls-export-cert', 'auth-gen-token-secret', 'tmp-dir'
]) {
    assert(isUnsafe(option), `${option} must be rejected`);
}
assert(isUnsafe('--up'), 'double-dash option spelling must be rejected');
for (const option of ['client', 'proto', 'remote', 'cipher', 'auth', 'redirect-gateway']) {
    assert(!isUnsafe(option), `${option} must remain importable`);
}

assert(headerSource.includes('#define VPN_UPLOAD_REJECTED_OPTIONS (1<<6)'),
    'rejected-option upload status bit is defined');
assert(/if\s*\(ovpn_option_is_unsafe\(p\[0\]\)\)[\s\S]*?return VPN_UPLOAD_REJECTED_OPTIONS;/.test(optionsSource),
    'profile importer rejects unsafe options before custom fall-through');
assert(setupSource.includes('return ovpn_option_is_unsafe(option);'),
    'client custom writer uses the same unsafe-option policy');

const clientWriterStart = setupSource.indexOf('int ovpn_write_client_config(');
const clientWriterEnd = setupSource.indexOf('\nvoid ovpn_write_client_keys', clientWriterStart);
assert(clientWriterStart >= 0 && clientWriterEnd > clientWriterStart, 'client config writer exists');
const clientWriter = setupSource.slice(clientWriterStart, clientWriterEnd);
const customIndex = clientWriter.indexOf('write_client_custom(fp, cconf->custom)');
const upIndex = clientWriter.indexOf('up \'ovpn-up %d client\'');
const scriptSecurityIndex = clientWriter.indexOf('script-security 2');
assert(customIndex >= 0 && customIndex < upIndex, 'custom config is written before router hooks');
assert(upIndex >= 0 && scriptSecurityIndex > upIndex,
    'router hooks and script-security follow custom config');
for (const [index, source] of uiSources.entries()) {
    assert(source.includes('Unsafe directives were rejected'),
        `${uiPaths[index]} reports rejected unsafe directives`);
}

console.log('OpenVPN profile import and generated-hook contracts passed');