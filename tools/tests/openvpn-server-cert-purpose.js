const assert = require('assert');
const fs = require('fs');

const setup = fs.readFileSync('release/src/router/libovpn/openvpn_setup.c', 'utf8');
const options = fs.readFileSync('release/src/router/libovpn/openvpn_options.c', 'utf8');
const page = fs.readFileSync('release/src/router/www/Advanced_OpenVPNClient_Content.asp', 'utf8');

assert.match(setup, /if \(cconf->auth_mode == OVPN_AUTH_TLS\s*\)\s*\{\s*fprintf\(fp, "client\\n"\);\s*fprintf\(fp, "remote-cert-tls server\\n"\);\s*\}/);
assert.match(options, /else if \(streq \(p\[0\], "remote-cert-tls"\)\)\s*\{\s*return 0;/);
assert.match(page, /<tr id="client_tls_verify">\s*<th>Server Certificate Purpose<\/th>\s*<td>Required \(serverAuth\)<\/td>/);
assert.match(page, /showhide\("client_tls_verify", \(auth == "tls"\)\);/);

console.log('OpenVPN TLS server certificate purpose checks: PASS');