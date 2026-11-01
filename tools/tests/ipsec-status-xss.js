const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const web = read('release/src/router/httpd/web.c');
const statusPage = read('release/src/router/www/Advanced_VPNStatus.asp');
const ipsecPage = read('release/src/router/www/Advanced_VPN_IPSec.asp');
const instantGuardPage = read('release/src/router/www/Advanced_Instant_Guard.asp');

const stateStart = web.indexOf('static int ipsec_status_get_state(');
const escapeStart = web.indexOf('static int ipsec_status_write_js_string(', stateStart);
const peerStart = web.indexOf('static int ipsec_status_parse_peer(', escapeStart);
const stateHelper = web.slice(stateStart, escapeStart);
const escapeHelper = web.slice(escapeStart, peerStart);
const infoStart = web.indexOf('get_ipsec_conn_info(');
const outputStart = web.indexOf('ej_get_ipsec_conn(', infoStart);
const infoFunction = web.slice(infoStart, outputStart);

assert(stateStart >= 0 && escapeStart > stateStart && peerStart > escapeStart);
assert.match(stateHelper, /strchr\(line, '\]'\)/);
assert.match(stateHelper, /separator\[1\] != ':'/);
assert.match(stateHelper, /length == sizeof\("ESTABLISHED"\) - 1/);
assert.match(stateHelper, /length == sizeof\("CONNECTING"\) - 1/);
assert.match(infoFunction, /connection_state = ipsec_status_get_state\(line\)/);
assert.match(infoFunction, /if\(connection_state == 1\)/);
assert.doesNotMatch(infoFunction, /strstr\(line,\s*"ESTABLISHED"\)/);
assert.match(infoFunction, /xauth_account\[0\] = '\\0';/);
assert.match(infoFunction, /eap_account\[0\] = '\\0';/);
assert.match(web, /ret \+= ipsec_status_write_js_string\(wp, ipsec_info_buf\)/);

for (const escape of ['\\\\u0022', '\\\\u0027', '\\\\u0026', '\\\\u003c',
    '\\\\u003e', '\\\\u005c', '\\\\u2028', '\\\\u2029'])
    assert(escapeHelper.includes(escape), `missing JavaScript escape ${escape}`);
assert.match(escapeHelper, /\*cursor < 0x20/);

function parseState(line) {
	const close = line.indexOf(']');
	if (close < 0 || line[close + 1] !== ':') return '';
	const token = line.slice(close + 2).trim().split(/\s+/, 1)[0];
	return token === 'ESTABLISHED' || token === 'CONNECTING' ? token : '';
}

const connectingLine = 'roadwarrior[17]: CONNECTING 198.51.100.8["+alert(1)+"ESTABLISHED]';
assert.equal(parseState(connectingLine), 'CONNECTING');
assert.equal(parseState('roadwarrior[17]: ESTABLISHED 198.51.100.8[peer]'), 'ESTABLISHED');
assert.equal(parseState('roadwarrior[17]: NOT_ESTABLISHED 198.51.100.8[peer]'), '');
assert.equal(parseState('roadwarrior[17]: ESTABLISHED,spoofed 198.51.100.8[peer]'), '');
assert.equal(parseState('roadwarrior[17]: CONNECTING 198.51.100.8["ESTABLISHED]') === 'ESTABLISHED', false);

function escapeJsString(value) {
	return Array.from(value, character => {
		const code = character.codePointAt(0);
		if (character === '"') return '\\u0022';
		if (character === "'") return '\\u0027';
		if (character === '&') return '\\u0026';
		if (character === '<') return '\\u003c';
		if (character === '>') return '\\u003e';
		if (character === '\\') return '\\u005c';
		if (code < 0x20 || code === 0x2028 || code === 0x2029)
			return `\\u${code.toString(16).padStart(4, '0')}`;
		return character;
	}).join('');
}

let alertCalls = 0;
const payload = '"+alert(1)+"ESTABLISHED';
assert.equal(vm.runInNewContext(`"${escapeJsString(payload)}"`, {
	alert: () => alertCalls++
}), payload);
assert.equal(alertCalls, 0);
const specialCharacters = `\\"'&<>\u0000\u001f\u2028\u2029`;
assert.equal(vm.runInNewContext(`"${escapeJsString(specialCharacters)}"`), specialCharacters);

const statusRender = statusPage.slice(statusPage.indexOf('function parseIPSecData('),
	statusPage.indexOf('function getIPSecClientStatus('));
assert.match(statusRender, /cell\.textContent = values\[column\] \|\| ""/);
assert.doesNotMatch(statusRender, /\+\s*profileName_col\[[0-4]\]/);
assert.match(statusRender, /tableContainer\.innerHTML = code/);

const ipsecRender = ipsecPage.slice(ipsecPage.indexOf('function showIPSecClients('),
	ipsecPage.indexOf('function export_cert('));
assert.match(ipsecRender, /cell\.textContent = values\[column\] \|\| ""/);
assert.doesNotMatch(ipsecRender, /html\s*\+=\s*["'][^\n]*item\[[0-4]\]/);

const instantGuardRender = instantGuardPage.slice(instantGuardPage.indexOf('function update_ipsec_conn('),
	instantGuardPage.indexOf('\n}\n</script>', instantGuardPage.indexOf('function update_ipsec_conn(')));
assert.match(instantGuardRender, /htmlEnDeCode\.htmlEncode\(value == undefined \? "" : String\(value\)\)/);
for (const value of ['itemCol[0]', 'statusText[itemCol[1]]', 'itemCol[2]', 'device', 'itemCol[4]'])
	assert(instantGuardRender.includes(`eachRuleArray.push(encodeCell(${value}))`), `unencoded Instant Guard cell: ${value}`);

const encode = value => String(value).replace(/[&<>"']/g, character => ({
	'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
})[character]);
assert.equal(encode('<script>alert("x")</script>&\''), '&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&#39;');

console.log('IPsec status XSS source/model checks passed');