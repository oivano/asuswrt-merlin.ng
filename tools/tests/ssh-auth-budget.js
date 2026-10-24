const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const listener = read('release/src/router/dropbear/src/svr-main.c');
const ssh = read('release/src/router/rc/ssh.c');
const ui = read('release/src/router/www/Advanced_System_Content.asp');
const constants = Object.fromEntries([...listener.matchAll(/^#define (SSH_SOURCE_\w+) (\d+)$/gm)]
    .map(match => [match[1], Number(match[2])]));
assert.deepEqual(constants, {
    SSH_SOURCE_SLOTS: 64, SSH_SOURCE_CONNECTIONS: 5, SSH_SOURCE_WINDOW: 60, SSH_SOURCE_BLOCK: 300,
});
const functionStart = listener.indexOf('static int ssh_source_allowed(');
const functionEnd = listener.indexOf('\nstatic void main_noinetd(', functionStart);
assert.ok(functionStart > 0 && functionEnd > functionStart);
let body = listener.slice(functionStart, functionEnd);
body = body.replace(/static int ssh_source_allowed\(const char \*host, time_t now\)/,
    'function ssh_source_allowed(host, now)')
    .replace(/struct ssh_source_budget \*budget = NULL;/, 'let budget = null;')
    .replace(/size_t source_index;/, 'let source_index;')
    .replace(/struct ssh_source_budget \*entry = &ssh_source_budgets\[source_index\];/,
        'let entry = ssh_source_budgets[source_index];')
    .replace(/sizeof\(ssh_source_budgets\[0\]\.host\)/g, '128')
    .replace(/strlen\(host\)/g, 'host.length')
    .replace(/strcmp\(([^,]+), host\)/g, '($1 === host ? 0 : 1)')
    .replace(/strcpy\(budget->host, host\);/, 'budget.host = host;')
    .replace(/->/g, '.')
    .replace(/\bNULL\b/g, 'null');
const makeLimiter = () => {
    const context = vm.createContext({
        ...constants,
        ssh_source_budgets: Array.from({ length: constants.SSH_SOURCE_SLOTS }, () => ({
            host: '', started: 0, blocked_until: 0, connections: 0,
        })),
    });
    vm.runInContext(body, context);
    return context.ssh_source_allowed;
};

for (const source of ['192.0.2.1', '2001:db8::1', '::ffff:192.0.2.1']) {
    const allowed = makeLimiter();
    for (let attempt = 0; attempt < 5; attempt++) assert.equal(allowed(source, 100 + attempt), 1);
    assert.equal(allowed(source, 105), 0);
    assert.equal(allowed(source, 404), 0);
    assert.equal(allowed('198.51.100.2', 106), 1);
    assert.equal(allowed(source, 405), 1);
}
const expiry = makeLimiter();
for (let attempt = 0; attempt < 5; attempt++) assert.equal(expiry('192.0.2.1', 0), 1);
assert.equal(expiry('192.0.2.1', 60), 1);
const full = makeLimiter();
for (let source = 0; source < 64; source++) assert.equal(full(`2001:db8::${source}`, 100), 1);
assert.equal(full('198.51.100.1', 101), 0);
for (let attempt = 0; attempt < 4; attempt++) assert.equal(full('2001:db8::0', 101), 1);
assert.equal(full('2001:db8::0', 102), 0);
assert.equal(full('198.51.100.1', 160), 1);
assert.equal(full('2001:db8::0', 161), 0);
assert.equal(makeLimiter()(null, 0), 0);
assert.equal(makeLimiter()('x'.repeat(128), 0), 0);

const admission = listener.indexOf('if (!ssh_source_allowed(remote_host, monotonic_now()))');
assert.ok(admission > listener.indexOf('childsock = accept('));
assert.ok(admission < listener.indexOf('fork_ret = fork();'));
assert.match(listener, /#if NON_INETD_MODE\s+#define SSH_SOURCE_SLOTS/);
assert.match(listener, /getaddrstring\(&remoteaddr, &remote_host, NULL, 0\)/);
assert.match(ssh, /if \(nvram_get_int\("sshd_enable"\) == 1 \|\| !nvram_get_int\("sshd_pass"\)\)\s+dropbear_argv\[index\+\+\] = "-s"/);
assert.doesNotMatch(ssh, /"-i"/);
for (const mode of [1, 2]) {
    for (const passwords of [0, 1]) {
        const expression = ssh.match(/if \((nvram_get_int\("sshd_enable"\).*?)\)\s+dropbear_argv\[index\+\+\] = "-s"/)[1];
        const keyOnly = vm.runInNewContext(expression, {
            nvram_get_int: name => name === 'sshd_enable' ? mode : passwords,
        });
        assert.equal(Boolean(keyOnly), mode === 1 || passwords === 0);
    }
}
const handler = ui.slice(ui.indexOf('function check_sshd_enable('), ui.indexOf('/*function sshd_remote_access('));
for (const mode of ['0', '1', '2']) {
    const controls = [{ checked: true, disabled: false }, { checked: false }];
    const elements = {};
    const context = vm.createContext({ document: {
        form: { sshd_pass: controls },
        getElementById: id => elements[id] || (elements[id] = { style: {} }),
    } });
    vm.runInContext(handler, context);
    context.check_sshd_enable(mode);
    assert.equal(controls[0].disabled, mode === '1');
    assert.equal(controls[1].checked, mode === '1');
    assert.equal(elements.auth_keys_tr.style.display, mode === '0' ? 'none' : '');
    context.check_sshd_enable('2');
    assert.equal(controls[0].disabled, false);
}
const keyGuard = ui.match(/if\((document\.form\.sshd_enable\.value != "0"[^\n]+)\)\{/)[1];
for (const mode of ['0', '1', '2']) {
    for (const passwords of [true, false]) {
        for (const keys of ['', ' \t\n', 'ssh-ed25519 fixture']) {
            const rejects = vm.runInNewContext(keyGuard, { document: { form: {
                sshd_enable: { value: mode }, sshd_pass: [{ checked: passwords }, { checked: !passwords }],
                sshd_authkeys: { value: keys },
            } } });
            assert.equal(rejects, mode !== '0' && (mode === '1' || !passwords) && keys.trim() === '');
        }
    }
}
assert.match(ui, />LAN & WAN \(key only\)<\/option>/);
assert.doesNotMatch(ui, /<%\s*nvram_\w+\(\s*"\s+[^"\n]*"/);
console.log('SSH reconnect budget, WAN key-only policy and UI checks passed (not compiled C or firmware).');