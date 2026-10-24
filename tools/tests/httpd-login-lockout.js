const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.c'), 'utf8');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const header = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.h'), 'utf8');
const limit = Number(source.match(/#define LOGIN_SOURCE_LIMIT (\d+)/)[1]);
function body(text, name) {
    const start = text.indexOf(`\n${name}(`);
    assert(start >= 0, name);
    return text.slice(text.indexOf('{', start), text.indexOf('\n}', start) + 2);
}
const login = body(web, 'login_cgi');
const dispatch = body(source, 'handle_request');
assert.doesNotMatch(dispatch, /check_lock_status|httpd_login_status|httpd_login_failed/);
assert.match(dispatch, /auth_result = auth_check\(url, file, cookies, fromapp, &add_try\);/);
assert.doesNotMatch(source + web, /(?:\+\+\s*\b(?:login_try(?:_wan)?|login_fail_num)\b|\b(?:login_try(?:_wan)?|login_fail_num)\s*\+\+|\block_flag\s*\|=)/);
assert.doesNotMatch(login, /check_lock_status|SG_mode|httpd_force_lock/);
assert.doesNotMatch(body(source, 'send_login_page'), /httpd_login_failed|login_try/);
assert.match(login, /lock_status = httpd_login_status\(&dt\);\s*if\(lock_status == LOGINLOCK\)/);
assert(login.indexOf('httpd_login_status(&dt)') < login.indexOf('is_captcha_match'));
assert(login.indexOf('httpd_login_status(&dt)') < login.indexOf('compare_passwd_in_shadow'));
assert.match(login, /httpd_login_failed\(WRONGCAPTCHA\)/);
assert.match(login, /login_error_status = httpd_login_failed\(ACCOUNTFAIL\);/);
assert.match(login, /HTTPD_DBG\("authpass!\\n"\);\s*httpd_login_reset\(\);/);
assert.match(login, /dt, NOLOGINTRY/);
assert.match(header, /extern int httpd_login_failed\(int error_status\);/);
assert.match(header, /extern void httpd_login_notify\(const char \*address\);/);
assert.match(body(web, 'httpd_login_notify'), /SEND_NT_EVENT\(ADMIN_LOGIN_FAIL_LAN_WEB_EVENT, event\)/);
function translated(name, parameters) {
    const start = source.indexOf(`\n${name}(`);
    assert(start >= 0, name);
    let body = source.slice(source.indexOf('{', start), source.indexOf('\n}', start) + 2)
        .replace(/struct login_source \*entry = &?([^;]+);/g, 'let entry = $1;')
        .replace(/\(unsigned long\)/g, '')
        .replace(/->/g, '.')
        .replace(/sizeof\([^)]*\)/g, '0')
        .replace(/\*elapsed/g, 'elapsed.value');
    if (name === 'login_source_get') {
        body = body.slice(body.indexOf('\n\tfor (index'));
        body = '{ let address = currentAddress, now = uptime(), slot = null, index;' + body;
        body = body.replace(/&login_sources/g, 'login_sources')
            .replace(/\bNULL\b/g, 'null')
            .replace(/strlcpy\(slot.address, address, 0\);/, 'slot.address = address;');
    }
    return `function ${name}(${parameters}) ${body}`;
}
const empty = () => ({ address: '', failures: 0, error_status: 0, last_failure: 0, blocked_at: 0 });
const notifications = [];
const context = vm.createContext({
    now: 100, currentAddress: '192.168.1.2', LOGIN_SOURCE_LIMIT: limit,
    MAX_LOGIN_BLOCK_TIME: 300, DEFAULT_LOGIN_MAX_NUM: 5, LOGINLOCK: 7, ACCOUNTFAIL: 3,
    login_sources: Array.from({ length: limit }, empty),
    uptime: () => context.now,
    httpd_login_notify: address => notifications.push(address),
    strcmp: (left, right) => left === right ? 0 : 1,
    memset: entry => Object.assign(entry, empty())
});
vm.runInContext([
    translated('login_source_get', 'create'),
    translated('httpd_login_attempts', ''),
    translated('httpd_login_status', 'elapsed'),
    translated('httpd_login_failed', 'error_status'),
    translated('httpd_login_reset', '')
].join('\n'), context);
const elapsed = { value: 0 };
for (let attempt = 1; attempt <= 5; ++attempt)
    assert.equal(context.httpd_login_failed(3), attempt === 5 ? 7 : 3);
assert.deepEqual(notifications, ['192.168.1.2']);
assert.equal(context.httpd_login_status(elapsed), 7);
context.currentAddress = '192.168.1.3';
assert.equal(context.httpd_login_status(elapsed), 0);
assert.equal(context.httpd_login_attempts(), 0);
context.httpd_login_failed(10);
assert.equal(context.httpd_login_status(elapsed), 10);
context.httpd_login_reset();
context.currentAddress = '192.168.1.2';
assert.equal(context.httpd_login_attempts(), 5);
context.now += 299;
assert.equal(context.httpd_login_status(elapsed), 7);
assert.equal(elapsed.value, 299);
context.httpd_login_failed(3);
assert.deepEqual(notifications, ['192.168.1.2']);
context.now += 1;
assert.equal(context.httpd_login_status(elapsed), 0);
assert.equal(context.httpd_login_attempts(), 0);
context.currentAddress = '2001:db8::1';
for (let attempt = 0; attempt < 5; ++attempt) context.httpd_login_failed(3);
context.currentAddress = '2001:db8::2';
assert.equal(context.httpd_login_status(elapsed), 0);
context.currentAddress = '2001:db8::1';
assert.equal(context.httpd_login_status(elapsed), 7);
context.now = 1;
assert.equal(context.httpd_login_status(elapsed), 0);
for (let index = 0; index <= limit; ++index) {
    context.currentAddress = `2001:db8:1::${index}`;
    context.httpd_login_failed(3);
}
context.currentAddress = '192.168.1.3';
assert.equal(context.httpd_login_status(elapsed), 0);
assert.equal(context.login_sources.length, limit);
assert.match(source, /IN6_IS_ADDR_V4MAPPED\(addr\)/);
assert.match(source, /inet_ntop\(family, peer, address, sizeof\(address\)\)/);

context.httpd_login_reset();
for (const userAgent of ['browser', 'asusrouter-a-DUTUtil-1', 'WebView', 'ASSIA', 'browser']) {
    context.userAgent = userAgent;
    context.httpd_login_failed(3);
}
assert.equal(context.httpd_login_status(elapsed), 7);
context.currentAddress = '192.168.1.50';
assert.equal(context.httpd_login_status(elapsed), 0);
for (let attempt = 0; attempt < 4; ++attempt) context.httpd_login_failed(3);
context.now += 300;
assert.equal(context.httpd_login_attempts(), 0);
assert.equal(context.httpd_login_failed(3), 3);
assert.equal(context.httpd_login_attempts(), 1);

const errorInfo = body(web, 'ej_login_error_info').split('\n\t/* url */')[0]
    .replace(/struct json_object \*item = json_object_new_object\(\);/, 'let item = {};')
    .replace(/int error_status/g, 'let error_status')
    .replace(/&login_dt/g, 'login_dt')
    .replace(/^#(?:ifdef RTCONFIG_CAPTCHA|endif).*$/gm, '') + '\n return item;\n}';
Object.assign(context, {
    login_dt: { value: 0 }, login_error_status: 7, WRONGCAPTCHA: 10,
    json_object_new_int: value => value,
    json_object_object_add: (item, key, value) => { item[key] = value; },
    last_time_lock_warning: () => 0
});
vm.runInContext(`function error_info() ${errorInfo.replace(/MAX_LOGIN_BLOCK_TIME - login_dt/g, 'MAX_LOGIN_BLOCK_TIME - login_dt.value')}`, context);
context.currentAddress = '192.168.1.51';
assert.equal(context.error_info().error_status, 0);
assert.equal(context.error_info().error_num, 0);
assert.equal(context.error_info().lock_time, 0);
context.httpd_login_failed(10);
assert.equal(context.error_info().error_status, 10);
assert.equal(context.error_info().error_num, 1);
for (let attempt = 0; attempt < 4; ++attempt) context.httpd_login_failed(3);
assert.equal(context.error_info().error_status, 7);
assert.equal(context.error_info().lock_time, 300);
context.now += 299;
assert.equal(context.error_info().lock_time, 1);
context.now += 1;
assert.equal(context.error_info().error_status, 0);
assert.equal(context.error_info().lock_time, 0);
console.log('httpd login lockout: dispatcher contracts, source-derived cooldown and error-page checks passed (not compiled C)');