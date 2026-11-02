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
const sendLogin = body(source, 'send_login_page');
const redirectPageValidator = body(source, 'httpd_login_redirect_page_valid');
const redirectValueValidator = body(source, 'httpd_login_redirect_value_valid');
const loginErrorInfo = body(web, 'ej_login_error_info');
assert.doesNotMatch(dispatch, /check_lock_status|httpd_login_status|httpd_login_failed/);
assert.match(dispatch, /auth_result = auth_check\(url, file, cookies, fromapp, &add_try\);/);
assert.doesNotMatch(source + web, /(?:\+\+\s*\b(?:login_try(?:_wan)?|login_fail_num)\b|\b(?:login_try(?:_wan)?|login_fail_num)\s*\+\+|\block_flag\s*\|=)/);
assert.doesNotMatch(login, /check_lock_status|SG_mode|httpd_force_lock/);
assert.doesNotMatch(body(source, 'send_login_page'), /httpd_login_failed|login_try/);
assert.match(login, /lock_status = httpd_login_status\(&dt\);\s*if\(lock_status == LOGINLOCK\)/);
assert(login.indexOf('httpd_login_status(&dt)') < login.indexOf('is_captcha_match'));
assert(login.indexOf('httpd_login_status(&dt)') < login.indexOf('compare_passwd_in_shadow'));
assert.match(login, /if \(!httpd_login_attempt_admit\(\)\) \{\s*send_login_page\(fromapp_flag, ACCOUNTFAIL/);
assert(login.indexOf('httpd_login_attempt_admit()') < login.indexOf('is_captcha_match'));
assert(login.indexOf('httpd_login_attempt_admit()') < login.indexOf('compare_passwd_in_shadow'));
assert.doesNotMatch(login.slice(login.indexOf('httpd_login_attempt_admit()') - 160,
    login.indexOf('httpd_login_attempt_admit()')), /FROM_DUTUtil/);
assert.match(login, /httpd_login_failed\(WRONGCAPTCHA\)/);
assert.match(login, /login_error_status = httpd_login_failed\(ACCOUNTFAIL\);/);
assert.match(login, /HTTPD_DBG\("authpass!\\n"\);\s*httpd_login_reset\(\);/);
assert.match(login, /dt, NOLOGINTRY/);
assert.match(redirectPageValidator, /length >= 128/);
assert.match(redirectPageValidator, /check_xss_blacklist\(page, 1\)/);
assert.match(redirectPageValidator, /useful_redirect_page\(page\)/);
assert.match(redirectValueValidator, /length >= 256/);
assert.doesNotMatch(redirectValueValidator, /strncpy/);
assert.match(sendLogin, /httpd_login_redirect_page_valid\(url\)/);
assert.match(sendLogin, /httpd_login_redirect_value_valid\(file_var\)/);
assert.doesNotMatch(sendLogin, /login_url|char cloud_file/);
assert.match(loginErrorInfo, /websGetVar\(wp, "next_page"/);
assert.match(loginErrorInfo, /websGetVar\(wp, "cloud_file"/);
assert.match(loginErrorInfo, /strcmp\(page, "cfg_onboarding\.cgi"\).*strlen\(redirect_file\) != 12/);
assert.doesNotMatch(loginErrorInfo, /login_url/);
assert.doesNotMatch(source, /^char login_url\[128\];$/m);
assert.match(login, /websGetVar\(wp, "cloud_file"/);
assert.doesNotMatch(login, /, cloud_file\)/);
assert.match(login, /httpd_login_redirect_page_valid\(next_page\)/);
assert.match(login, /httpd_login_redirect_value_valid\(redirect_file\)/);
assert.match(login, /strcmp\(next_page, "cfg_onboarding\.cgi"\).*strlen\(redirect_file\) != 12/);
assert.match(login, /next_page=%s&cloud_file=%s/);
assert.match(login, /url=%s[^\n]*indexpage/);
assert.match(login.slice(login.indexOf('HTTPD_DBG("authfail:')), /parent\.location\.href='\/Main_Login\.asp\?next_page=%s&cloud_file=%s'/);
assert.doesNotMatch(login, /, cloud_file\)/);
const loginPage = fs.readFileSync(path.join(root, 'release/src/router/www/Main_Login.asp'), 'utf8');
assert.match(loginPage, /name="cloud_file"/);
assert.match(loginPage, /document\.form\.cloud_file\.value = redirect_file/);
assert.match(loginPage, /window\.location\.search/);
assert.match(header, /extern int httpd_login_failed\(int error_status\);/);
assert.match(header, /extern void httpd_login_notify\(const char \*address\);/);
assert.match(header, /extern int httpd_login_attempt_admit\(void\);/);
assert.match(source, /#define LOGIN_GLOBAL_STATE_FILE "\/tmp\/httpd\/login-budget"/);
assert.match(source, /flock\(fd, LOCK_EX\)/);
assert.match(source, /flock\(fd, LOCK_UN\)/);
assert.match(body(source, 'login_global_state_open'), /O_NOFOLLOW/);
assert.match(body(source, 'login_global_state_open'), /st_uid != 0.*st_nlink != 1/s);
assert.match(body(source, 'login_global_state_open'), /flock\(fd, LOCK_EX\)/);
assert.match(body(source, 'httpd_login_attempt_admit'), /login_global_delay\(state\.attempts\)/);
assert.match(body(source, 'httpd_login_attempt_admit'), /state\.last_attempt = now/);
assert.match(body(source, 'httpd_login_attempt_admit'), /if \(fd < 0\)\s*return 0/);
assert.match(body(source, 'httpd_login_attempt_admit'), /login_global_state_save\(fd, &state\) == 0/);
assert.match(body(source, 'login_global_reset'), /memset\(&state, 0, sizeof\(state\)\)/);
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
    LOGIN_GLOBAL_MAX_DELAY: 30,
    login_sources: Array.from({ length: limit }, empty),
    uptime: () => context.now,
    httpd_login_notify: address => notifications.push(address),
    strcmp: (left, right) => left === right ? 0 : 1,
    memset: entry => Object.assign(entry, empty())
});
const globalBudget = { attempts: 0, lastAttempt: 0, nextAttempt: 0 };
const globalDelayBody = body(source, 'login_global_delay')
    .replace('unsigned int delay = 1;', 'let delay = 1;')
    .replace('unsigned int level;', 'let level;')
    .replace('level = (attempts - DEFAULT_LOGIN_MAX_NUM) / DEFAULT_LOGIN_MAX_NUM;',
        'level = Math.floor((attempts - DEFAULT_LOGIN_MAX_NUM) / DEFAULT_LOGIN_MAX_NUM);');
vm.runInContext(`function login_global_delay(attempts) ${globalDelayBody}`, context);
context.login_global_attempt_admit = () => {
    if (globalBudget.attempts &&
        (context.now < globalBudget.lastAttempt || context.now - globalBudget.lastAttempt >= 300))
        Object.assign(globalBudget, { attempts: 0, lastAttempt: 0, nextAttempt: 0 });
    if (globalBudget.nextAttempt && context.now < globalBudget.nextAttempt) return false;
    ++globalBudget.attempts;
    globalBudget.lastAttempt = context.now;
    const delay = context.login_global_delay(globalBudget.attempts);
    globalBudget.nextAttempt = delay ? context.now + delay : 0;
    return true;
};
context.httpd_login_attempt_admit = context.login_global_attempt_admit;
context.login_global_reset = () =>
    Object.assign(globalBudget, { attempts: 0, lastAttempt: 0, nextAttempt: 0 });
vm.runInContext([
    translated('login_source_get', 'create'),
    translated('httpd_login_attempts', ''),
    translated('httpd_login_status', 'elapsed'),
    translated('httpd_login_failed', 'error_status'),
    translated('httpd_login_reset', '')
].join('\n'), context);
context.now = 0;
for (let attempt = 0; attempt < 5; ++attempt)
    assert.equal(context.httpd_login_attempt_admit(), true);
assert.equal(context.httpd_login_attempt_admit(), false);
context.now = 300;
assert.equal(context.httpd_login_attempt_admit(), true);
assert.equal(globalBudget.attempts, 1, 'window expires when first attempt occurs at uptime zero');
context.login_global_reset();
context.now = 100;
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

assert.deepEqual([4, 5, 9, 10, 15, 20, 25, 30, 100].map(context.login_global_delay),
    [0, 1, 1, 2, 4, 8, 16, 30, 30]);
const rotatingBudget = { attempts: 0, lastAttempt: 0, nextAttempt: 0 };
let rotatingAttempts = 0;
for (let seconds = 0; seconds < 300; ++seconds) {
    if (rotatingBudget.nextAttempt > seconds) continue;
    ++rotatingAttempts;
    ++rotatingBudget.attempts;
    rotatingBudget.lastAttempt = seconds;
    const delay = context.login_global_delay(rotatingBudget.attempts);
    rotatingBudget.nextAttempt = delay ? seconds + delay : 0;
}
assert(rotatingAttempts < 40, `rotating sources admitted ${rotatingAttempts} guesses in five minutes`);

const errorInfo = body(web, 'ej_login_error_info').split('\n\t/* Keep redirect state on this login-page request, not in process globals. */')[0]
    .replace(/char \*page = websGetVar\(wp, "next_page", ""\);/, 'let page = "";')
    .replace(/char \*redirect_file = websGetVar\(wp, "cloud_file", ""\);/, 'let redirect_file = "";')
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
const slowlorisSourceGet = body(source, 'httpd_slowloris_source_get');
const slowlorisBlocked = body(source, 'httpd_slowloris_blocked');
const slowlorisCheck = body(source, 'httpd_slowloris_record_timeout');
const requestDeadlineStop = body(source, 'httpd_request_deadline_stop');
assert.doesNotMatch(source + header, /\b(?:filter_ban_ip|slowloris_check|add_ban_ip|clean_ban_ip_timeout)\s*\(/);
assert.match(slowlorisSourceGet, /inet_ntop\(family, peer_address, address, sizeof\(address\)\)/);
assert.match(slowlorisSourceGet, /entry->family == family &&\s*!strcmp\(entry->address, address\)/);
assert.match(slowlorisCheck, /httpd_slowloris_loopback\(peer\)/);
assert.match(requestDeadlineStop, /if \(!request_headers_complete\)\s*httpd_slowloris_record_timeout\(&request_peer\)/);
assert.match(slowlorisBlocked, /now < entry->blocked_until/);
assert.match(source, /httpd_slowloris_blocked\(&item->usa\)/);
assert.match(source, /#define HTTPD_SLOWLORIS_ATTEMPT_LIMIT 7/);
assert.match(source, /#define HTTPD_SLOWLORIS_WINDOW 600/);
assert.match(source, /#define HTTPD_SLOWLORIS_BLOCK 600/);
assert.doesNotMatch(slowlorisSourceGet + slowlorisBlocked + slowlorisCheck, /nvram_(?:get|set)|slowloris_ip_list/);

const slowlorisLimit = Number(source.match(/#define HTTPD_SLOWLORIS_ATTEMPT_LIMIT (\d+)/)[1]);
const slowlorisWindow = Number(source.match(/#define HTTPD_SLOWLORIS_WINDOW (\d+)/)[1]);
const slowlorisBlock = Number(source.match(/#define HTTPD_SLOWLORIS_BLOCK (\d+)/)[1]);
const slowlorisSources = new Map();
function slowlorisTimeout(family, address, now) {
    const identity = `${family}:${address}`;
    let entry = slowlorisSources.get(identity);
    if (!entry) {
        entry = { attempts: 0, firstAttempt: now, blockedUntil: 0 };
        slowlorisSources.set(identity, entry);
    }
    if (now < entry.firstAttempt || now - entry.firstAttempt >= slowlorisWindow) {
        entry.attempts = 0;
        entry.firstAttempt = now;
    }
    if (++entry.attempts >= slowlorisLimit)
        entry.blockedUntil = now + slowlorisBlock;
}
function slowlorisIsBlocked(family, address, now) {
    const entry = slowlorisSources.get(`${family}:${address}`);
    return Boolean(entry && entry.blockedUntil && now < entry.blockedUntil);
}

const slowlorisVictim = '192.168.1.100';
const slowlorisAttacker = '2001:db8::c0a8:164';
for (let index = 0; index < slowlorisLimit; ++index)
    slowlorisTimeout('AF_INET6', slowlorisAttacker, 100 + index);
assert(slowlorisIsBlocked('AF_INET6', slowlorisAttacker, 106));
assert(!slowlorisIsBlocked('AF_INET', slowlorisVictim, 106));
assert(!slowlorisIsBlocked('AF_INET6', slowlorisAttacker, 706));
slowlorisTimeout('AF_INET', slowlorisVictim, 107);
assert(!slowlorisIsBlocked('AF_INET', slowlorisVictim, 107));

console.log('httpd login lockout and slowloris ban: per-source accounting, full-address family isolation and expiry checks passed (source contracts/model; not compiled C)');