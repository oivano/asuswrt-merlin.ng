const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');
const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.c'), 'utf8');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const header = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.h'), 'utf8');
const sharedBudgetSource = fs.readFileSync(path.join(root, 'release/src/router/shared/login_budget.c'), 'utf8');
const limit = Number(source.match(/#define LOGIN_SOURCE_LIMIT (\d+)/)[1]);
const captchaLimit = Number(header.match(/#define CAPTCHA_MAX_LOGIN_NUM\s+(\d+)/)[1]);
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
const captchaMatcher = body(web, 'httpd_login_captcha_match');
assert.doesNotMatch(dispatch, /check_lock_status|httpd_login_status|httpd_login_failed/);
assert.match(dispatch, /auth_result = auth_check\(url, file, cookies, fromapp, &add_try\);/);
assert.doesNotMatch(source + web, /(?:\+\+\s*\b(?:login_try(?:_wan)?|login_fail_num)\b|\b(?:login_try(?:_wan)?|login_fail_num)\s*\+\+|\block_flag\s*\|=)/);
assert.doesNotMatch(login, /check_lock_status|SG_mode|httpd_force_lock/);
assert.doesNotMatch(body(source, 'send_login_page'), /httpd_login_failed|login_try/);
assert.match(login, /lock_status = httpd_login_status\(&dt\);\s*if\(lock_status == LOGINLOCK\)/);
assert(login.indexOf('httpd_login_status(&dt)') < login.indexOf('httpd_login_captcha_match'));
assert(login.indexOf('httpd_login_status(&dt)') < login.indexOf('compare_passwd_in_shadow'));
assert.match(login, /if\(!nvram_match\("captcha_enable", "0"\)\)/);
assert.doesNotMatch(login, /fromapp_flag\s*!=\s*FROM_DUTUtil[^\n]*captcha_enable/);
assert.match(login, /httpd_login_captcha_match\(captcha_text, fromapp_flag\)/);
assert(login.indexOf('httpd_login_captcha_match') < login.indexOf('compare_passwd_in_shadow'));
assert.match(captchaMatcher, /fromapp_flag != FROM_DUTUtil/);
assert.match(captchaMatcher, /strlcpy\(user_agent, "Mozilla\/5\.0", sizeof\(user_agent\)\)/);
assert.match(captchaMatcher, /matched = is_captcha_match\(captcha_text\);\s*strlcpy\(user_agent, saved_user_agent, sizeof\(user_agent\)\);/);
assert.match(sharedBudgetSource, /#define LOGIN_BUDGET_CAPACITY 5/);
assert.match(sharedBudgetSource, /#define LOGIN_BUDGET_REFILL_SECONDS 30/);
assert.match(sharedBudgetSource, /#define LOGIN_BUDGET_FILE_LAN "\/tmp\/httpd\/login-budget-lan"/);
assert.match(sharedBudgetSource, /#define LOGIN_BUDGET_FILE_WAN "\/tmp\/httpd\/login-budget-wan"/);
assert.match(sharedBudgetSource, /#define LOGIN_BUDGET_FILE_UNKNOWN "\/tmp\/httpd\/login-budget-unknown"/);
assert.match(sharedBudgetSource, /#define LOGIN_BUDGET_FILE_SSH "\/tmp\/httpd\/login-budget-ssh"/);
const loginBudget = body(sharedBudgetSource, 'shared_login_attempt_admit');
assert.match(loginBudget, /file_lock\("httpd-login-budget"\)/);
assert.match(loginBudget, /login_budget_ensure_temp_dir\(\)/);
assert.match(loginBudget, /O_CREAT \| O_RDWR \| O_NOFOLLOW/);
assert.match(loginBudget, /st\.st_uid != geteuid\(\).*st\.st_nlink != 1/);
assert.match(loginBudget, /state\.tokens > LOGIN_BUDGET_CAPACITY/);
assert.match(loginBudget, /state\.tokens = 0/);
assert.match(loginBudget, /LOGIN_BUDGET_REFILL_SECONDS -/);
assert.match(loginBudget, /write\(fd, &state, sizeof\(state\)\)/);
assert.match(header, /#define LOGINRETRY\s+12/);
assert.match(source, /shared_login_attempt_admit\(scope, retry_after\)/);
assert.match(source, /cur_login_ip_type == 0[\s\S]*LOGIN_BUDGET_LAN[\s\S]*cur_login_ip_type == 1[\s\S]*LOGIN_BUDGET_WAN/);
assert.match(login, /if \(!authpass_fail && !auth_pass && !httpd_login_attempt_admit\(&retry_after\)\)/);
assert.doesNotMatch(login, /Retry-After|retry_after\\"/);
assert(login.indexOf('httpd_login_attempt_admit') > login.indexOf('compare_passwd_in_shadow'));
const throttledLogin = login.slice(login.indexOf('if (!authpass_fail && !auth_pass && !httpd_login_attempt_admit'),
    login.indexOf('if (!authpass_fail && auth_pass'));
assert.match(throttledLogin, /httpd_login_failed\(ACCOUNTFAIL\)/);
assert.match(throttledLogin, /httpd_login_response_headers\(wp, fromapp_flag, now, 429\)/);
assert.doesNotMatch(throttledLogin, /Retry-After|retry_after\\"/);
assert.doesNotMatch(login, /admin_account|login_name/);
assert.match(login, /else\s*\{\s*char \*admin_user = nvram_safe_get\("http_username"\);\s*if \(!compare_passwd_in_shadow\(admin_user, authpass\)\)\s*app_auth\(admin_user, authpass\);\s*\}/);
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
assert.match(web, /status == 429 \? "Too Many Requests" : "OK"/);
assert.match(body(web, 'httpd_login_notify'), /SEND_NT_EVENT\(ADMIN_LOGIN_FAIL_LAN_WEB_EVENT, event\)/);
function translated(name, parameters) {
    const start = source.indexOf(`\n${name}(`);
    assert(start >= 0, name);
    let body = source.slice(source.indexOf('{', start), source.indexOf('\n}', start) + 2)
        .replace(/struct login_(?:source|client) \*entry = &?([^;]+);/g, 'let entry = $1;')
        .replace(/struct login_client \*client = ([^;]+);/g, 'let client = $1;')
        .replace(/struct login_client \*client;/g, 'let client;')
        .replace(/unsigned long now =/g, 'let now =')
        .replace(/unsigned long activity =/g, 'let activity =')
        .replace(/\(unsigned long\)/g, '')
        .replace(/->/g, '.')
        .replace(/sizeof\([^)]*\)/g, '0')
        .replace(/\*elapsed/g, 'elapsed.value');
    if (name === 'login_source_get' || name === 'login_client_get') {
        body = body.slice(body.indexOf('\n\tfor (index'));
        body = `{ let address = ${name === 'login_source_get' ? 'networkAddress(currentAddress)' : 'currentAddress'}, now = uptime(), scope = currentScope, slot = null, index;` + body;
        body = body.replace(/&login_sources/g, 'login_sources')
            .replace(/&login_clients/g, 'login_clients')
            .replace(/\bNULL\b/g, 'null')
            .replace(/strlcpy\(slot.address, address, 0\);/, 'slot.address = address;');
    }
    return `function ${name}(${parameters}) ${body}`;
}
const empty = () => ({ address: '', scope: -1, failures: 0, error_status: 0, last_failure: 0, blocked_at: 0 });
const emptyClient = () => ({ address: '', scope: -1, failures: 0, last_failure: 0, last_success: 0 });
function networkAddress(address) {
    if (address.includes('.')) return address.split('.').slice(0, 3).join('.') + '.0';
    const [head, tail = ''] = address.split('::');
    const left = head ? head.split(':') : [];
    const right = tail ? tail.split(':') : [];
    const groups = [...left, ...Array(8 - left.length - right.length).fill('0'), ...right];
    return groups.slice(0, 4).join(':') + '::';
}
const notifications = [];
const context = vm.createContext({
    now: 100, currentAddress: '192.168.1.2', currentScope: 0, LOGIN_SOURCE_LIMIT: limit,
    LOGIN_CLIENT_LIMIT: 256, MAX_LOGIN_BLOCK_TIME: 300, DEFAULT_LOGIN_MAX_NUM: 5, LOGINLOCK: 7, ACCOUNTFAIL: 3,
    login_sources: Array.from({ length: limit }, empty),
    login_clients: Array.from({ length: 256 }, emptyClient),
    networkAddress,
    uptime: () => context.now,
    httpd_login_notify: address => notifications.push(address),
    strcmp: (left, right) => left === right ? 0 : 1,
    memset: entry => Object.assign(entry, Object.hasOwn(entry, 'blocked_at') ? empty() : emptyClient())
});
vm.runInContext([
    translated('login_source_get', 'create'),
    translated('login_client_get', 'create'),
    translated('httpd_login_attempts', ''),
    translated('httpd_login_status', 'elapsed'),
    translated('httpd_login_failed', 'error_status'),
    translated('httpd_login_reset', '')
].join('\n'), context);
context.now = 100;
const elapsed = { value: 0 };
context.currentAddress = '192.168.1.99';
context.httpd_login_reset();
for (let attempt = 1; attempt <= 5; ++attempt) {
    context.currentAddress = `192.168.1.${attempt}`;
    assert.equal(context.httpd_login_failed(3), attempt === 5 ? 7 : 3);
}
assert.deepEqual(notifications, ['192.168.1.0']);
assert.equal(context.httpd_login_status(elapsed), 7);
context.currentAddress = '192.168.1.100';
assert.equal(context.httpd_login_status(elapsed), 7, 'address rotation cannot bypass an aggregated subnet lock');
context.currentAddress = '192.168.1.99';
assert.equal(context.httpd_login_status(elapsed), 0, 'a recently successful host retains a login path');
assert.equal(context.httpd_login_attempts(), 5, 'rotating hosts share the subnet failure count');
context.currentScope = 1;
assert.equal(context.httpd_login_status(elapsed), 0, 'WAN failure state is isolated from the same LAN source range');
assert.equal(context.httpd_login_attempts(), 0);
context.currentScope = 0;
context.currentAddress = '192.168.1.100';
context.httpd_login_failed(10);
assert.equal(context.httpd_login_status(elapsed), 7, 'a failed reserved attempt is locked on subsequent requests');
context.httpd_login_reset();
context.currentAddress = '192.168.1.100';
assert.equal(context.httpd_login_attempts(), 0);
assert.equal(context.httpd_login_status(elapsed), 0, 'recently successful exact clients retain a reserved path');
context.now += 299;
assert.equal(context.httpd_login_status(elapsed), 0);
context.now += 1;
assert.equal(context.httpd_login_status(elapsed), 0);
assert.equal(context.httpd_login_attempts(), 0);
for (let attempt = 1; attempt <= 5; ++attempt) {
    context.currentAddress = `2001:db8::${attempt}`;
    context.httpd_login_failed(3);
}
context.currentAddress = '2001:db8::6';
assert.equal(context.httpd_login_status(elapsed), 7, 'address rotation cannot bypass an aggregated IPv6 /64 lock');
assert.equal(context.httpd_login_attempts(), 5);
context.currentAddress = '2001:db8::5';
assert.equal(context.httpd_login_status(elapsed), 7);
context.now = 1;
assert.equal(context.httpd_login_status(elapsed), 0);
for (let index = 0; index <= limit; ++index) {
    context.currentAddress = `2001:db8:${index + 1}::1`;
    context.httpd_login_failed(3);
}
context.currentAddress = '192.168.1.3';
assert.equal(context.httpd_login_status(elapsed), 0);
assert.equal(context.login_sources.length, limit);
assert.match(source, /IN6_IS_ADDR_V4MAPPED\(addr\)/);
assert.match(source, /memset\(&ipv6\.s6_addr\[8\], 0, 8\)/);
assert.match(source, /htonl\(ntohl\(ipv4\.s_addr\) & 0xffffff00U\)/);
assert.match(source, /login_peer_address\(1, address, sizeof\(address\)\)/);
assert.match(source, /login_peer_address\(0, address, sizeof\(address\)\)/);
assert.match(source, /entry->scope == scope && !strcmp\(entry->address, address\)/);

const translatedCaptchaMatcher = captchaMatcher
    .replace(/int matched;/, 'let matched;')
    .replace(/char saved_user_agent\[sizeof\(user_agent\)\];/, 'let saved_user_agent;')
    .replace(/strlcpy\(saved_user_agent, user_agent, sizeof\(saved_user_agent\)\);/, 'saved_user_agent = user_agent;')
    .replace(/strlcpy\(user_agent, "Mozilla\/5\.0", sizeof\(user_agent\)\);/, 'user_agent = "Mozilla/5.0";')
    .replace(/strlcpy\(user_agent, saved_user_agent, sizeof\(user_agent\)\);/, 'user_agent = saved_user_agent;');
Object.assign(context, {
    FROM_DUTUtil: 2,
    user_agent: '',
    is_captcha_match: captchaText => context.user_agent !== 'asusrouter-Android-DUTUtil-1.0' && captchaText === 'valid' ? 1 : 0
});
vm.runInContext(`function translatedCaptchaMatcher(captcha_text, fromapp_flag) ${translatedCaptchaMatcher}`, context);
for (const [userAgent, fromApp] of [['asusrouter-Android-DUTUtil-1.0', 2], ['Mozilla/5.0', 0]]) {
    context.user_agent = userAgent;
    assert.equal(context.translatedCaptchaMatcher('invalid', fromApp), 0);
    assert.equal(context.user_agent, userAgent, 'the request User-Agent is restored after CAPTCHA validation');
    assert.equal(context.translatedCaptchaMatcher('valid', fromApp), 1);
    assert.equal(context.user_agent, userAgent, 'the request User-Agent is restored after CAPTCHA validation');
}
let passwordChecks = 0;
function loginAttempt(attempts, userAgent, captchaText) {
    const fromApp = userAgent === 'asusrouter-Android-DUTUtil-1.0' ? context.FROM_DUTUtil : 0;
    context.user_agent = userAgent;
    if (attempts >= captchaLimit && !context.translatedCaptchaMatcher(captchaText, fromApp))
        return 'WRONGCAPTCHA';
    passwordChecks++;
    return 'PASSWORD_CHECKED';
}
assert.equal(loginAttempt(captchaLimit - 1, 'asusrouter-Android-DUTUtil-1.0', ''), 'PASSWORD_CHECKED');
assert.equal(loginAttempt(captchaLimit, 'asusrouter-Android-DUTUtil-1.0', ''), 'WRONGCAPTCHA');
assert.equal(passwordChecks, 1, 'the third attempt without CAPTCHA never evaluates the password');
assert.equal(loginAttempt(captchaLimit, 'asusrouter-Android-DUTUtil-1.0', 'valid'), 'PASSWORD_CHECKED');

context.httpd_login_reset();
context.now = 1000;
context.currentAddress = '192.168.3.99';
context.httpd_login_reset();
for (const [index, userAgent] of ['browser', 'asusrouter-a-DUTUtil-1', 'WebView', 'ASSIA', 'browser'].entries()) {
    context.userAgent = userAgent;
    context.currentAddress = `192.168.3.${index + 1}`;
    context.httpd_login_failed(3);
}
assert.equal(context.httpd_login_status(elapsed), 7);
context.currentAddress = '192.168.3.50';
assert.equal(context.httpd_login_status(elapsed), 7);
context.currentAddress = '192.168.3.99';
assert.equal(context.httpd_login_status(elapsed), 0, 'the recent successful client remains admitted');
context.currentAddress = '192.168.3.50';
for (let attempt = 0; attempt < 4; ++attempt) context.httpd_login_failed(3);
context.now += 300;
assert.equal(context.httpd_login_attempts(), 0);
assert.equal(context.httpd_login_failed(3), 3);
assert.equal(context.httpd_login_attempts(), 1);

for (let index = 0; index < 40; ++index) {
    context.currentAddress = `192.168.2.${index + 1}`;
    for (let attempt = 0; attempt < 4; ++attempt)
        context.httpd_login_failed(3);
}
context.currentAddress = '192.168.1.99';
assert.equal(context.httpd_login_status(elapsed), 0,
    'failures across rotating sources do not lock out another client');

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
context.currentAddress = '192.168.4.51';
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
assert.match(requestDeadlineStop, /if \(!request_headers_complete \|\| request_deadline_body\)\s*httpd_slowloris_record_timeout\(&request_peer\)/);
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

assert.match(sharedBudgetSource, /shared_login_attempt_admit\(enum login_budget_scope scope, unsigned int \*retry_after\)/);
assert.match(fs.readFileSync(path.join(root, 'release/src/router/dropbear/src/svr-authpasswd.c'), 'utf8'),
    /shared_login_attempt_admit\(LOGIN_BUDGET_SSH, &retry_after\)/);

const sharedBudgetCapacity = Number(sharedBudgetSource.match(/#define LOGIN_BUDGET_CAPACITY (\d+)/)[1]);
const sharedBudgetRefill = Number(sharedBudgetSource.match(/#define LOGIN_BUDGET_REFILL_SECONDS (\d+)/)[1]);
const scopedBudgets = new Map();
function admitScopedBudget(scope, now) {
    let budget = scopedBudgets.get(scope);
    if (!budget) {
        budget = { tokens: sharedBudgetCapacity, lastRefill: now };
        scopedBudgets.set(scope, budget);
    }
    if (now < budget.lastRefill) {
        budget.tokens = sharedBudgetCapacity;
        budget.lastRefill = now;
    } else if (budget.tokens < sharedBudgetCapacity) {
        const periods = Math.floor((now - budget.lastRefill) / sharedBudgetRefill);
        if (periods) {
            budget.tokens = Math.min(sharedBudgetCapacity, budget.tokens + periods);
            budget.lastRefill += periods * sharedBudgetRefill;
        }
    }
    if (!budget.tokens) return false;
    budget.tokens--;
    return true;
}
for (let attempt = 0; attempt < sharedBudgetCapacity; ++attempt)
    assert(admitScopedBudget('LAN', 100));
assert.equal(admitScopedBudget('LAN', 100), false, 'the exhausted LAN failure bucket throttles');
assert(admitScopedBudget('WAN', 100), 'WAN failures have an independent bucket');
assert(admitScopedBudget('SSH', 100), 'SSH retains a separate bucket');

const networkFailures = new Map();
const hostFailures = new Map();
const successfulHosts = new Map();
function ipv4Network(address) {
    return address.split('.').slice(0, 3).join('.') + '.0';
}
function ipv6Network(address) {
    return address.split(':').slice(0, 4).join(':') + '::/64';
}
function failLogin(network, host) {
    networkFailures.set(network, Math.min(captchaLimit + 3,
        (networkFailures.get(network) || 0) + 1));
    hostFailures.set(host, Math.min(captchaLimit + 3, (hostFailures.get(host) || 0) + 1));
}
failLogin('192.168.10.0', '192.168.10.9');
assert.equal(networkFailures.get('192.168.10.0'), 1,
    'a request rejected by the shared budget is still counted against its source');
function canTryLockedNetwork(network, host, now) {
    return (networkFailures.get(network) || 0) < budgetCapacity ||
        (successfulHosts.has(host) && now - successfulHosts.get(host) < 300);
}
const budgetCapacity = Number(header.match(/#define DEFAULT_LOGIN_MAX_NUM\s+(\d+)/)[1]);
const attackedNetwork = ipv4Network('192.168.10.1');
for (let index = 1; index <= 6; ++index)
    failLogin(attackedNetwork, `192.168.10.${index}`);
assert.equal(networkFailures.get(attackedNetwork), budgetCapacity);
assert(!canTryLockedNetwork(attackedNetwork, '192.168.10.2', 100),
    'a previously failing client remains locked despite address rotation');
assert(!canTryLockedNetwork(attackedNetwork, '192.168.10.99', 100),
    'a new address cannot bypass a locked subnet');
successfulHosts.set('192.168.10.99', 100);
failLogin(attackedNetwork, '192.168.10.1');
assert(canTryLockedNetwork(attackedNetwork, '192.168.10.99', 200),
    'a recently successful admin client retains a password-verification path');
assert(canTryLockedNetwork('192.168.11.0', '192.168.11.99', 200),
    'a source network with no failures retains its normal login path');
assert.equal(ipv6Network('2001:db8:abcd:1234::1'), ipv6Network('2001:db8:abcd:1234::beef'),
    'IPv6 addresses within one /64 share a source identity');
assert.notEqual(ipv4Network('192.168.10.1'), ipv4Network('192.168.11.1'),
    'different IPv4 /24 sources remain independent');
assert.doesNotMatch(login, /Retry-After|retry_after\\"/,
    'web login throttling exposes no exact refill time');

console.log('httpd login lockout and slowloris ban: subnet-scoped failures, reserved success path, isolated LAN/WAN/SSH budgets, no Retry-After (source contracts/model; not compiled C)');