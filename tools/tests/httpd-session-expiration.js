const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.c'), 'utf8');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const limit = Number(source.match(/#define BROWSER_SESSION_LIMIT (\d+)/)[1]);
const maximum = vm.runInNewContext(source.match(/#define BROWSER_SESSION_MAX_AGE (.*)/)[1].replace(/UL/g, ''));
assert.equal(maximum, 86400);
function body(text, name) {
    const matches = [...text.matchAll(new RegExp(`(?:^|\\n)(?:static\\s+)?(?:void|int)\\s*${name}\\s*\\([^;]*\\)\\s*\\{`, 'g'))];
    assert(matches.length, name);
    const start = matches[matches.length - 1].index + matches[matches.length - 1][0].lastIndexOf('{');
    return text.slice(start, text.indexOf('\n}', start) + 2);
}

const classification = source.indexOf('fromapp = check_user_agent(useragent);');
const expiration = source.indexOf('browser_session_expire();', classification);
const authentication = source.indexOf('auth_result = auth_check(');
assert(expiration > classification && expiration < authentication);
const takeover = body(source, 'http_login_timeout');
const originCheck = body(source, 'httpd_check_request_origin');
const authenticatedSession = body(source, 'browser_session_authenticated');
assert.match(takeover, /browser_session_authenticated\(cookies\)/);
assert.doesNotMatch(takeover, /http_logout\(/);
assert.doesNotMatch(takeover, /referer_host|delete_logout_from_list|browser_session_forget/);
assert.match(authenticatedSession, /session && session->authenticated/);
assert.match(originCheck, /session->authenticated && session->referer_host\[0\]/);
assert.match(originCheck, /strlcpy\(referer_host, session->referer_host/);
assert.match(originCheck, /strlcpy\(referer_host, saved_referer_host/);
const logout = body(source, 'http_logout');
assert.match(logout, /fromapp_flag == 0 && !browser_session_authenticated\(cookies\)\)\s*return/);
assert.match(logout, /browser_session_forget\(cookies\)/);
const failedAuth = source.slice(authentication).match(/if \(auth_result != 0\)\s*\{([\s\S]*?)\n\t{5}\}/);
assert(failedAuth);
assert.match(failedAuth[1], /return;/);
assert.doesNotMatch(failedAuth[1], /browser_session_touch/);
assert(source.indexOf('browser_session_touch(cookies);', authentication) >
    authentication + failedAuth.index + failedAuth[0].length);
assert.match(source, /gen_asus_token_cookie\([^;]+;\s*browser_session_register\(asus_token, fromapp, 0\);/);
assert.match(web, /gen_asus_token_cookie\([^;]+;\s*browser_session_register\(asus_token, fromapp_flag, 1\);/);
assert.equal((source.match(/gen_asus_token_cookie\(/g) || []).length, 1);
assert.equal((web.match(/gen_asus_token_cookie\(/g) || []).length, 1);

for (const extension of ['png', 'conf']) {
    const route = web.match(new RegExp(`\\{ "wgs_client\\.${extension}",([^}]+)\\}`));
    assert(route, `WireGuard ${extension} download route exists`);
    const fields = route[1].split(',').map(field => field.trim());
    assert.equal(fields[2], 'NULL');
    assert.equal(fields[3], `do_wgs_client_${extension}`);
    assert.equal(fields[4], 'do_auth', `WireGuard ${extension} download requires authentication`);
}
const authGate = source.indexOf('if (handler->auth) {');
const outputCall = source.indexOf('handler->output(file, conn_fp);', authentication);
assert(authGate >= 0 && authGate < authentication);
assert(outputCall > authentication + failedAuth.index + failedAuth[0].length);

function translated(name, parameters) {
    const start = source.indexOf(`\n${name}(`);
    assert(start >= 0, name);
    const body = source.slice(source.indexOf('{', start), source.indexOf('\n}', start) + 2)
        .replace(/^#(?:ifdef RTCONFIG_HTTPS|endif).*$/gm, '')
        .replace(/asus_token_t \*entry = head, \*previous = NULL;/, 'let entry = head, previous = null;')
        .replace(/struct browser_session \*(\w+) = &?([^;]+);/g, 'let $1 = $2;')
        .replace(/const char \*name = "asus_token", \*value;/, 'let name = "asus_token", value;')
        .replace(/(?:unsigned long|int|size_t) (\w+)/g, 'let $1')
        .replace(/\(unsigned long\)/g, '')
        .replace(/\bNULL\b/g, 'null')
        .replace(/\b(\d+)UL\b/g, '$1')
        .replace(/sizeof\([^)]*\)/g, '0')
        .replace(/->/g, '.')
        .replace(/!\*token/g, '!token[0]')
        .replace(/value \+= strlen\(name\) \+ 1;/, 'value = value.slice(strlen(name) + 1);')
        .replace(/strlcpy\(slot.token, token, 0\);/, 'slot.token = token;')
        .replace(/strlcpy\(slot.referer_host, referer_host, 0\);/, 'slot.referer_host = referer_host;');
    return `function ${name}(${parameters}) ${body}`;
}

function fixture() {
    const freed = new Set();
    const context = vm.createContext({
        now: 100, minutes: 30, do_ssl: false, head: null, curr: null, referer_host: 'router.asus.com',
        BROWSER_SESSION_LIMIT: limit, BROWSER_SESSION_MAX_AGE: maximum,
        browser_sessions: Array.from({ length: limit }, () => ({ token: '', created: 0, active: 0 })),
        uptime: () => context.now,
        nvram_get_int: () => context.minutes,
        strcmp: (left, right) => left === right ? 0 : 1,
        strncmp: (left, right, length) => left.slice(0, length) === right.slice(0, length) ? 0 : 1,
        strlen: value => value.length,
        strstr: (value, needle) => value.includes(needle) ? value.slice(value.indexOf(needle)) : null,
        strspn: (value, characters) => {
            let length = 0;
            while (length < value.length && characters.includes(value[length])) ++length;
            return length;
        },
        memset: session => Object.assign(session, { token: '', created: 0, active: 0 }),
        free: entry => { assert(!freed.has(entry)); freed.add(entry); }
    });
    vm.runInContext([
        translated('browser_session_remove', 'session'),
        translated('browser_session_expire', ''),
        translated('browser_session_register', 'token, fromapp, authenticated'),
        translated('browser_session_find', 'token'),
        translated('browser_session_touch', 'cookies')
    ].join('\n'), context);
    const mint = (token, fromapp = 0, authenticated = true) => {
        const entry = { token, next: null };
        if (context.curr) context.curr.next = entry;
        else context.head = entry;
        context.curr = entry;
        context.browser_session_register(token, fromapp, authenticated);
        return entry;
    };
    const request = (cookies, valid = true) => {
        context.browser_session_expire();
        const token = (cookies || '').match(/asus_(?:s_)?token=([A-Za-z0-9]+)/)?.[1];
        let entry = context.head;
        while (entry && entry.token !== token) entry = entry.next;
        if (!entry || !valid) return false;
        context.browser_session_touch(cookies);
        return true;
    };
    return { context, mint, request, freed };
}

let test = fixture();
test.mint('anonymous', 0, false);
test.mint('admin', 0, true);
assert.equal(test.context.browser_session_find('anonymous').authenticated, false,
    'a token issued before login cannot trigger idle takeover');
assert.equal(test.context.browser_session_find('admin').authenticated, true,
    'a token minted after successful login is eligible for takeover');
test.context.referer_host = 'attacker.example';
assert.equal(test.context.browser_session_find('admin').referer_host, 'router.asus.com');
test = fixture();
const stale = test.mint('stale');
test.context.now += 1800;
assert.equal(test.request('asus_token=stale'), false);
assert(test.freed.has(stale));
assert.equal(test.context.head, null);
assert.equal(test.context.curr, null);
assert(test.context.browser_sessions.every(session => !session.token));

test = fixture();
test.mint('active');
test.context.now += 1799;
assert(test.request('other=1; asus_token=active; other=2'));
test.context.now += 1799;
assert(test.request('asus_token=active'));
test.context.now += 1800;
assert.equal(test.request('asus_token=active'), false);

test = fixture();
test.mint('denied');
test.context.now += 1799;
assert.equal(test.request('asus_token=denied', false), false);
test.context.now += 1;
assert.equal(test.request('asus_token=denied'), false);

test = fixture();
test.context.minutes = 0;
test.mint('capped');
for (test.context.now = 101; test.context.now < 100 + maximum; test.context.now += 1000)
    assert(test.request('asus_token=capped'));
test.context.now = 100 + maximum;
assert.equal(test.request('asus_token=capped'), false);

test = fixture();
test.mint('https');
test.context.do_ssl = true;
test.context.now += 1799;
assert(test.request('asus_s_token=https'));
test.context.now += 1800;
test.context.do_ssl = false;
assert.equal(test.request('asus_token=https'), false);

test = fixture();
const first = test.mint('first');
const middle = test.mint('middle');
const last = test.mint('last');
test.context.now += 100;
test.context.browser_session_touch('unrelated=middle; asus_token=first');
const middleSlot = test.context.browser_sessions.find(session => session.token === 'middle');
assert.equal(middleSlot.active, 100);
assert.equal(test.context.browser_sessions.find(session => session.token === 'first').active, 200);
test.context.browser_session_remove(middleSlot);
assert.equal(first.next, last);
assert.equal(test.context.curr, last);
test.context.browser_session_remove(test.context.browser_sessions.find(session => session.token === 'last'));
assert.equal(test.context.curr, first);
assert.equal(first.next, null);
test.context.browser_session_remove(test.context.browser_sessions.find(session => session.token === 'first'));
assert.equal(test.context.head, null);
assert.equal(test.context.curr, null);
assert(test.freed.has(middle));

test = fixture();
test.mint('older');
test.context.now += 1000;
test.mint('newer');
test.context.now += 800;
assert.equal(test.request('asus_token=older'), false);
assert(test.request('asus_token=newer'));
test.context.minutes = 1;
test.context.now += 60;
assert.equal(test.request('asus_token=newer'), false);

test = fixture();
test.mint('app', 1);
test.mint('browser');
test.context.now += 1800;
test.context.browser_session_expire();
assert.equal(test.context.head.token, 'app');
assert.equal(test.context.curr.token, 'app');
assert.equal(test.context.head.next, null);

test = fixture();
test.mint('evicted');
for (let index = 1; index <= limit; ++index) {
    test.context.now += 1;
    test.mint(`token${index}`);
}
assert.equal(test.request('asus_token=evicted'), false);
assert(test.request(`asus_token=token${limit}`));

test = fixture();
test.mint('rollback');
test.context.now = 99;
assert.equal(test.request('asus_token=rollback'), false);

test = fixture();
test.context.minutes = 2147483647;
test.mint('bounded');
test.context.now += 999 * 60;
assert.equal(test.request('asus_token=bounded'), false);

test = fixture();
test.context.minutes = -1;
test.mint('negative');
test.context.now += maximum;
assert.equal(test.request('asus_token=negative'), false);

console.log('httpd session expiration: source contracts and source-derived lifecycle checks passed (not compiled C)');