const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const httpd = read('release/src/router/httpd/httpd.c');
const web = read('release/src/router/httpd/web.c');
const header = read('release/src/router/httpd/httpd.h');
const hook = web.slice(web.indexOf('static int ej_update_variables('), web.indexOf('\n}', web.indexOf('static int ej_update_variables(')) + 2);
const guard = hook.indexOf('if (!httpd_check_request_origin())\n\t\treturn 0;');
assert(guard >= 0);
for (const operation of ['validate_apply(', 'notify_rc(', 'nvram_set', 'killall(', 'kill_pidfile_s(']) {
    assert(hook.indexOf(operation) > guard, operation);
}
assert.match(header, /extern int httpd_check_request_origin\(void\);/);
assert.match(header, /extern int httpd_check_csrf_token\(const char \*token\);/);
assert.match(httpd, /value_length > 0 && value_length < sizeof\(token\)/);
assert.match(httpd, /strlen\(token\) == strlen\(expected\)/);
const request = httpd.slice(httpd.indexOf('handle_request(void)\n{'));
assert(request.indexOf('request_referer = NULL;') < request.indexOf('fgets('));
assert.match(request, /referer = cp;\s*request_referer = referer;/);
assert.match(request, /Origin:", 7\s*\)[\s\S]*?request_origin = cp;/);
const requestOriginGuard = request.indexOf('!httpd_check_request_origin()');
assert(requestOriginGuard > request.indexOf('auth_result = auth_check('));
assert(requestOriginGuard < request.indexOf('handler->input(file, conn_fp, cl, boundary)'));

const dispatchGuard = request.match(/if \(\(handler->input \|\| \(do_referer & CHECK_REFERER\) \|\| strstr\(url, "\.cgi"\)\) &&\s*!httpd_check_request_origin\(\) && !httpd_check_csrf_token\(csrf_token\)\)/);
assert(dispatchGuard, 'All authenticated input/CGI handlers require origin or session token, regardless of method/UA');
const postOnlyGuard = request.match(/if \(strcasecmp\(method, "post"\) != 0 &&\s*\(match\("feedback_mail\.cgi\*", url\) \|\|\s*match\("enable_remote_control\.cgi\*", url\) \|\|\s*match\("block_device_internet\.cgi\*", url\) \|\|\s*match\("chpass\.cgi\*", url\)\)\)/);
assert(postOnlyGuard);
assert(request.indexOf(postOnlyGuard[0]) < request.indexOf('handler->input(file, conn_fp, cl, boundary)'));
const disabledFeedback = request.indexOf('#ifndef RTCONFIG_FRS_FEEDBACK');
assert(disabledFeedback > request.indexOf(postOnlyGuard[0]));
assert(disabledFeedback < request.indexOf('handler->input(file, conn_fp, cl, boundary)'));
assert.match(request.slice(disabledFeedback), /if \(match\("feedback_mail.cgi\*", url\)\) \{\s*send_error\(403/);
assert.match(request, /csrf_header_seen \|\| !token_length \|\| token_length >= sizeof\(csrf_token\)/);
assert.match(request, /strncasecmp\(cur, "X-CSRF-Token:", 13\)/);
const tokenExpression = httpd.match(/httpd_check_csrf_token\(const char \*token\)\s*\{[\s\S]*?return ([^;]+);/)[1];
const tokenAllowed = new Function('token', 'expected', `
    const strlen = value => value.length;
    const strcmp = (left, right) => left === right ? 0 : 1;
    return ${tokenExpression.replace('*expected', 'expected.length')};`);
for (const [token, expected, allowed] of [
    [null, 'session', false], ['', 'session', false], ['other', 'session', false],
    ['session-extra', 'session', false], ['session', '', false], ['session', 'session', true]
]) assert.equal(Boolean(tokenAllowed(token, expected)), allowed);
const originDenied = new Function('handler', 'do_referer', 'url', 'originOK', 'tokenOK',
    `const CHECK_REFERER = 1;
     const strstr = (value, part) => value.includes(part);
     const httpd_check_request_origin = () => originOK;
     const httpd_check_csrf_token = () => tokenOK;
     const csrf_token = '';
     return ${dispatchGuard[0].slice(4, -1).replaceAll('handler->input', 'handler.input')};`);
const postDenied = new Function('method', 'url',
    `const strcasecmp = (left, right) => left.toLowerCase() === right.toLowerCase() ? 0 : 1;
     const match = (pattern, value) => pattern.endsWith('*') ? value.startsWith(pattern.slice(0, -1)) : pattern === value;
     return ${postOnlyGuard[0].slice(4, -1)};`);
for (const url of ['feedback_mail.cgi', 'feedback_mail.cgi?http_passwd_app=X',
    'enable_remote_control.cgi', 'block_device_internet.cgi', 'chpass.cgi']) {
    for (const method of ['GET', 'HEAD', 'POST']) {
        for (const fromapp of [false, true]) {
            for (const originOK of [false, true]) {
                for (const tokenOK of [false, true]) {
                    const nvram = { http_passwd_app: 'unchanged', sshd_authkeys: 'unchanged', misc_http_x: '0' };
                    let firewall = 0;
                    const denied = originDenied({ input: true }, 0, url, originOK, tokenOK) || postDenied(method, url);
                    if (!denied) { nvram.misc_http_x = '1'; firewall++; }
                    assert.equal(denied, method !== 'POST' || (!originOK && !tokenOK), `${url} ${method} app=${fromapp}`);
                    if (denied) {
                        assert.deepEqual(nvram, { http_passwd_app: 'unchanged', sshd_authkeys: 'unchanged', misc_http_x: '0' });
                        assert.equal(firewall, 0);
                    }
                }
            }
        }
    }
}
assert(originDenied({ input: false }, 0, 'renew_ikev2_cert_key.cgi', false, false));
assert(originDenied({ input: true }, 0, 'start_apply.htm', false, false));
assert(!originDenied({ input: false }, 0, 'static.css', false, false));

const feedback = web.match(/do_feedback_mail_safe_cgi\(char \*url, FILE \*stream\)\n\{([\s\S]*?)\n\}/)[1];
assert.match(header, /extern void send_error\( int status, char\* title, char\* extra_header, char\* text \);/);
assert.match(httpd, /\nvoid\nsend_error\( int status, char\* title, char\* extra_header, char\* text \)/);
assert.doesNotMatch(httpd, /static void\s+send_error\s*\(/);
assert.match(web, /"feedback_mail.cgi\*"[^\n]+do_feedback_mail_safe_cgi, do_auth/);
assert.doesNotMatch(feedback, /validate_apply|do_feedback_mail_cgi|do_apply_cgi/);
assert.match(feedback, /#ifndef RTCONFIG_FRS_FEEDBACK\s*send_error\(403[^\n]+\n#else/);
const fields = [...feedback.matchAll(/\{ "(fb_[^"]+)", (\d+) \}/g)].map(([, name, limit]) => [name, Number(limit)]);
assert(fields.length > 20);
for (const forbidden of ['http_passwd_app', 'sshd_authkeys', 'misc_http_x', 'fb_email_dbg', 'fb_state']) {
    assert(!fields.some(([name]) => name === forbidden), forbidden);
}
assert.match(feedback, /nvram_set\(fields\[field\]\.name, value\)/);
assert(feedback.indexOf('goto invalid;') < feedback.indexOf('nvram_set('));
function feedbackModel(params, enabled) {
    const state = { http_passwd_app: 'old', sshd_authkeys: 'old', misc_http_x: '0' };
    if (!enabled) return state;
    for (const [name, limit] of fields) {
        if (params[name] !== undefined && params[name].length > limit) return state;
    }
    for (const [name] of fields) {
        if (params[name] !== undefined) state[name] = params[name];
    }
    state.fb_state = '0';
    return state;
}
const maliciousFeedback = { fb_email: 'a@b.cd', fb_attach_syslog: '1',
    http_passwd_app: 'X', sshd_authkeys: 'key', misc_http_x: '1', fb_email_dbg: 'attacker@example.com' };
for (const enabled of [false, true]) {
    const state = feedbackModel(maliciousFeedback, enabled);
    assert.equal(state.http_passwd_app, 'old');
    assert.equal(state.sshd_authkeys, 'old');
    assert.equal(state.misc_http_x, '0');
    assert(!Object.hasOwn(state, 'fb_email_dbg'));
    assert.equal(state.fb_email, enabled ? 'a@b.cd' : undefined);
}
for (const [name, limit] of fields) {
    assert.deepEqual(feedbackModel({ ...maliciousFeedback, [name]: 'x'.repeat(limit + 1) }, true),
        { http_passwd_app: 'old', sshd_authkeys: 'old', misc_http_x: '0' });
}
assert.match(read('release/src/router/www/js/httpApi.js'), /url: '\/chpass.cgi',\s*type: 'POST'/);
for (const page of ['Advanced_Smart_Home_IFTTT.asp', 'Advanced_Smart_Home_Alexa.asp']) {
    const control = read(`release/src/router/www/${page}`).match(/function enable_remote_control\(\)\{([\s\S]*?)\n\}/)[1];
    let options;
    const callback = () => {};
    new Function('confirm', '$', 'hide_remote_control', control)(() => true, { ajax: value => { options = value; } }, callback);
    assert.equal(options.url, '/enable_remote_control.cgi');
    assert.equal(options.type, 'POST');
    assert.equal(options.success, callback);
}

function requestOriginAllowed(origin, referer, routerHost) {
    if (origin !== null && !origin) return false;
    const value = origin !== null ? origin : referer;
    if (!value) return false;
    try {
        return new URL(value).host === routerHost;
    } catch {
        return false;
    }
}
const router = '192.168.1.1';
for (const template of ['wlconn_apply.htm', 'diskmon_test.asp', 'start_apply.htm']) {
    assert.match(read(`release/src/router/www/${template}`), /<%\s*update_variables\(/);
    for (const [origin, referer, expected] of [
        [null, null, false],
        ['', `http://${router}/Advanced_System_Content.asp`, false],
        ['https://attacker.example', `http://${router}/Advanced_System_Content.asp`, false],
        ['http://192.168.1.1.attacker.example', null, false],
        [`http://${router}`, null, true],
        [null, `http://${router}/Advanced_System_Content.asp`, true],
        [null, 'http://192.168.1.1@attacker.example/', false]
    ]) {
        assert.equal(requestOriginAllowed(origin, referer, router), expected,
            `${template}, Origin=${origin}, Referer=${referer}`);
    }
}
for (const source of [httpd, web]) {
    const cookies = [...source.matchAll(/"Set-Cookie: ([^"\n]+)"/g)];
    assert.equal(cookies.length, 1);
    assert.match(cookies[0][1], /%s; SameSite=Strict\\r\\n/);
}

const uploadPost = web.slice(web.indexOf('do_upload_server_ovpn_cert_post('), web.indexOf('\nstatic void\ndo_upload_server_ovpn_cert_cgi', web.indexOf('do_upload_server_ovpn_cert_post(')));
assert(uploadPost.indexOf('httpd_check_csrf_token(post_buf)') < uploadPost.indexOf('mkdir(OPENVPN_UPLOAD_FLODER'));
assert(uploadPost.indexOf('httpd_check_csrf_token(post_buf)') < uploadPost.indexOf('open(upload_fifo'));
assert.match(uploadPost, /O_CREAT \| O_EXCL \| O_NOFOLLOW/);
assert.match(uploadPost, /name=\\\"csrf_token\\\"/);
assert.match(uploadPost, /pending_length == marker_length/);
assert.match(uploadPost, /boundary_found/);
assert.match(read('release/src/router/www/Advanced_VPN_OpenVPN.asp'), /name="csrf_token" value="<% httpd_csrf_token\(\); %>"/);
const uploadAjax = read('release/src/router/www/js/httpApi.js').match(/"uploadServerOvpnCert": function\(postData, handler\)\s*\{([\s\S]*?)\n\t\},/)[1];
assert.match(uploadAjax, /formData\.append\('csrf_token', document\.import_cert_form\.csrf_token\.value\)/);

const extractor = web.match(/openvpn_extract_server_cert_archive\(int unit\)\n\{([\s\S]*?)\n\}/)[1];
assert.match(extractor, /header\[156\] != '\\0' && header\[156\] != '0'/);
assert.match(extractor, /O_CREAT \| O_EXCL \| O_NOFOLLOW/);
assert.match(extractor, /total_size > 102400 - size/);
assert.doesNotMatch(extractor, /system\(|tar -xzf/);
assert.match(web, /"ca", "ca_key", "client_crt", "client_key", "crt",\s*"dh", "key", "crl", "extra", "static"/);
assert.match(web, /if \(openvpn_extract_server_cert_archive\(unit\) == 0\) \{[\s\S]*?eval\("mv"/);
const uploadOutput = web.slice(web.indexOf('do_upload_server_ovpn_cert_cgi('), web.indexOf('\n#endif\t//RTCONFIG_OPENVPN', web.indexOf('do_upload_server_ovpn_cert_cgi(')));
const invalidTokenReturn = uploadOutput.indexOf('if (!openvpn_upload_csrf_valid)');
assert(invalidTokenReturn >= 0 && invalidTokenReturn < uploadOutput.indexOf('doSystem("rm -rf %s", OPENVPN_UPLOAD_FLODER)'));

const allowedTypes = ['ca', 'ca_key', 'client_crt', 'client_key', 'crt', 'dh', 'key', 'crl', 'extra', 'static'];
function tarEntry(name, type, data = '', link = '') {
    const header = Buffer.alloc(512);
    header.write(name, 0, 100, 'ascii');
    header.write('0000600\0', 100, 8, 'ascii');
    header.write('0000000\0', 108, 8, 'ascii');
    header.write('0000000\0', 116, 8, 'ascii');
    header.write(data.length.toString(8).padStart(11, '0') + '\0', 124, 12, 'ascii');
    header.write('00000000000\0', 136, 12, 'ascii');
    header.fill(0x20, 148, 156);
    header[156] = type.charCodeAt(0);
    header.write(link, 157, 100, 'ascii');
    const checksum = header.reduce((sum, value) => sum + value, 0);
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
    const payload = Buffer.from(data);
    const padding = Buffer.alloc((512 - payload.length % 512) % 512);
    return Buffer.concat([header, payload, padding]);
}
function archive(entries) {
    return zlib.gzipSync(Buffer.concat([...entries, Buffer.alloc(1024)]));
}
function modelSafeExtract(gzip, unit) {
    const tar = zlib.gunzipSync(gzip);
    const extracted = [];
    const seen = new Set();
    let offset = 0;
    let total = 0;
    try {
        while (offset + 512 <= tar.length) {
            const header = tar.subarray(offset, offset + 512);
            offset += 512;
            if (header.every(byte => byte === 0)) break;
            const name = header.subarray(0, 100).toString('ascii').split('\0', 1)[0];
            const type = header[156];
            if (type !== 0 && type !== 0x30) return { ok: false, extracted: [] };
            const suffix = allowedTypes.find(candidate => name === `vpn_crt_server${unit}_${candidate}`);
            if (!suffix || seen.has(name)) return { ok: false, extracted: [] };
            const size = parseInt(header.subarray(124, 136).toString('ascii').replace(/\0.*$/, '').trim(), 8);
            if (!Number.isFinite(size) || size < 0 || total + size > 102400 || offset + size > tar.length) {
                return { ok: false, extracted: [] };
            }
            seen.add(name);
            extracted.push(name);
            total += size;
            offset += size + ((512 - size % 512) % 512);
        }
        return { ok: extracted.length > 0, extracted };
    } catch {
        return { ok: false, extracted: [] };
    }
}
assert.deepEqual(modelSafeExtract(archive([tarEntry('vpn_crt_server1_ca', '0', 'certificate')]), 1), {
    ok: true, extracted: ['vpn_crt_server1_ca']
});
for (const members of [
    [tarEntry('d', '2', '', '/tmp/x'), tarEntry('d/f', '0', 'escape')],
    [tarEntry('d', '1', '', '/tmp/x'), tarEntry('vpn_crt_server1_ca', '0', 'certificate')],
    [tarEntry('d', '5')],
    [tarEntry('../etc/passwd', '0', 'escape')],
    [tarEntry('not_a_certificate', '0', 'ignored')]
]) {
    assert.deepEqual(modelSafeExtract(archive(members), 1), { ok: false, extracted: [] });
}
console.log('httpd CSRF and OpenVPN upload: source contracts and source-derived checks passed (native C and device behavior not executed)');
