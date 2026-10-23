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
