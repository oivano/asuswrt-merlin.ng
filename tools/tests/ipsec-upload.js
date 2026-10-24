const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const web = read('release/src/router/httpd/web.c');
const httpd = read('release/src/router/httpd/httpd.c');
const header = read('release/src/router/httpd/httpd.h');
const body = name => web.match(new RegExp(`${name}\\([^\\n]*\\)\\n\\{([\\s\\S]*?)\\n\\}`))[1];

const validator = body('ipsec_upload_profile_valid')
    .replace('const char *digit;', 'let digit;')
    .replace('strncmp(value, "ipsec_profile_", 14)', '(value.slice(0, 14) === "ipsec_profile_" ? 0 : 1)')
    .replaceAll('strlen(value)', 'value.length')
    .replace('for (digit = value + 14; *digit; digit++)', 'for (digit = 14; digit < value.length; digit++)')
    .replaceAll('*digit', 'value[digit]');
const valid = new Function('value', validator);
for (const value of ['ipsec_profile_1', 'ipsec_profile_12345', `ipsec_profile_${'9'.repeat(17)}`]) {
    assert.equal(valid(value), 1, value);
    assert(`/jffs/ipsec/${value}.crt`.length < 64);
}
for (const value of ['', '../..////etc/shadow', '/etc/shadow', 'ipsec_profile_',
    'ipsec_profile_1/../../etc/shadow', 'ipsec_profile_1..', 'ipsec_profile_1.crt',
    'ipsec_profile_-1', 'ipsec_profile_1 ', 'ipsec_profile_1\n',
    'ipsec_profile_\u0661', `ipsec_profile_${'1'.repeat(18)}`]) {
    assert.equal(valid(value), 0, value);
}

const upload = body('do_ipsecupload_post');
assert.doesNotMatch(upload, /nvram_set\(name,|fopen\(|F_SETOWN/);
assert.match(upload, /nvram_set\("ipsec_profile_item", profile\)/);
assert(upload.indexOf('ipsec_upload_profile_valid(post_buf)') < upload.indexOf('mkstemp('));
assert(upload.indexOf('if (!boundary_found)') < upload.indexOf('rename('));
assert(upload.indexOf('rename(') < upload.indexOf('nvram_set('));
assert.match(header, /extern int httpd_ipsec_upload_ok\(void\);/);
assert.match(web, /"ipsecupload.cgi\*"[^\n]+do_ipsecupload_post, do_ipsecupload_cgi, do_auth/);
const request = httpd.slice(httpd.indexOf('handle_request(void)\n{'));
const inputPosition = request.indexOf('handler->input(file, conn_fp, cl, boundary)');
assert(request.indexOf('!httpd_ipsec_upload_ok()') > inputPosition);
assert(request.indexOf('!httpd_ipsec_upload_ok()') < request.indexOf('send_headers( 200,'));
assert.match(request, /match\("ipsecupload.cgi\*", url\) && !httpd_ipsec_upload_ok\(\)\) \{\s*send_error\(400/);
const dispatchGuard = request.match(/if \(\(handler->input \|\| \(do_referer & CHECK_REFERER\) \|\| strstr\(url, "\.cgi"\)\) &&\s*!httpd_check_request_origin\(\) && !httpd_check_csrf_token\(csrf_token\)\)/);
assert(dispatchGuard && request.indexOf(dispatchGuard[0]) < inputPosition);
const denied = new Function('originOK', 'tokenOK', `
    const handler = { input: true }, do_referer = 0, CHECK_REFERER = 1;
    const url = 'ipsecupload.cgi', csrf_token = '';
    const strstr = (value, part) => value.includes(part);
    const httpd_check_request_origin = () => originOK;
    const httpd_check_csrf_token = () => tokenOK;
    return ${dispatchGuard[0].slice(4, -1).replaceAll('handler->input', 'handler.input')};`);
assert(denied(false, false), 'Foreign/missing origin with only a session cookie must fail before input');
assert(!denied(true, false));
assert(!denied(false, true), 'Explicit session CSRF headers remain supported');

// Execute the source handler's control flow with mocked C I/O, not native C.
const translated = upload
    .replace('char upload_fifo[64];', 'let upload_fifo = "";')
    .replace('char temporary[] =', 'let temporary =')
    .replace('char marker[256];', 'let marker = "";')
    .replace('char profile[32] =', 'let profile =')
    .replace('FILE *fifo = NULL;', 'let fifo = null;')
    .replace('int ch, fd = -1;', 'let ch, fd = -1;')
    .replace('int path_length;', 'let path_length;')
    .replace('int boundary_found = 0, headers_found = 0;', 'let boundary_found = 0, headers_found = 0;')
    .replace('struct stat directory;', 'let directory = {};')
    .replace('char *end;', 'let end;')
    .replaceAll('sizeof(post_buf)', '4096')
    .replaceAll('sizeof(marker)', '256')
    .replaceAll('sizeof(profile)', '32')
    .replaceAll('sizeof(upload_fifo)', '64')
    .replaceAll('memset(post_buf, 0, 4096);', 'post_buf = "";')
    .replaceAll('!*boundary', '!boundary.length')
    .replaceAll('!*profile', '!profile.length')
    .replaceAll('*profile', 'profile.length')
    .replace('snprintf(marker, 256, "--%s", boundary);', 'marker = "--" + boundary;')
    .replaceAll('fgets(post_buf, MIN(len + 1, 4096), stream)', '(post_buf = fgets(MIN(len + 1, 4096), stream))')
    .replace('end = strstr(post_buf, "\\r\\n");', 'end = post_buf.indexOf("\\r\\n");')
    .replace("!end || end[2] != '\\0'", 'end < 0 || end + 2 !== post_buf.length')
    .replace("*end = '\\0';", 'post_buf = post_buf.slice(0, end);')
    .replace('strlcpy(profile, post_buf, 32);', 'profile = post_buf;')
    .replace('path_length = snprintf(upload_fifo, 64, "/jffs/ipsec/%s.crt", profile);',
        'upload_fifo = "/jffs/ipsec/" + profile + ".crt"; path_length = upload_fifo.length;')
    .replaceAll('&directory', 'directory')
    .replaceAll('post_buf + strlen(marker)', 'post_buf.slice(marker.length)')
    .replaceAll('NULL', 'null')
    .replaceAll('goto err;', 'throw rejected;');
const [operations, cleanup] = translated.split('\nerr:');
assert(operations && cleanup);
const run = new Function('api', 'stream', 'len', 'boundary', `
    with (api) {
        const rejected = {};
        let post_buf = '', ipsec_upload_complete = 0;
        ${operations.slice(0, operations.indexOf('ipsec_upload_complete = 0;'))}
        try {
            ${operations.slice(operations.indexOf('ipsec_upload_complete = 0;'))}
        } catch (error) {
            if (error !== rejected) throw error;
        } finally {
            ${cleanup}
        }
        return Boolean(ipsec_upload_complete);
    }`);

function execute(payload, options = {}) {
    const stream = { payload, offset: 0 };
    const staged = new Map();
    const files = new Map([['/jffs/ipsec/ipsec_profile_1.crt', 'old certificate']]);
    const nvram = { ipsec_profile_item: 'old', http_passwd: 'unchanged' };
    let creations = 0;
    const api = {
        EEXIST: 17, errno: 17, EOF: -1, MIN: Math.min,
        strlen: value => value.length,
        strcmp: (left, right) => left === right ? 0 : 1,
        strcasecmp: (left, right) => left.toLowerCase() === right.toLowerCase() ? 0 : 1,
        strncmp: (left, right, length) => left.slice(0, length) === right.slice(0, length) ? 0 : 1,
        strncasecmp: (left, right, length) => left.slice(0, length).toLowerCase() === right.slice(0, length).toLowerCase() ? 0 : 1,
        strstr: (value, part) => value.includes(part),
        ipsec_upload_profile_valid: valid,
        fgets(limit, input) {
            if (input.offset >= input.payload.length) return null;
            const newline = input.payload.indexOf('\n', input.offset);
            const end = Math.min(input.offset + limit - 1, newline < 0 ? input.payload.length : newline + 1);
            const result = input.payload.slice(input.offset, end);
            input.offset = end;
            return result;
        },
        fgetc: input => input.offset < input.payload.length ? input.payload.charCodeAt(input.offset++) : -1,
        lstat(name, directory) {
            directory.st_mode = options.unsafeDirectory === name ? 0o120777 : 0o040700;
            directory.st_uid = 0;
            return 0;
        },
        S_ISDIR: mode => (mode & 0o170000) === 0o040000,
        mkdir: () => 0,
        mkstemp(name) { creations++; staged.set(name, ''); return 3; },
        fdopen: () => options.fdopenFailure ? null : { name: '/jffs/ipsec/.upload-XXXXXX' },
        close: () => 0,
        fputs(data, output) {
            if (options.writeFailure) return -1;
            staged.set(output.name, staged.get(output.name) + data);
            return 0;
        },
        fclose: () => options.closeFailure ? -1 : 0,
        rename(from, to) {
            if (options.renameFailure) return -1;
            files.set(to, staged.get(from)); staged.delete(from); return 0;
        },
        unlink: name => staged.delete(name),
        nvram_set: (key, value) => { nvram[key] = value; }
    };
    const ok = run(api, stream, payload.length, options.boundary === undefined ? 'test-boundary' : options.boundary);
    assert.equal(staged.size, 0, 'Temporary uploads must always be cleaned up');
    return { ok, files, nvram, creations };
}
const part = (name, value, extra = '') =>
    `--test-boundary\r\nContent-Disposition: form-data; ${extra}name="${name}"\r\n\r\n${value}\r\n`;
const certificate = '-----BEGIN CERTIFICATE-----\r\nTEST\r\n-----END CERTIFICATE-----';
const file = part('file', certificate).replace('name="file"', 'name="file"; filename="test.crt"');
const finish = '--test-boundary--\r\n';
const good = part('ipsec_profile_item', 'ipsec_profile_1') + file + finish;
const accepted = execute(good);
assert(accepted.ok);
assert.equal(accepted.files.get('/jffs/ipsec/ipsec_profile_1.crt'), certificate + '\r\n');
assert.deepEqual(accepted.nvram, { ipsec_profile_item: 'ipsec_profile_1', http_passwd: 'unchanged' });
for (const payload of [
    part('ipsec_profile_item', '../..////etc/shadow') + file + finish,
    part('ipsec_profile_item', 'ipsec_profile_1', 'x="http_passwd"; ') + file + finish,
    part('ipsec_profile_item', 'ipsec_profile_1') + part('ipsec_profile_item', 'ipsec_profile_2') + file + finish,
    file + finish,
    part('ipsec_profile_item', 'ipsec_profile_1') + finish,
    good.replace(finish, ''),
    good.replace('ipsec_profile_1\r\n', 'ipsec_profile_1/traversal\r\n')
]) {
    const result = execute(payload);
    assert(!result.ok, payload);
    assert.equal(result.files.get('/jffs/ipsec/ipsec_profile_1.crt'), 'old certificate');
    assert.deepEqual(result.nvram, { ipsec_profile_item: 'old', http_passwd: 'unchanged' });
}
for (const options of [{ boundary: null }, { boundary: '' }, { boundary: 'x'.repeat(250) },
    { unsafeDirectory: '/jffs' }, { unsafeDirectory: '/jffs/ipsec' },
    { fdopenFailure: true }, { writeFailure: true }, { closeFailure: true }, { renameFailure: true }]) {
    const result = execute(good, options);
    assert(!result.ok, JSON.stringify(options));
    assert.equal(result.files.get('/jffs/ipsec/ipsec_profile_1.crt'), 'old certificate');
    assert.equal(result.nvram.ipsec_profile_item, 'old');
}
assert.equal(execute(part('ipsec_profile_item', '../..////etc/shadow') + file + finish).creations, 0);

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'ipsec-upload-'));
try {
    const outside = path.join(directory, 'outside');
    const destination = path.join(directory, 'ipsec_profile_1.crt');
    const temporary = path.join(directory, '.upload-test');
    fs.writeFileSync(outside, 'untouched');
    fs.symlinkSync(outside, destination);
    fs.writeFileSync(temporary, certificate, { flag: 'wx', mode: 0o600 });
    fs.renameSync(temporary, destination);
    assert.equal(fs.readFileSync(outside, 'utf8'), 'untouched');
    assert.equal(fs.readFileSync(destination, 'utf8'), certificate);
    assert.equal(fs.statSync(destination).mode & 0o777, 0o600);
} finally {
    fs.rmSync(directory, { recursive: true, force: true });
}
console.log('PASS: IPsec upload source-derived parser, fixed-key/CSRF contracts and host rename semantics (not native C or firmware)');