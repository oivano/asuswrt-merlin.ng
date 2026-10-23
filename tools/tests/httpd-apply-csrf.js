const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const httpd = read('release/src/router/httpd/httpd.c');
const web = read('release/src/router/httpd/web.c');
const header = read('release/src/router/httpd/httpd.h');
const hook = web.slice(web.indexOf('static int ej_update_variables('), web.indexOf('\n}', web.indexOf('static int ej_update_variables(')) + 2);
const guard = hook.indexOf('if (!httpd_check_apply_origin())\n\t\treturn 0;');
assert(guard >= 0);
for (const operation of ['validate_apply(', 'notify_rc(', 'nvram_set', 'killall(', 'kill_pidfile_s(']) {
    assert(hook.indexOf(operation) > guard, operation);
}
assert.match(header, /extern int httpd_check_apply_origin\(void\);/);
const request = httpd.slice(httpd.indexOf('handle_request(void)\n{'));
assert(request.indexOf('request_referer = NULL;') < request.indexOf('fgets('));
assert.match(request, /referer = cp;\s*request_referer = referer;/);

const body = httpd.match(/httpd_check_apply_origin\(void\)\n\{([\s\S]*?)\n\}/)[1]
    .replace(/\bNULL\b/g, 'null')
    .replace(/\*request_referer != '\\0'/g, 'request_referer.length !== 0');
const router = '192.168.1.1';
for (const template of ['wlconn_apply.htm', 'diskmon_test.asp', 'start_apply.htm']) {
    assert.match(read(`release/src/router/www/${template}`), /<%\s*update_variables\(/);
    for (const referer of [null, '', 'https://attacker.example/', 'http://192.168.1.1.attacker.example/',
        'http://192.168.1.1@attacker.example/', `http://${router}/Advanced_System_Content.asp`]) {
        for (const fromapp of [0, 1]) {
            let calls = 0;
            const context = vm.createContext({
                request_referer: referer,
                referer_check: (value, app) => {
                    ++calls;
                    assert.equal(app, 0, 'UA classification must not bypass the guard');
                    return new URL(value).host === router ? 0 : 1;
                }
            });
            const allowed = vm.runInContext(`(function () { ${body} })()`, context);
            const mutations = [];
            if (allowed) mutations.push('validate_apply', 'notify_rc');
            const expected = referer === `http://${router}/Advanced_System_Content.asp`;
            assert.equal(Boolean(allowed), expected, `${template}, app=${fromapp}, Referer=${referer}`);
            assert.equal(mutations.length, expected ? 2 : 0);
            assert.equal(calls, referer ? 1 : 0);
        }
    }
}
for (const source of [httpd, web]) {
    const cookies = [...source.matchAll(/"Set-Cookie: ([^"\n]+)"/g)];
    assert.equal(cookies.length, 1);
    assert.match(cookies[0][1], /%s; SameSite=Strict\\r\\n/);
}
console.log('httpd apply CSRF: source contracts and source-derived guard checks passed (origin validator stubbed, not compiled C)');