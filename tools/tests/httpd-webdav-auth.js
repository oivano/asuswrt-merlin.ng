#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const repo = path.resolve(__dirname, '../..');
const web = fs.readFileSync(path.join(repo, 'release/src/router/httpd/web.c'), 'utf8');
const httpd = fs.readFileSync(path.join(repo, 'release/src/router/httpd/httpd.c'), 'utf8');

const route = web.match(/\{\s*"get_webdavInfo\.asp"[^\n]*\}/);
assert(route, 'missing get_webdavInfo.asp MIME handler');
assert.match(route[0], /do_ej,\s*do_auth\s*\}/,
    'get_webdavInfo.asp must authenticate before rendering the disclosure hook');

const authCheck = httpd.indexOf('if (handler->auth) {');
const checkCredentials = httpd.indexOf('auth_result = auth_check(url, file, cookies, fromapp, &add_try);', authCheck);
const rejectUnauthenticated = httpd.indexOf('send_login_page(fromapp, auth_result, url, file, auth_check_dt, add_try);', checkCredentials);
const rejectReturn = httpd.indexOf('return;', rejectUnauthenticated);
assert(authCheck !== -1 && checkCredentials > authCheck && rejectUnauthenticated > checkCredentials &&
    rejectReturn > rejectUnauthenticated,
    'authenticated MIME handlers must reject failed auth before continuing dispatch');

for (const disclosure of ['ddns_hostname_x', 'wan0_ipaddr', 'firmver', 'buildno', 'get_lan_hwaddr()', 'get_label_mac()']) {
    assert(web.includes(disclosure), `expected WebDAV info disclosure marker ${disclosure}`);
}

console.log('httpd WebDAV-info authentication contract passed');