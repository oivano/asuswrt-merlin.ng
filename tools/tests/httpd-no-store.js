const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');

assert.match(web, /static char no_cache\[\]\s*=\s*"Cache-Control: no-store\\r\\n"\s*"Pragma: no-cache"/);
assert.doesNotMatch(web, /\bno_cache_IE7\b/);

for (const route of [
    'login.cgi',
    'apply.cgi*',
    'appGet.cgi*',
    '**.asp*',
    '**.htm*',
    '**.js',
    '**.json'
]) {
    const escaped = route.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    assert.match(web, new RegExp(`\\{ "${escaped}",[^\\n]*, no_cache,`), `${route} uses no_cache`);
}

console.log('PASS: dynamic httpd routes use the static no-store response header');
