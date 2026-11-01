const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const web = read('release/src/router/httpd/web.c');
const common = read('release/src/router/httpd/common.h');
const makefile = read('release/src/router/httpd/Makefile');
const captcha = read('release/src/router/httpd/libcaptcha.c');

const match = web.match(/static void do_captcha_file_memory\(char \*url, FILE \*stream\)\s*\{([\s\S]*?)\n\}/);
assert.ok(match, 'source-owned CAPTCHA output handler exists');
const handler = match[1];

assert.match(web, /\{ "captcha\.gif", "image\/gif", no_cache_IE7, NULL, do_captcha_file_memory, NULL \}/);
assert.doesNotMatch(web, /\bdo_captcha_file\s*\(/);
assert.match(web, /extern char cur_captcha\[6\]/);
assert.match(handler, /captcha\(image, text\)/);
assert.match(handler, /memcpy\(cur_captcha, text, sizeof\(cur_captcha\)\)/);
assert.match(handler, /makegif\(image, gif\)/);
assert.match(handler, /fwrite\(gif, 1, sizeof\(gif\), stream\)/);
assert.match(handler, /fflush\(stream\)/);
assert.doesNotMatch(handler, /fopen|open\s*\(|captcha\.gif|\/tmp/);
assert.match(common, /#define GIFSIZE\s+17646/);
assert.match(makefile, /ifeq \(\$\(RTCONFIG_CAPTCHA\),y\)[\s\S]*?OBJS \+= libcaptcha\.o/);
assert.match(captcha, /void captcha\(unsigned char im\[70\*200\], unsigned char l\[6\]\)/);
assert.match(captcha, /void makegif\(unsigned char im\[70\*200\], unsigned char gif\[GIFSIZE\]\)/);

console.log('PASS: captcha.gif is generated in memory and streamed without a temporary path');