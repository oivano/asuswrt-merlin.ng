#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const repo = path.resolve(__dirname, '../..');
const httpd = fs.readFileSync(path.join(repo, 'release/src/router/httpd/httpd.c'), 'utf8');
const web = fs.readFileSync(path.join(repo, 'release/src/router/httpd/web.c'), 'utf8');
const wwwMakefile = fs.readFileSync(path.join(repo, 'release/src/router/www/Makefile'), 'utf8');

function functionBody(source, signature) {
	const start = source.indexOf(signature);
	assert.notStrictEqual(start, -1, `missing ${signature}`);
	const open = source.indexOf('{', start);
	let depth = 0;
	for (let index = open; index < source.length; index++) {
		if (source[index] === '{') depth++;
		if (source[index] === '}' && --depth === 0) return source.slice(open + 1, index);
	}
	assert.fail(`unterminated ${signature}`);
}

const openHelper = functionBody(httpd, 'static int httpd_open_webroot_file(');
assert.match(openHelper, /realpath\(requested, resolved\)/);
assert.match(openHelper, /strncmp\(resolved, "\/www\/", 5\)/);
assert.match(openHelper, /httpd_open_addon_file\(path\)/);
assert.match(openHelper, /openat\(dirfd, component, O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK/);
assert.match(openHelper, /S_ISREG\(st\.st_mode\)/);
assert.match(openHelper, /st\.st_uid != 0/);
assert.match(openHelper, /S_IWGRP \| S_IWOTH/);
const addonOpen = functionBody(httpd, 'static int httpd_open_addon_file(');
assert.match(addonOpen, /strncmp\(path, "user\/", 5\)/);
assert.match(addonOpen, /strncmp\(path, "ext\/", 4\)/);
assert.match(addonOpen, /open\("\/tmp\/var\/wwwext", O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(addonOpen, /openat\(dirfd, alias, O_RDONLY \| O_DIRECTORY \| O_NONBLOCK\)/);
assert.match(addonOpen, /openat\(dirfd, component, O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK/);
assert.match(addonOpen, /strcmp\(component, "\.\."\)/);
assert.match(web, /\{ "\*\*\.htm\*", "text\/html"[^\n]*do_ej/);
assert.match(web, /\{ "\*\*\.css", "text\/css"[^\n]*do_file/);
assert.match(web, /\{ "\*\*\.png", "image\/png"[^\n]*do_file/);

assert(httpd.includes('handler->output == do_file && !httpd_web_file_exists(file)'),
	'static do_file routes must fail before response headers');
assert(httpd.includes('handler->output != do_file && !check_if_file_exist(file)'),
	'static dispatch must not use the symlink-following existence check');
const fallbackCondition = httpd.match(/if\((!strstr\(file, "\.cgi"\)[^\n]+)\r?\n#ifdef RTCONFIG_USB_MODEM/);
assert(fallbackCondition, 'missing fallback file rejection condition');
const rejectsFile = new Function('file', 'handler', 'do_file', 'check_if_file_exist', 'strstr',
	`return ${fallbackCondition[1].replace(/handler->output/g, 'handler.output')};`);
const staticHandler = {};
for (const file of ['index_style.css', 'js/jquery.js', 'require/require.min.js', 'images/loading.gif']) {
	assert.strictEqual(rejectsFile(file, { output: staticHandler }, staticHandler,
		() => assert.fail('validated static file must bypass the legacy existence check'),
		(value, needle) => value.includes(needle)), false, `${file} must not receive a fallback 404`);
}
for (const exists of [false, true]) {
	assert.strictEqual(rejectsFile('index.asp', { output: {} }, staticHandler,
		() => exists, (value, needle) => value.includes(needle)), !exists,
		'template requests must retain their existence check');
}
const doFile = functionBody(httpd, 'void do_file(char *path, FILE *stream)');
assert.match(doFile, /httpd_open_webroot_file\(_path\)/);
assert.match(doFile, /do_fwrite\(buf, nr, stream\) < 0/);
assert(!/ln -sf \/tmp\/fb_data\.tgz\.gz/.test(wwwMakefile),
	'feedback-disabled image must not install a writable-/tmp web-root link');

function containedRegularFile(root, candidate) {
	let resolved;
	try {
		resolved = fs.realpathSync(candidate);
	} catch (_) {
		return false;
	}
	const rootPath = fs.realpathSync(root);
	if (!resolved.startsWith(`${rootPath}${path.sep}`)) return false;
	try {
		return fs.statSync(resolved).isFile();
	} catch (_) {
		return false;
	}
}

function containedAddonFile(alias, candidate) {
	let aliasTarget;
	let resolved;
	try {
		aliasTarget = fs.realpathSync(alias);
		resolved = fs.realpathSync(candidate);
	} catch (_) {
		return false;
	}
	try {
		if (fs.statSync(aliasTarget).isDirectory()) {
			return resolved.startsWith(`${aliasTarget}${path.sep}`);
		}
		return resolved === aliasTarget;
	} catch (_) {
		return false;
	}
}

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'httpd-static-file-'));
try {
	const root = path.join(temp, 'www');
	const outside = path.join(temp, 'outside');
	const wwwext = path.join(temp, 'wwwext');
	const addon = path.join(temp, 'addon', 'webui', 'diversion');
	fs.mkdirSync(root);
	fs.mkdirSync(wwwext);
	fs.mkdirSync(addon, { recursive: true });
	fs.writeFileSync(path.join(root, 'safe.gz'), 'safe');
	fs.writeFileSync(outside, 'secret');
	fs.writeFileSync(path.join(addon, 'home.html'), 'home');
	fs.symlinkSync(outside, path.join(addon, 'outside.html'));
	fs.symlinkSync(addon, path.join(wwwext, 'diversion'));
	fs.symlinkSync('safe.gz', path.join(root, 'internal-link.gz'));
	fs.symlinkSync(outside, path.join(root, 'fb_data.tgz.gz'));
	fs.symlinkSync('/dev/zero', path.join(root, 'zero.gz'));
	assert(containedRegularFile(root, path.join(root, 'safe.gz')));
	assert(containedRegularFile(root, path.join(root, 'internal-link.gz')));
	assert(containedAddonFile(path.join(wwwext, 'diversion'),
		path.join(wwwext, 'diversion', 'home.html')));
	assert(!containedAddonFile(path.join(wwwext, 'diversion'),
		path.join(wwwext, 'diversion', 'outside.html')));
	assert(!containedAddonFile(path.join(wwwext, 'diversion'), outside),
		'add-on symlinks must not escape their registered alias target');
	assert(!containedRegularFile(root, path.join(root, 'fb_data.tgz.gz')));
	assert(!containedRegularFile(root, path.join(root, 'zero.gz')));
	console.log('httpd static-file source contracts and containment cases passed');
} finally {
	fs.rmSync(temp, { recursive: true, force: true });
}