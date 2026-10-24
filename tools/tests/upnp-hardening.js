const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const miniupnpd = fs.readFileSync(path.join(root, 'release/src/router/miniupnpd/miniupnpd.c'), 'utf8');
const arrays = fs.readFileSync(path.join(root, 'release/src/router/httpd/data_arrays.c'), 'utf8');
const page = fs.readFileSync(path.join(root, 'release/src/router/www/Main_IPTStatus_Content.asp'), 'utf8');

assert.match(services, /static int upnp_config_dir_ready\(void\)[\s\S]*?lstat\("\/etc\/upnp"[\s\S]*?S_ISDIR\(st\.st_mode\)[\s\S]*?st\.st_uid != 0[\s\S]*?chmod\("\/etc\/upnp", 0700\)/);
assert.match(services, /static int upnp_config_file_trusted\(const char \*path\)[\s\S]*?lstat\(path, &st\) == 0 && S_ISREG\(st\.st_mode\)[\s\S]*?st\.st_uid == 0 && !\(st\.st_mode & 022\)/);
assert.match(services, /old_umask = umask\(077\);[\s\S]*?upnp_config_dir_ready\(\)/);
assert.match(services, /open\("\/etc\/upnp\/config", O_WRONLY \| O_CREAT \| O_EXCL, 0600\)/);
assert.match(services, /upnp_config_file_trusted\("\/etc\/upnp\/config\.alt"\)/);
assert.match(services, /upnp_config_file_trusted\("\/etc\/upnp\/config\.custom"\)/);
assert(services.includes('"/etc/upnp/upnp.leases"'));
assert(!services.includes('"/tmp/upnp.leases"'));
assert.match(miniupnpd, /umask\(077\);[\s\S]*?#ifndef NO_BACKGROUND_NO_PIDFILE[\s\S]*?daemon\(0, 0\)/);

const serializer = arrays.slice(arrays.indexOf('static int websWriteJsonString('), arrays.indexOf('\n#include "httpd.h"'));
assert.match(serializer, /case '<': ret \+= websWrite\(wp, "\\\\u003c"\)/);
assert.match(serializer, /case '>': ret \+= websWrite\(wp, "\\\\u003e"\)/);
assert.match(serializer, /case '&': ret \+= websWrite\(wp, "\\\\u0026"\)/);
assert.match(serializer, /case '\/': ret \+= websWrite\(wp, "\\\\\/"\)/);

const showUpnp = page.match(/function show_upnp\(\) \{[\s\S]*?\n\}/)[0];
for (const field of [0, 1, 2, 3, 5])
    assert(showUpnp.includes(`htmlEnDeCode.htmlEncode(line[${field}]`), `UPnP field ${field} must be HTML-encoded`);

const upnpBlock = { innerHTML: '' };
const context = {
	htmlEnDeCode: {
		htmlEncode: value => String(value).replace(/[&<>"']/g, character => ({
			'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
		})[character])
	},
	document: { getElementById: () => upnpBlock }
};
vm.createContext(context);
vm.runInContext(`${showUpnp}\nString.prototype.shorter = function(length) { return this.substring(0, length); };`, context);
for (const payload of [
	'<img src=x onerror=alert(1)>',
	'</script><svg onload=alert(1)>',
	'plain description'
]) {
	context.upnparray = [['<svg>', '<img>', '</script>', '<tag>', '60', payload], []];
	context.show_upnp();
	const output = upnpBlock.innerHTML;
	if (payload.startsWith('<')) {
		assert(!output.includes(payload));
		assert(output.includes('&lt;'));
	} else {
		assert(output.includes(payload));
	}
}

console.log('PASS: UPnP config hardening, script-context serialization, and lease rendering');