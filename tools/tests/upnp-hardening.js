const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const miniupnpd = fs.readFileSync(path.join(root, 'release/src/router/miniupnpd/miniupnpd.c'), 'utf8');
const arrays = fs.readFileSync(path.join(root, 'release/src/router/httpd/data_arrays.c'), 'utf8');
const page = fs.readFileSync(path.join(root, 'release/src/router/www/Main_IPTStatus_Content.asp'), 'utf8');
const soap = fs.readFileSync(path.join(root, 'release/src/router/miniupnpd/upnpsoap.c'), 'utf8');

const rangeDelete = soap.slice(soap.indexOf('\nDeletePortMappingRange('), soap.indexOf('\nGetGenericPortMappingEntry('));
const deleteLoop = rangeDelete.match(/for\(i = 0; i < number; i\+\+\)[\s\S]*?\n\t\}\n\tfree\(port_list\);/)[0];
assert.match(deleteLoop, /if\(GETFLAG\(SECUREMODEMASK\)\)/);
assert.match(deleteLoop, /upnp_get_redirection_infos\(port_list\[i\], protocol, &iport,/);
assert.match(deleteLoop, /if\(r < 0 \|\| inet_pton\(AF_INET, int_ip, &int_ip_addr\) != 1 \|\|\s*h->clientaddr\.s_addr != int_ip_addr\.s_addr\)\s*continue;/);
assert(deleteLoop.indexOf('continue;') < deleteLoop.indexOf('upnp_delete_redirection('));

const runDeleteLoop = vm.runInNewContext(`(function(h, secure, protocol, port_list, lookup, remove) {
	let i, r;
	const number = port_list.length, action = 'DeletePortMappingRange';
	const SECUREMODEMASK = 1, AF_INET = 2, NULL = null, LOG_INFO = 0;
	const GETFLAG = () => secure;
	const upnp_get_redirection_infos = lookup;
	const upnp_delete_redirection = remove;
	const syslog = () => {};
	const free = () => {};
	const inet_pton = (family, text, address) => {
		if (!/^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$/.test(text.value) ||
			text.value.split('.').some(part => Number(part) > 255)) return 0;
		address.s_addr = text.value;
		return 1;
	};
	${deleteLoop
		.replace('char int_ip[32];', 'const int_ip = {};')
		.replace('struct in_addr int_ip_addr;', 'const int_ip_addr = {};')
		.replace('unsigned short iport;', 'const iport = {};')
		.replace('unsigned int leaseduration = 0;', 'const leaseduration = {};')
		.replace('sizeof(int_ip)', '32')
		.replace(/&(iport|leaseduration|int_ip_addr)\b/g, '$1')
		.replace(/->/g, '.')}
})`);

for (const protocol of ['TCP', 'UDP']) {
	for (const secure of [false, true]) {
		const mappings = new Map([
			[4000, '192.168.1.10'],
			[4001, '192.168.1.20'],
			[4002, '192.168.1.10'],
			[4003, 'invalid'],
			[4004, '192.168.1.20']
		]);
		const removed = [];
		let lookups = 0;
		runDeleteLoop({ clientaddr: { s_addr: '192.168.1.20' } }, secure, protocol,
			[...mappings.keys()], (port, transport, internalPort, internalAddress) => {
				assert.equal(transport, protocol);
				lookups++;
				internalAddress.value = mappings.get(port);
				return port === 4004 ? -1 : 0;
			}, (port, transport) => {
				assert.equal(transport, protocol);
				removed.push(port);
				mappings.delete(port);
				return 0;
			});
		assert.deepEqual(removed, secure ? [4001] : [4000, 4001, 4002, 4003, 4004], protocol);
		assert.equal(lookups, secure ? 5 : 0);
		if (secure) {
			assert.equal(mappings.get(4000), '192.168.1.10', `${protocol}: victim mapping must remain reserved`);
			assert.equal(mappings.get(4002), '192.168.1.10');
			assert(mappings.has(4003), 'invalid owner must not authorize deletion');
			assert(mappings.has(4004), 'lookup failure must not authorize deletion');
		}
	}
}

const methods = soap.slice(soap.indexOf('soapMethods[] ='), soap.indexOf('#ifdef ENABLE_L3F_SERVICE', soap.indexOf('soapMethods[] =')));
assert.match(methods, /#ifdef IGD_V2\s*\{ "AddAnyPortMapping", AddAnyPortMapping\},\s*\{ "DeletePortMappingRange", DeletePortMappingRange\},\s*\{ "GetListOfPortMappings", GetListOfPortMappings\},\s*#endif/);
for (const version2 of [false, true]) {
	const registered = methods.replace(/#ifdef IGD_V2\n([\s\S]*?)#endif[^\n]*/g, (_, actions) => version2 ? actions : '');
	for (const action of ['AddAnyPortMapping', 'DeletePortMappingRange', 'GetListOfPortMappings'])
		assert.equal(registered.includes(`"${action}"`), version2, action);
	assert(registered.includes('"DeletePortMapping"'));
}

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

console.log('PASS: UPnP range-delete ownership, IGD action registration, config hardening, serialization, and lease rendering');