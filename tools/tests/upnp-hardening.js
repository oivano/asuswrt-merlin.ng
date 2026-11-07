const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const firewall = fs.readFileSync(path.join(root, 'release/src/router/rc/firewall.c'), 'utf8');
const ovpnControl = fs.readFileSync(path.join(root, 'release/src/router/libovpn/openvpn_control.c'), 'utf8');
const portInUse = fs.readFileSync(path.join(root, 'release/src/router/miniupnpd/portinuse.c'), 'utf8');
const miniupnpd = fs.readFileSync(path.join(root, 'release/src/router/miniupnpd/miniupnpd.c'), 'utf8');
const natpmp = fs.readFileSync(path.join(root, 'release/src/router/miniupnpd/natpmp.c'), 'utf8');
const pcp = fs.readFileSync(path.join(root, 'release/src/router/miniupnpd/pcpserver.c'), 'utf8');
const redirect = fs.readFileSync(path.join(root, 'release/src/router/miniupnpd/upnpredirect.c'), 'utf8');
const iptRedirect = fs.readFileSync(path.join(root, 'release/src/router/miniupnpd/netfilter/iptcrdr.c'), 'utf8');
const arrays = fs.readFileSync(path.join(root, 'release/src/router/httpd/data_arrays.c'), 'utf8');
const page = fs.readFileSync(path.join(root, 'release/src/router/www/Main_IPTStatus_Content.asp'), 'utf8');
const soap = fs.readFileSync(path.join(root, 'release/src/router/miniupnpd/upnpsoap.c'), 'utf8');
const redirectHeader = fs.readFileSync(path.join(root, 'release/src/router/miniupnpd/upnpredirect.h'), 'utf8');
const lan = fs.readFileSync(path.join(root, 'release/src/router/rc/lan.c'), 'utf8');
const help = fs.readFileSync(path.join(root, 'release/src/router/www/help_content.js'), 'utf8');
assert(help.includes('NAT-PMP and PCP are disabled in this mode'));

assert.match(portInUse, /tcp6file = "\/proc\/net\/tcp6"/);
assert.match(portInUse, /udp6file = "\/proc\/net\/udp6"/);
assert.match(portInUse, /if \(!found\)[\s\S]*?proto == IPPROTO_TCP[\s\S]*?%\*32\[0-9A-Fa-f\]:%x[\s\S]*?tmp_port == eport/);
const ovpnNatWriter = ovpnControl.match(/void ovpn_write_nat_rules\(FILE \*fp\)[\s\S]*?\n\}/)[0];
assert.match(ovpnNatWriter, /unit <= OVPN_SERVER_MAX/);
assert.match(ovpnNatWriter, /port < 1 \|\| port > 65535/);
assert.match(ovpnNatWriter, /strcmp\(proto, "tcp"\).*strcmp\(proto, "udp"\)/);
assert.match(ovpnNatWriter, /-A PREROUTING -p %s --dport %d -j ACCEPT/);
const natBuilders = firewall.match(/void nat_setting2?\([\s\S]*?^\}/gm);
assert.equal(natBuilders.length, 2);
for (const natBuilder of natBuilders) {
	assert(natBuilder.indexOf('ovpn_write_nat_rules(fp);') < natBuilder.indexOf('-j VSERVER'));
}
const multiWanBuilder = natBuilders.find(natBuilder => natBuilder.startsWith('void nat_setting2('));
const multiWanWriter = multiWanBuilder.indexOf('ovpn_write_nat_rules(fp);');
assert(multiWanWriter > multiWanBuilder.indexOf('if (!fp)'));
assert(multiWanWriter < multiWanBuilder.indexOf('_dprintf("writting prerouting 2'));
const natRestore = services.slice(services.indexOf('int start_nat_rules(void)'), services.indexOf('\nint stop_nat_rules(void)'));
assert.match(natRestore, /eval\("iptables-restore", NAT_RULES\)/);
assert(!natRestore.includes('run_ovpn_fw_nat_scripts'));

const leaseReader = redirect.match(/static int\nlease_file_read_line\([\s\S]*?\n\}/)[0];
const leaseReloadStart = redirect.indexOf('int reload_from_lease_file(void)');
const leaseReloadEnd = redirect.indexOf('\n#ifdef LEASEFILE_USE_REMAINING_TIME\nvoid lease_file_rewrite', leaseReloadStart);
const leaseReload = redirect.slice(leaseReloadStart, leaseReloadEnd);
const leaseWriter = redirect.match(/static int\nlease_file_add\([\s\S]*?\n\}/)[0];
assert.match(leaseReader, /fgetc\(fd\)/);
assert.match(leaseReader, /length >= size - 1/);
assert.match(leaseReader, /c == '\\0'/);
assert.match(leaseReader, /if\s*\(invalid\)\s*return -1;/);
assert.match(leaseReload, /while\(\(r = lease_file_read_line\(fd, line, sizeof\(line\)\)\) != 0\)/);
assert.match(leaseReload, /if\s*\(r < 0\)[\s\S]*?continue;/);
assert(leaseReload.indexOf('if (r < 0)') < leaseReload.indexOf('r = upnp_redirect('));
assert(!leaseReload.includes('fgets(line'));
assert.match(leaseWriter, /desc_len < 63/);
assert.match(leaseWriter, /c != ':'/);
assert.match(leaseWriter, /c != 0x7f/);

const globalMappingLimit = Number(redirect.match(/#define UPNP_MAX_REDIRECTS (\d+)/)[1]);
const clientMappingLimit = Number(redirect.match(/#define UPNP_MAX_REDIRECTS_PER_CLIENT (\d+)/)[1]);
const redirectInternal = redirect.match(/int\nupnp_redirect_internal\([\s\S]*?\n\}/)[0];
assert.equal(globalMappingLimit, 256);
assert.equal(clientMappingLimit, 64);
assert(redirectHeader.includes('#define UPNP_REDIRECT_LIMIT_REACHED -5'));
assert.match(redirectInternal, /get_redirect_rule_counts\(iaddr, &rule_count, &per_client\) < 0 \|\|[\s\S]*?rule_count >= UPNP_MAX_REDIRECTS[\s\S]*?per_client >= UPNP_MAX_REDIRECTS_PER_CLIENT/);
const mappingCounter = iptRedirect.match(/get_redirect_rule_counts\(const char \* iaddr, int \* total, int \* per_client\)[\s\S]*?\n\}/)[0];
assert.match(mappingCounter, /iptc_init\("nat"\)/);
assert.match(mappingCounter, /iptc_first_rule\(miniupnpd_nat_chain/);
assert.match(mappingCounter, /\(\*total\)\+\+/);
assert.match(mappingCounter, /mr->range\[0\]\.min_ip == address\.s_addr/);
assert(redirectInternal.indexOf('UPNP_MAX_REDIRECTS_PER_CLIENT') < redirectInternal.indexOf('add_redirect_rule2('));
assert.match(leaseReload, /r = upnp_redirect\(rhost, eport, iaddr, iport, proto, desc, leaseduration\);/);
assert.match(redirectInternal, /add_redirect_rule2\(ext_if_name, rhost, eport, iaddr, iport, proto,/);
assert.match(natpmp, /upnp_redirect_internal\([\s\S]*?resp\[3\] = 3/);
assert.match(pcp, /upnp_redirect_internal\([\s\S]*?if \(r < 0\)\s*return PCP_ERR_NO_RESOURCES;/);
assert.match(soap, /case UPNP_REDIRECT_LIMIT_REACHED:\s*SoapError\(h, 728, "NoPortMapsAvailable"\);/);
assert.match(soap, /r != 0 && r != -1 && r != UPNP_REDIRECT_LIMIT_REACHED/);
assert.match(soap, /r == 0 \|\| r == -1 \|\| r == UPNP_REDIRECT_LIMIT_REACHED/);
assert(!soap.includes('gethostbyname('));
const internalClientGuards = [...soap.matchAll(/if \(inet_pton\(AF_INET, int_ip, &result_ip\) != 1\)\s*\{\s*ClearNameValueList\(&data\);\s*SoapError\(h, 402, "Invalid Args"\);\s*return;\s*\}/g)];
assert.equal(internalClientGuards.length, 2);
for (const guard of internalClientGuards) {
	const secureModeCheck = soap.indexOf('if(GETFLAG(SECUREMODEMASK))', guard.index);
	assert(secureModeCheck > guard.index);
}
const validateInternalClient = vm.runInNewContext(`(function(int_ip) {
	const AF_INET = 2, data = {}, h = {}, result_ip = {};
	let error = 0, cleared = false;
	const inet_pton = (family, text, address) => {
		if (!/^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$/.test(text) ||
			text.split('.').some(part => Number(part) > 255)) return 0;
		address.value = text;
		return 1;
	};
	const ClearNameValueList = () => { cleared = true; };
	const SoapError = (_h, code) => { error = code; };
	const guardResult = (function() {
	${internalClientGuards[0][0].replace('&result_ip', 'result_ip').replace('&data', 'data')}
		return true;
	})();
	return { error, cleared, address: result_ip.value, guardResult };
})`);
const rejectedInternalClient = validateInternalClient('router-attacker.example');
assert.equal(rejectedInternalClient.error, 402);
assert.equal(rejectedInternalClient.cleared, true);
assert.equal(rejectedInternalClient.guardResult, undefined);
const acceptedInternalClient = validateInternalClient('192.168.1.20');
assert.equal(acceptedInternalClient.error, 0);
assert.equal(acceptedInternalClient.cleared, false);
assert.equal(acceptedInternalClient.address, '192.168.1.20');
assert.equal(acceptedInternalClient.guardResult, true);
assert.match(firewall, /fprintf\(fp, "-A FORWARD -i %s ! -o %s -j FUPNP\\n", wan_if, wan_if\);/);
assert(!/fprintf\(fp, "-A FORWARD -j FUPNP\\n"\)/.test(firewall));

function canAddMapping(mappings, address) {
	if (mappings.length >= globalMappingLimit) return false;
	return mappings.filter(mapping => mapping === address).length < clientMappingLimit;
}
const oneHostAtLimit = Array(clientMappingLimit).fill('192.168.1.10');
assert(!canAddMapping(oneHostAtLimit, '192.168.1.10'));
assert(canAddMapping(oneHostAtLimit, '192.168.1.20'));
assert(canAddMapping([...oneHostAtLimit.slice(0, -1), ...Array(globalMappingLimit - clientMappingLimit).fill('192.168.1.20')], '192.168.1.10'));
assert(!canAddMapping(Array(globalMappingLimit).fill('192.168.1.20'), '192.168.1.10'));

function readLeaseRecords(input, capacity = 320) {
	const bytes = Buffer.from(input, 'latin1');
	const records = [];
	let offset = 0;
	while (offset < bytes.length) {
		const line = [];
		let invalid = false;
		while (offset < bytes.length && bytes[offset] !== 10) {
			const byte = bytes[offset++];
			if (byte === 0 || line.length >= capacity - 1) invalid = true;
			else if (!invalid) line.push(byte);
		}
		if (offset < bytes.length) offset++;
		if (!invalid) records.push(Buffer.from(line).toString('latin1'));
	}
	return records;
}

const injectedTail = 'TCP:8080:192.168.1.20:8080:0:x';
const boundaryPrefix = 'TCP:80:192.168.1.10:80:0:';
const boundaryPadding = 'd'.repeat(319 - Buffer.byteLength(boundaryPrefix));
const longLease = `${boundaryPrefix}${boundaryPadding}${injectedTail}`;
assert.equal(Buffer.byteLength(boundaryPrefix + boundaryPadding), 319);
const followingLease = 'UDP:5353:192.168.1.30:5353:0:valid';
assert.deepEqual(readLeaseRecords(`${longLease}\n${followingLease}\n`), [followingLease]);
assert.deepEqual(readLeaseRecords(`${'x'.repeat(319)}\n${followingLease}\n`), ['x'.repeat(319), followingLease]);
assert.deepEqual(readLeaseRecords(`TCP:80:192.168.1.10:80:0:bad\0tail\n${followingLease}\n`), [followingLease]);

function serializeLeaseDescription(input) {
	const bytes = Buffer.from(input);
	let output = '';
	for (let index = 0; index < bytes.length && index < 63; index++) {
		const byte = bytes[index];
		if (byte >= 32 && byte !== 58 && byte !== 127) output += String.fromCharCode(byte);
	}
	return output;
}
const serializedDescription = serializeLeaseDescription(`${'a'.repeat(10)}:TCP\n:8080:192.168.1.20:8080:0:${'x'.repeat(80)}`);
assert(Buffer.byteLength(serializedDescription) <= 63);
assert(!/[\x00-\x1f\x7f:]/.test(serializedDescription));
assert(Buffer.byteLength(`TCP:80:192.168.1.10:80:0:${serializedDescription}\n`) < 320);

const protocolSetting = services.match(/upnp_mnp_enable = (nvram_get_int\("upnp_mnp"\)[^;]*);/)[1];
const configuredProtocols = vm.runInNewContext(`(function(settings) {
	const nvram_get_int = key => settings[key];
	return Boolean(${protocolSetting});
})`);
const protocolPolicy = miniupnpd.match(/\tif\(GETFLAG\(SECUREMODEMASK\) && GETFLAG\(ENABLENATPMPMASK\)\) \{[\s\S]*?\n\t\}/)[0];
const enforceProtocolPolicy = vm.runInNewContext(`(function(secure, enabled) {
	const SECUREMODEMASK = 1, ENABLENATPMPMASK = 2, LOG_NOTICE = 0;
	const GETFLAG = mask => mask === SECUREMODEMASK ? secure : enabled;
	const CLEARFLAG = mask => { if (mask === ENABLENATPMPMASK) enabled = false; };
	const syslog = () => {};
	${protocolPolicy}
	return enabled;
})`);
for (const secure of [false, true]) {
	for (const enabled of [false, true]) {
		assert.equal(configuredProtocols({ upnp_secure: Number(secure), upnp_mnp: Number(enabled) }), enabled && !secure);
		assert.equal(enforceProtocolPolicy(secure, enabled), enabled && !secure);
	}
}
assert(miniupnpd.indexOf(protocolPolicy) > miniupnpd.indexOf('if(init(argc, argv, &v) != 0)'));
assert(miniupnpd.indexOf(protocolPolicy) < miniupnpd.indexOf('OpenAndConfNATPMPSockets(snatpmp)'));
assert.match(miniupnpd, /if\(GETFLAG\(ENABLENATPMPMASK\)\)\s*\{\s*if\(OpenAndConfNATPMPSockets\(snatpmp\)/);
assert.match(miniupnpd, /if\(GETFLAG\(ENABLENATPMPMASK\) && !GETFLAG\(IPV6DISABLEDMASK\)\) \{\s*spcp_v6 = OpenAndConfPCPv6Socket\(\);/);

const guestIsolation = lan.slice(lan.indexOf('\nvoid lanaccess_mssid('), lan.indexOf('\nvoid CP_lanaccess_wl('));
const guestUdpRule = guestIsolation.match(/eval\("ebtables", mode \? "-A" : "-D", "INPUT",[^;]*"5351"[^;]*;/)[0];
const generateGuestUdpRule = vm.runInNewContext(`(function(lifname, mode) {
	let args;
	const evalRule = (...values) => { args = values; };
	${guestUdpRule.replace('eval(', 'evalRule(')}
	return args;
})`);
for (const iface of ['wl0.1', 'wl0.2', 'wl1.1', 'wl1.3']) {
	for (const mode of [0, 1]) {
		assert.deepEqual(Array.from(generateGuestUdpRule(iface, mode)), [
			'ebtables', mode ? '-A' : '-D', 'INPUT', '-i', iface, '-p', 'ipv4',
			'--ip-proto', 'udp', '--ip-dport', '5351', '-j', 'DROP'
		]);
	}
}
assert(!guestUdpRule.includes('--ip-src'));
assert(!guestUdpRule.includes('--ip-dst'));
assert(guestIsolation.indexOf(guestUdpRule) > guestIsolation.indexOf('if (!is_router_mode()) return;'));
assert(guestIsolation.indexOf(guestUdpRule) < guestIsolation.indexOf('#ifdef RTCONFIG_WIFI_SON'));

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

console.log('PASS: UPnP mapping caps, WAN-only filter traversal, NAT-PMP/PCP policy, guest isolation, and lease/config hardening (source/model checks, not firmware execution)');