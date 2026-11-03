import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(`../../release/src/router/${path}`, import.meta.url), 'utf8');
const cacheH = read('avahi/avahi-core/cache.h');
const cacheC = read('avahi/avahi-core/cache.c');
const server = read('avahi/avahi-core/server.c');
const services = read('rc/services.c');
const watchdog = read('rc/watchdog.c');

const recordMax = Number(cacheH.match(/#define AVAHI_CACHE_RECORD_SIZE_MAX (\d+)/)?.[1]);
const bytesExpr = cacheH.match(/#define AVAHI_CACHE_BYTES_MAX \(([\d*]+)\)/)?.[1];
assert.equal(recordMax, 9000, 'per-record cap follows the RFC 6762 packet limit');
assert.ok(bytesExpr, 'per-interface byte budget defined');
const bytesMax = bytesExpr.split('*').reduce((a, b) => a * Number(b), 1);
assert.ok(bytesMax <= 512 * 1024, 'byte budget well below the 4 MiB avahi rlimit-data');

assert.match(cacheH, /AvahiRecord \*record;\n\s*size_t size;/);
assert.match(cacheH, /unsigned n_entries;\n\s*size_t n_bytes;/);

const update = cacheC.match(/void avahi_cache_update\([\s\S]*?\n\}\n/)?.[0];
assert.ok(update, 'avahi_cache_update exists');
const sizeGate = update.indexOf('> AVAHI_CACHE_RECORD_SIZE_MAX');
assert.ok(sizeGate > 0 && sizeGate < update.indexOf('cache_flush) {'),
	'oversized records rejected before cache-flush expiry of existing entries');
const budgetGate = update.indexOf('c->n_bytes + cost > AVAHI_CACHE_BYTES_MAX');
assert.ok(budgetGate > 0 && budgetGate < update.indexOf('avahi_new(AvahiCacheEntry'), 'budget checked before allocation');
assert.match(update, /e->size = cost;\n\s*c->n_bytes \+= cost;/);
assert.match(update, /c->n_bytes = c->n_bytes - e->size \+ cost;\n\s*e->size = cost;/);
const remove = cacheC.match(/static void remove_entry\([\s\S]*?\n\}\n/)?.[0];
assert.match(remove, /c->n_bytes -= e->size;/);
assert.match(cacheC, /c->n_bytes = 0;/);

const handler = server.match(/static void handle_response_packet\([\s\S]*?\n\}\n/)?.[0];
const early = handler.indexOf('> AVAHI_CACHE_RECORD_SIZE_MAX');
assert.ok(early > 0 && early < handler.indexOf('handle_conflict('), 'oversized records skip conflict/scheduler/cache');
assert.match(handler.slice(early, early + 200), /goto unref;/);

const mdnsGenerator = services.match(/int generate_mdns_config\(void\)([\s\S]*?)\n\}/)?.[1];
assert.match(mdnsGenerator, /cache-entries-max=1024\\n/);
assert.ok(mdnsGenerator.indexOf('cache-entries-max') < mdnsGenerator.indexOf('[publish]'), 'set in [Server] section');

const secureDirectory = services.match(/int secure_root_config_dir\(const char \*path\)([\s\S]*?)\n\}/)?.[1];
assert.ok(secureDirectory, 'shared root config directory hardening exists');
assert.match(secureDirectory, /geteuid\(\) != 0/);
assert.match(secureDirectory, /mkdir\(path, 0755\)/);
assert.match(secureDirectory, /O_DIRECTORY \| O_NOFOLLOW/);
assert.match(secureDirectory, /fchmod\(fd, 0755\)/);
assert.match(secureDirectory, /fchown\(fd, 0, 0\)/);
assert.match(secureDirectory, /st\.st_uid == 0/);
assert.match(secureDirectory, /st\.st_mode & 0022/);

const safeConfigOpen = services.match(/FILE \*open_root_config_file\([\s\S]*?\n\}/)?.[0];
assert.match(safeConfigOpen, /unlinkat\(dirfd, name, 0\)/);
assert.match(safeConfigOpen, /openat\(dirfd, name, O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW/);
assert.match(safeConfigOpen, /S_ISREG\(st\.st_mode\)/);
assert.match(safeConfigOpen, /st\.st_nlink != 1/);
assert.match(mdnsGenerator, /open_root_config_file\(AVAHI_CONFIG_PATH, AVAHI_CONFIG_FN/);
for (const [generator, directory, filename] of [
	['generate_afpd_service_config', 'AVAHI_SERVICES_PATH', 'AVAHI_AFPD_SERVICE_FN'],
	['generate_adisk_service_config', 'AVAHI_SERVICES_PATH', 'AVAHI_ADISK_SERVICE_FN'],
	['generate_itune_service_config', 'AVAHI_SERVICES_PATH', 'AVAHI_ITUNE_SERVICE_FN'],
]) {
	const body = services.match(new RegExp(`int ${generator}\\(void\\)([\\s\\S]*?)\\n\\}`))?.[1];
	assert.match(body, new RegExp(`open_root_config_file\\(${directory}, ${filename}, 0644\\)`));
}
const safeConfigMode = services.match(/static int set_root_config_file_mode\([\s\S]*?\n\}/)?.[0];
assert.match(safeConfigMode, /openat\(dirfd, name, O_RDONLY \| O_NOFOLLOW/);
assert.match(safeConfigMode, /fchmod\(fd, mode\)/);
assert.match(safeConfigMode, /st\.st_nlink != 1/);

const dnscryptStart = services.match(/void start_dnscrypt_proxy\(void\)([\s\S]*?)\n\}/)?.[1];
assert.match(dnscryptStart, /secure_root_config_dir\("\/etc\/dnscrypt-proxy"\)/);
assert.match(dnscryptStart, /secure_root_config_dir\(DNSCRYPT_CACHE_DIR\)/);
assert.match(dnscryptStart, /open_root_config_file\("\/etc\/dnscrypt-proxy", "dnscrypt-proxy\.toml"/);
assert.match(dnscryptStart, /set_root_config_file_mode\("\/etc\/dnscrypt-proxy", "dnscrypt-proxy\.toml", 0644\)/);
assert.match(services, /f_write_excl\("\/etc\/pam\.d\/openvpn"/);
assert.match(services, /secure_root_config_dir\("\/etc\/pam\.d"\)/);
assert.match(services, /int start_mdns\(void\)[\s\S]*?secure_root_config_dir\(AVAHI_CONFIG_PATH\)/);
const timemachine = read('rc/timemachine.c');
assert.match(timemachine, /secure_root_config_dir\(AFP_CONFIG_PATH\)/);
assert.match(timemachine, /open_root_config_file\(AFP_CONFIG_PATH, AFP_CONFIG_FN, 0644\)/);

const check = watchdog.match(/static void mdns_check\(void\)([\s\S]*?)\n\}/)?.[1];
assert.ok(check, 'watchdog mdns_check exists');
assert.match(check, /pids\("avahi-daemon"\)/);
assert.match(check, /notify_rc\("start_mdns"\)/);
assert.match(check, /success_start_service/);
assert.match(watchdog, /dnsmasq_check\(\);[\s\S]{0,100}#if defined\(RTCONFIG_MDNS\)\n\tmdns_check\(\);\n#endif/);
assert.match(services, /else if \(strcmp\(script, "mdns"\) == 0\)[\s\S]{0,120}RC_SERVICE_START\) start_mdns\(\);/);

// Model: replay a flood of maximal generic records plus legitimate small records.
const overhead = 100;
function makeCache(maxEntries) {
	return { n: 0, bytes: 0, maxEntries, entries: new Map() };
}
function cacheUpdate(c, rec) {
	if (rec.size > recordMax) return false;
	const cost = rec.size + overhead;
	const e = c.entries.get(rec.key);
	if (e) {
		c.bytes = c.bytes - e.size + cost;
		e.size = cost;
		return true;
	}
	if (c.n >= c.maxEntries) return false;
	if (c.bytes + cost > bytesMax) return false;
	c.entries.set(rec.key, { size: cost });
	c.n++;
	c.bytes += cost;
	return true;
}

const flood = makeCache(1024);
for (let i = 0; i < 20000; i++) cacheUpdate(flood, { key: `x${i}`, size: 65535 });
assert.equal(flood.n, 0, 'maximal 64 KiB records are never cached');
for (let i = 0; i < 20000; i++) cacheUpdate(flood, { key: `y${i}`, size: recordMax });
assert.ok(flood.bytes <= bytesMax, 'near-limit flood bounded by byte budget');

const normal = makeCache(1024);
for (let i = 0; i < 300; i++) assert.ok(cacheUpdate(normal, { key: `svc${i}`, size: 120 }), 'typical LAN records cached');
for (let i = 0; i < 300; i++) cacheUpdate(normal, { key: `svc${i}`, size: 120 });
assert.equal(normal.n, 300);
assert.equal(normal.bytes, 300 * 220, 'refreshes do not double-count');

const interfaces = 8;
assert.ok(interfaces * bytesMax < 4 * 1024 * 1024, 'aggregate budget fits under rlimit-data for 8 interfaces');

console.log('Avahi cache budget source contracts and model passed');
