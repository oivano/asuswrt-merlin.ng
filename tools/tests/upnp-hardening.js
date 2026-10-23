const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const miniupnpd = fs.readFileSync(path.join(root, 'release/src/router/miniupnpd/miniupnpd.c'), 'utf8');

assert.match(services, /static int upnp_config_dir_ready\(void\)[\s\S]*?lstat\("\/etc\/upnp"[\s\S]*?S_ISDIR\(st\.st_mode\)[\s\S]*?st\.st_uid != 0[\s\S]*?chmod\("\/etc\/upnp", 0700\)/);
assert.match(services, /static int upnp_config_file_trusted\(const char \*path\)[\s\S]*?lstat\(path, &st\) == 0 && S_ISREG\(st\.st_mode\)[\s\S]*?st\.st_uid == 0 && !\(st\.st_mode & 022\)/);
assert.match(services, /old_umask = umask\(077\);[\s\S]*?upnp_config_dir_ready\(\)/);
assert.match(services, /open\("\/etc\/upnp\/config", O_WRONLY \| O_CREAT \| O_EXCL, 0600\)/);
assert.match(services, /upnp_config_file_trusted\("\/etc\/upnp\/config\.alt"\)/);
assert.match(services, /upnp_config_file_trusted\("\/etc\/upnp\/config\.custom"\)/);
assert(services.includes('"/etc/upnp/upnp.leases"'));
assert(!services.includes('"/tmp/upnp.leases"'));
assert.match(miniupnpd, /umask\(077\);[\s\S]*?#ifndef NO_BACKGROUND_NO_PIDFILE[\s\S]*?daemon\(0, 0\)/);

console.log('PASS: UPnP config directory, override, config creation, and lease-file hardening contracts');