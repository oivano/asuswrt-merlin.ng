const assert = require('assert');
const fs = require('fs');
const path = require('path');

const sourcePath = path.join(__dirname, '../../release/src/router/rc/wan.c');
const source = fs.readFileSync(sourcePath, 'utf8');
const start = source.indexOf('start_igmpproxy(char *wan_ifname)');
const end = source.indexOf('\n#ifdef RTCONFIG_IPV6\nvoid\nstop_mldproxy', start);
assert(start >= 0 && end > start, 'start_igmpproxy body is present');
const body = source.slice(start, end);

assert(body.includes('"/tmp/ppp/igmpproxy.conf"'), 'config uses the protected runtime directory');
assert(!body.includes('"/tmp/igmpproxy.conf"'), 'legacy world-writable config path is absent');
assert(source.includes('O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK, 0600'),
    'config creation is exclusive and does not follow symlinks');
assert(source.includes('st_uid != 0') && source.includes('st_nlink != 1'),
    'created and consumed configs are checked for root ownership and a single link');

const customConfig = body.indexOf('use_custom_config("igmpproxy.conf", igmpproxy_conf)');
const postconf = body.indexOf('run_postconf("igmpproxy", igmpproxy_conf)');
const launch = body.indexOf('eval("/usr/sbin/igmpproxy", igmpproxy_conf)');
assert(customConfig >= 0 && postconf > customConfig && launch > postconf,
    'custom config, postconf, and launch retain their expected order');
assert(body.slice(0, customConfig).includes('!igmpproxy_config_is_safe(config_dirfd)'),
    'config is validated before custom-config copying');
assert(body.slice(customConfig, postconf).includes('!igmpproxy_config_is_safe(config_dirfd)'),
    'config is validated after custom-config copying and before postconf');
assert(body.slice(postconf, launch).includes('!igmpproxy_config_is_safe(config_dirfd)'),
    'config is validated after postconf and before daemon launch');

console.log('igmpproxy config symlink checks passed');