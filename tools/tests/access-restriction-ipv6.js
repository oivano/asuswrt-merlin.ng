const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/rc/firewall.c'), 'utf8');
const www = path.join(root, 'release/src/router/www');
const helperStart = source.indexOf('void write_access_restriction_ipv6(FILE *fp)');
const helperEnd = source.indexOf('\nvoid write_access_restriction(FILE *fp, FILE *fp_ipv6)', helperStart);
assert(helperStart >= 0 && helperEnd > helperStart);
const helper = source.slice(helperStart, helperEnd);

assert.match(helper, /if \(!fp \|\| !nvram_match\("enable_acc_restriction", "1"\)\)/);
assert.match(helper, /https_lanport[\s\S]*?-j DROP/);
assert.match(helper, /http_lanport[\s\S]*?-j DROP/);
assert.match(helper, /misc_httpsport_x[\s\S]*?-j DROP/);
assert.match(helper, /sshd_port[\s\S]*?-j DROP/);
assert.match(helper, /--dport 23 -j DROP/);
assert.match(source.slice(helperEnd), /write_access_restriction_ipv6\(fp_ipv6\);/);

assert.equal((source.match(/write_access_restriction\(fp, fp_ipv6\);/g) || []).length, 2);
assert.equal((source.match(/write_access_restriction\(fp, NULL\);/g) || []).length, 1);
const ipv6CallIndexes = [...source.matchAll(/write_access_restriction\(fp, fp_ipv6\);/g)].map(match => match.index);
const lanAccept = 'fprintf(fp_ipv6, "-A INPUT -i %s -m state --state NEW -j %s\\n", lan_if, "ACCEPT");';
const remoteHttps = 'misc_httpsport_x';
const wanSsh = 'fprintf(fp_ipv6, "-A INPUT -p tcp --dport %d -j %s\\n"';
for (const index of ipv6CallIndexes) {
    const following = source.slice(index);
    assert(following.indexOf(lanAccept) > 0, 'IPv6 restriction must precede the LAN accept');
    assert(following.indexOf(remoteHttps) > 0, 'IPv6 restriction must precede remote HTTPS accept');
    assert(following.indexOf(wanSsh) > 0, 'IPv6 restriction must precede WAN SSH accept');
}
const defaultFilterStart = source.indexOf('start_default_filter(int lanunit)');
const defaultFilterEnd = source.indexOf('void set_cap_apmode_filter', defaultFilterStart);
const defaultFilter = source.slice(defaultFilterStart, defaultFilterEnd);
const defaultIpv6Start = defaultFilter.indexOf('if (ipv6_enabled()) {');
const defaultIpv6 = defaultFilter.slice(defaultIpv6Start);
const defaultIpv6Restriction = defaultIpv6.indexOf('write_access_restriction_ipv6(fp);');
const defaultLanAccept = defaultIpv6.indexOf('fprintf(fp, "-A INPUT -i %s -m state --state NEW -j ACCEPT\\n", lan_if);');
assert(defaultIpv6Restriction >= 0 && defaultIpv6Restriction < defaultLanAccept,
    'default IPv6 restriction must precede the LAN accept');

for (const filename of fs.readdirSync(www).filter(filename => filename.endsWith('.dict'))) {
    const dictionary = fs.readFileSync(path.join(www, filename), 'utf8');
    const restrictionHelp = dictionary.match(/^System_Allow_Specified_IP=(.*)$/m);
    assert(restrictionHelp, `${filename} must define the Access Restrictions help text`);
    assert.match(restrictionHelp[1], /IPv6/, `${filename} must disclose the IPv6 policy`);
}
console.log('IPv6 access-restriction contracts passed');
