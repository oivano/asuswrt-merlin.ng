const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const common = fs.readFileSync(path.join(root, 'release/src/router/rc/common.c'), 'utf8');
const firewall = fs.readFileSync(path.join(root, 'release/src/router/rc/firewall.c'), 'utf8');
const defaults = fs.readFileSync(path.join(root, 'release/src/router/shared/defaults.c'), 'utf8');
const page = fs.readFileSync(path.join(root, 'release/src/router/www/Advanced_NATPassThrough_Content.asp'), 'utf8');

function section(source, startMarker, endMarker) {
    const start = source.indexOf(startMarker);
    const end = source.indexOf(endMarker, start);
    assert(start !== -1 && end > start, `missing source section ${startMarker}`);
    return source.slice(start, end);
}

const ftpSetup = section(common, 'void setup_ftp_conntrack(int port)', 'void setup_udp_timeout');
assert(ftpSetup.indexOf('fw_pt_ftp') < ftpSetup.indexOf('ct_modprobe("ftp", ports)'));
assert(ftpSetup.includes('nvram_match("nf_ftp", "1")'));
assert(ftpSetup.includes('ct_modprobe_r("ftp")'));
assert(ftpSetup.includes('nvram_set("ftp_ports", "")'));
assert(ftpSetup.includes('ports=21,%d'));

const conntrackSetup = section(common, 'void setup_conntrack(void)', 'void setup_pt_conntrack(void)');
assert(conntrackSetup.includes('nvram_match("fw_pt_ftp", "1") || nvram_match("nf_ftp", "1")'));
assert(conntrackSetup.includes('ct_modprobe_r("ftp")'));

assert(defaults.includes('{ "fw_pt_ftp", "0",'));
assert(page.includes('<select name="fw_pt_ftp"'));
assert(page.includes('nvram_match("fw_pt_ftp", "0","selected")'));
assert(page.includes('nvram_match("fw_pt_ftp", "1","selected")'));

const ftpDropRule = '-A FORWARD -m state --state RELATED -m helper --helper ftp -j DROP';
const relatedAcceptRule = '-A FORWARD -m state --state ESTABLISHED,RELATED -j %s';
const singleWan = firewall.indexOf('filter_setting(int wan_unit, char *lan_if, char *lan_ip, char *logaccept, char *logdrop)');
const multiWan = firewall.indexOf('filter_setting2(char *lan_if, char *lan_ip, char *logaccept, char *logdrop)');
assert(singleWan !== -1 && multiWan > singleWan);

for (const start of [singleWan, multiWan]) {
    const guard = firewall.indexOf('if (!nvram_match("fw_pt_ftp", "1")', start);
    const drop = firewall.indexOf(ftpDropRule, start);
    const accept = firewall.indexOf(relatedAcceptRule, drop);
    assert(guard >= start && guard < drop && drop < accept, 'FTP helper DROP must precede RELATED accept');
}
assert.strictEqual(firewall.split(ftpDropRule).length - 1, 4);
assert.strictEqual(firewall.split('m helper --helper ftp -j DROP\\n");').length - 1, 4);

console.log('FTP conntrack helper defaults, opt-in, and firewall rules passed');
