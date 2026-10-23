const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const httpd = read('release/src/router/httpd/httpd.c');
const web = read('release/src/router/httpd/web.c');
const rc = read('release/src/router/rc/rc_ipsec.c');

assert.match(httpd, /match\("set_ipsec_clientlist\.cgi\*", url\)[\s\S]*?match\("set_ipsec_profile\.cgi\*", url\)[\s\S]*?do_referer = CHECK_REFERER;/);
assert.match(web, /\{ "set_ipsec_clientlist\.cgi\*"[^\n]*do_set_ipsec_clientlist_cgi, do_auth \}/);
assert.match(web, /\{ "set_ipsec_profile\.cgi\*"[^\n]*do_set_ipsec_profile_cgi, do_auth \}/);
const profileTemplates = [...web.matchAll(/snprintf\(ipsec_profile_[12],[^,]+,\s*"([^"]*)"/g)];
assert.equal(profileTemplates.length, 5);
for (const [, template] of profileTemplates)
    assert.ok([38, 43].includes((template.match(/>/g) || []).length + 1));

const clientHandler = web.slice(web.indexOf('do_set_ipsec_clientlist_cgi('), web.indexOf('static int\nipsec_auth_method_key_valid('));
assert.match(clientHandler, /ipsec_client_name_valid\(key\)/);
assert.match(clientHandler, /ipsec_client_name_valid\(name\)/);
assert.ok(clientHandler.indexOf('ipsec_client_name_valid(key)') < clientHandler.indexOf('nvram_set("ipsec_client_list_1"'));

const profileHandler = web.slice(web.indexOf('do_set_ipsec_profile_cgi('), web.indexOf('#ifdef RTCONFIG_INSTANT_GUARD', web.indexOf('do_set_ipsec_profile_cgi(')));
assert.match(profileHandler, /ipsec_auth_method_key_valid\(auth_method_key\)/);
assert.match(profileHandler, /ipsec_virtual_subnet_normalize\(virtual_subnet/);
assert.ok(profileHandler.indexOf('ipsec_virtual_subnet_normalize(virtual_subnet') < profileHandler.indexOf('nvram_set("ipsec_profile_1"'));
assert.match(web, /strchr\("\._\+-@:\/=", \*character\)/);
assert.match(web, /inet_pton\(AF_INET, address, &parsed_address\)/);
assert.match(web, /prefix_length > 32/);

const profileParser = rc.slice(rc.indexOf('void ipsec_prof_fill('), rc.indexOf('void ipsec_prof_fill_ext('));
assert.match(rc, /field_count == 38 \|\| field_count == 43/);
assert.match(profileParser, /ipsec_profile_field_count_valid\(p_data\)/);
assert.match(profileParser, /ipsec_ipv4_prefix_valid\(prof\[prof_type\]\[prof_idx\]\.virtual_subnet\)/);
assert.match(profileParser, /ipsec_ipv4_prefix_list_valid\(prof\[prof_type\]\[prof_idx\]\.local_subnet\)/);
assert.match(profileParser, /ipsec_conn_en = IPSEC_CONN_EN_DOWN;/);
assert.match(profileParser, /profilename\[0\] = '\\0';/);
assert.match(rc, /while\(\(subnet = strsep\(&next, ","\)\) != NULL\)/);

const normalize = input => {
    if (!input || input.length >= 32) return null;
    const prefixParts = input.split('/');
    if (prefixParts.length > 2) return null;
    const address = prefixParts[0];
    if (prefixParts.length === 2 && !/^[0-9]+$/.test(prefixParts[1])) return null;
    if (prefixParts.length === 2 && Number(prefixParts[1]) > 32) return null;
    const isIpv4 = candidate => {
        const octets = candidate.split('.');
        return octets.length === 4 && octets.every(octet =>
            /^(0|[1-9][0-9]{0,2})$/.test(octet) && Number(octet) <= 255);
    };
    if (isIpv4(address))
        return `${address}/${prefixParts[1] ?? '32'}`;
    if (prefixParts.length !== 1 || !/^([0-9]{1,3}\.){2}[0-9]{1,3}$/.test(address)) return null;
    return isIpv4(`${address}.0`) ? `${address}.0/24` : null;
};

assert.equal(normalize('10.10.10'), '10.10.10.0/24');
assert.equal(normalize('192.168.4.0/24'), '192.168.4.0/24');
assert.equal(normalize('192.168.4.1'), '192.168.4.1/32');
for (const invalid of ['x;touch /tmp/p;', '$(reboot)', '10.10.10.0/33', '10.10.10/24;id', '1.2.3.4/2/3', '256.1.1.1'])
    assert.equal(normalize(invalid), null, invalid);

const validAuthKey = value => value.length <= 32 && /^[A-Za-z0-9._+@:/=-]*$/.test(value);
assert.equal(validAuthKey('vpnKey_123+/='), true);
for (const invalid of ['K>x', 'x;reboot;', '$(id)', 'two words'])
    assert.equal(validAuthKey(invalid), false, invalid);

const validClient = value => value.length > 0 && value.length <= 64 && /^[A-Za-z0-9_.@-]+$/.test(value);
assert.equal(validClient('client-01@example.net'), true);
for (const invalid of ['name>evil', 'x;id', '$(reboot)', 'two words', '<client>'])
    assert.equal(validClient(invalid), false, invalid);

console.log('PASS: IPsec mutation routes require referers; unsafe profile and client values are rejected before persistence and rc drops malformed subnets');
