const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const httpd = read('release/src/router/httpd/httpd.c');
const web = read('release/src/router/httpd/web.c');
const rc = read('release/src/router/rc/rc_ipsec.c');
const rcHeader = read('release/src/router/rc/rc_ipsec.h');

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
assert.match(profileParser, /ipsec_profile_valid\(p_data, 0\)/);
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

const constants = Object.fromEntries([...rcHeader.matchAll(/^#define\s+(SZ_\w+)\s+(\d+)/gm)]
    .map(([, name, value]) => [name, Number(value)]));
const capacitySource = rc.match(/static const size_t capacities\[\] = \{([^}]+)\}/)[1];
const capacities = capacitySource.split(',').map(expression => expression.trim()
    .split('+').reduce((sum, value) => sum + (constants[value.trim()] ?? Number(value)), 0));
assert.equal(capacities.length, 43);
const stringFields = new Map([
    [1, 'profilename'], [2, 'remote_gateway_method'], [3, 'remote_gateway'],
    [4, 'local_public_interface'], [5, 'local_pub_ip'], [7, 'auth_method_key'],
    [8, 'local_subnet'], [10, 'remote_subnet'], [12, 'tun_type'], [13, 'virtual_ip_en'],
    [14, 'virtual_subnet'], [20, 'local_id'], [21, 'remote_id'], [24, 'xauth_account'],
    [25, 'xauth_password'], [26, 'rightauth2_method'], [36, 'samba_settings'],
    [38, 'leftauth_method'], [39, 'leftcert'], [40, 'leftsendcert'], [41, 'leftkey'], [42, 'eap_identity']
]);
for (const [index, member] of stringFields) {
    const expression = rcHeader.match(new RegExp(`char ${member}\\[([^\\]]+)\\]`))[1];
    const size = expression.split('+').reduce((sum, value) => sum + (constants[value.trim()] ?? Number(value)), 0);
    assert.equal(capacities[index], size + ([8, 10].includes(index) ? 1 : 0), member);
    assert.ok(profileParser.includes(`ipsec_profile_str_parse(p_end, p_tmp, sizeof(prof[prof_type][prof_idx].${member}), &i)`), member);
}
assert.match(rc, /while\(\*p_end && \*p_end != '>'\)/);
assert.doesNotMatch(rc, /while\(\*p_end\+\+ != '>'\)|strcpy\((?:s_tmp|xauth_buf), nvram_safe_get/);
assert.match(rc, /if\(length >= capacity\)[\s\S]*?return 0;[\s\S]*?memcpy\(p_tmp, p_end, length\)/);
assert.match(rc, /\*nsize_shifft = length \+ \(end != NULL\)/);
assert.match(rc, /strnlen\(data, SZ_BUF\) >= SZ_BUF/);
assert.match(rc, /length \+ sizeof\("\.0\/24"\) > capacity/);
assert.match(rc, /parts != 4/);
const preload = rc.slice(rc.indexOf('int pre_ipsec_prof_set()'), rc.indexOf('int pre_ipsec_samba_prof_set()'));
assert.ok(preload.indexOf('ipsec_profile_valid(nvram_safe_get(buf), 0)') < preload.indexOf('strlcpy(p_tmp,'));
assert.ok(preload.indexOf('ipsec_profile_valid(nvram_safe_get(buf_ext), 1)') < preload.indexOf('strlcpy(p_tmp_ext,'));
assert.ok(preload.indexOf('memset(&prof[prof_count][i-1]') < preload.indexOf('if(strlen(nvram_safe_get'));
assert.match(rc, /void ipsec_prof_fill_ext\([^]*?if\(!ipsec_profile_valid\(p_data, 1\)\)/);

// Model the source's tuple guard; these checks do not compile or execute rc C code.
const validTuple = (data, extended = false) => {
    if (Buffer.byteLength(data) >= constants.SZ_BUF || data.includes('\0')) return false;
    const fields = data.split('>');
    if (!(extended ? fields.length === 6 : [38, 43].includes(fields.length))) return false;
    return fields.every((field, index) => {
        const length = Buffer.byteLength(field);
        const capacity = extended ? 11 : capacities[index];
        if (length >= capacity) return false;
        if (extended) return true;
        if ([8, 10].includes(index) && field !== 'null' && !field.startsWith('<')) return false;
        if (index === 14 && length && !field.includes('/') && length + 6 > capacity) return false;
        if (index === 36 && field !== 'null') {
            const parts = field.slice(1).split('<');
            if (!field.startsWith('<') || parts.length !== 4 || parts.some(part => Buffer.byteLength(part) >= constants.SZ_MIN)) return false;
        }
        return true;
    });
};
const tuple = count => {
    const fields = Array(count).fill('0');
    fields[1] = 'safe-profile';
    fields[8] = fields[10] = '<0.0.0.0/0';
    fields[14] = '10.10.10';
    fields[36] = '<<<<';
    return fields;
};
for (const count of [38, 43]) assert.ok(validTuple(tuple(count).join('>')));
for (const [, template] of profileTemplates) {
    const generated = template.split('>').map((field, index) => field.replace(/%s/g, index === 36 ? '<<<<' : '10.10.10')).join('>');
    assert.ok(validTuple(generated), 'generated HTTP profile remains accepted');
}
for (const [index, member] of stringFields) {
    if (index === 36) continue;
    const fields = tuple(43);
    const limit = capacities[index] - 1 - (index === 14 ? 5 : 0);
    fields[index] = [8, 10].includes(index) ? '<' + 'a'.repeat(limit - 1) : 'a'.repeat(limit);
    assert.ok(validTuple(fields.join('>')), `${member}: capacity boundary accepted`);
    fields[index] += 'a';
    assert.equal(validTuple(fields.join('>')), false, `${member}: overflow rejected`);
}
const oversized = tuple(43);
oversized[1] = 'a'.repeat(500);
oversized[3] += 'b'.repeat(1024 - Buffer.byteLength(oversized.join('>')));
assert.equal(Buffer.byteLength(oversized.join('>')), 1024);
assert.equal(validTuple(oversized.join('>')), false);
for (const count of [1, 6, 37, 39, 42, 44]) assert.equal(validTuple(Array(count).fill('0').join('>')), false);
assert.ok(validTuple('0>0>0>0>0>0', true));
for (const extension of ['', '0', '0>0>0>0>0', '0>0>0>0>0>0>0', '9'.repeat(500) + '>0>0>0>0>0'])
    assert.equal(validTuple(extension, true), false);
for (const samba of ['<a<b<c', '<a<b<c<d<e', '<' + 'a'.repeat(32) + '<<<']) {
    const fields = tuple(38);
    fields[36] = samba;
    assert.equal(validTuple(fields.join('>')), false, 'malformed Samba field rejected');
}
const boundary = tuple(43);
for (const index of [3, 5, 20, 21]) {
    const padding = Math.min(capacities[index] - 1 - boundary[index].length, 511 - boundary.join('>').length);
    boundary[index] += 'a'.repeat(padding);
}
assert.equal(boundary.join('>').length, 511);
assert.ok(validTuple(boundary.join('>')));
boundary[39] += 'a';
assert.equal(validTuple(boundary.join('>')), false);

console.log('PASS: IPsec request/source contracts and tuple-boundary models, including oversized names, missing delimiters, extensions, Samba fields, and generated legacy profiles (not compiled C)');
