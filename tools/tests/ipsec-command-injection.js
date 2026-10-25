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
assert.match(profileHandler, /virtual_subnet\[128\] = \{0\}/);
assert.match(profileHandler, /normalized_virtual_subnet\[sizeof\(virtual_subnet\)\] = \{0\}/);
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

const tunables = ['ipsec_server_enable', 'auth_method_key', 'dead_peer_detection', 'ipsec_dpd', 'virtual_subnet'];
const handlerCapacities = Object.fromEntries(tunables.map(name => [name,
    Number(profileHandler.match(new RegExp(`\\b${name}\\[(\\d+)\\] = \\{0\\}`))[1])]));
const fallbackFields = Object.fromEntries([...profileHandler.matchAll(/(\w+)_ptr = profile_fields\[(\d+)\];/g)]
    .map(([, name, index]) => [name, Number(index)]));
assert.deepEqual(fallbackFields, { auth_method_key: 7, dead_peer_detection: 31, ipsec_dpd: 30, virtual_subnet: 14 });
const lengthGuard = profileHandler.match(/if\((!auth_method_key_ptr[^]*?)\)\{\s*ret = HTTP_INVALID_INPUT;/)[1];
const countGuard = profileHandler.match(/if\((profile_next != NULL[^]*?)\)\{\s*ret = HTTP_INVALID_INPUT;/)[1];
const enableGuard = profileHandler.match(/if\(((?:\(strcmp\(ipsec_server_enable)[^]*?)\)\{\s*HTTPD_DBG/)[1];
const dpdGuard = profileHandler.match(/if\((!isValid_digit_string\(ipsec_dpd\)[^]*?)\)\{/)[1];
const evaluateGuard = (expression, values) => new Function(...Object.keys(values), `
    const strlen = value => Buffer.byteLength(value);
    const strcmp = (left, right) => left === right ? 0 : 1;
    const isValid_digit_string = value => /^[0-9]+$/.test(value);
    const atoi = value => Number.parseInt(value, 10) || 0;
    return Boolean(${expression.replace(/sizeof\((\w+)\)/g, (_, name) => handlerCapacities[name])
        .replace(/\bNULL\b/g, 'null')});`)(...Object.values(values));
for (const name of tunables) {
    assert.match(lengthGuard, new RegExp(`strlen\\(${name}_ptr\\) >= sizeof\\(${name}\\)`));
    assert.match(profileHandler, new RegExp(`strlcpy\\(${name}, ${name}_ptr, sizeof\\(${name}\\)\\);`));
    assert.ok(profileHandler.indexOf(lengthGuard) < profileHandler.indexOf(`strlcpy(${name},`));
}
assert.doesNotMatch(profileHandler, /sizeof\(tmp_str\)|get_string_in_62/);
assert.match(profileHandler, /strlcpy\(ipsec_profile_tmp,[^\n]+>= sizeof\(ipsec_profile_tmp\)/);
assert.match(profileHandler, /while\(profile_count < 43 && profile_next != NULL\)\s*profile_fields\[profile_count\+\+\] = strsep\(&profile_next, ">"\);/);
for (const guard of [lengthGuard, countGuard, enableGuard, dpdGuard])
    assert.ok(profileHandler.indexOf(guard) < profileHandler.indexOf('nvram_set('));

// Execute the C guard expressions with source-derived capacities/field indices, not native C.
const profileUpdate = (stored, request = {}, enabled = '1') => {
    const unchanged = { profile: stored, commits: 0, notifications: 0 };
    if (Buffer.byteLength(stored) >= 1024) return unchanged;
    const fields = stored ? stored.split('>') : [];
    if (stored && evaluateGuard(countGuard, {
        profile_count: Math.min(fields.length, 43), profile_next: fields.length > 43 ? '' : null
    })) return unchanged;
    const values = Object.fromEntries(tunables.map(name => [`${name}_ptr`, request[name] ??
        (name === 'ipsec_server_enable' ? enabled : fields[fallbackFields[name]] ?? null)]));
    if (evaluateGuard(lengthGuard, values)) return unchanged;
    const effective = Object.fromEntries(tunables.map(name => [name, values[`${name}_ptr`]]));
    if (evaluateGuard(enableGuard, effective) || evaluateGuard(dpdGuard, effective) ||
        !validAuthKey(effective.auth_method_key) || !normalize(effective.virtual_subnet)) return unchanged;
    return { profile: 'validated replacement', commits: 1, notifications: request.do_rc === '1' ? 1 : 0 };
};
const fallbackTemplate = profileHandler.match(/snprintf\(ipsec_profile_1,[^,]+,\s*"([^"]*)"/)[1];
const fallbackProfile = fallbackTemplate.split('>').map((field, index) => field.replace(/%s/g,
    ({ 7: 'vpnKey_123+/=', 14: '10.10.10', 30: '10', 31: '1', 36: '<<<<' })[index] ?? 'safe'));
assert.equal(fallbackProfile.length, 38);
assert.equal(profileUpdate(fallbackProfile.join('>')).commits, 1, 'omitted tunables use valid stored fields');
assert.equal(profileUpdate(fallbackProfile.join('>'), { ipsec_dpd: '900' }).commits, 1, 'partial update');
const expectRefused = (stored, request = {}, enabled = '1') => {
    assert.deepEqual(profileUpdate(stored, request, enabled), { profile: stored, commits: 0, notifications: 0 });
};
for (const index of [7, 14, 30, 31]) {
    const fields = [...fallbackProfile];
    fields[index] = 'A'.repeat(127);
    expectRefused(fields.join('>'));
}
const allOversized = [...fallbackProfile];
for (const index of [7, 14, 30, 31]) allOversized[index] = 'A'.repeat(127);
expectRefused(allOversized.join('>'), { samba_dns1: '', samba_dns2: '', samba_win1: '', samba_win2: '' });
for (const name of tunables) {
    expectRefused(fallbackProfile.join('>'), { [name]: '1'.repeat(handlerCapacities[name]), do_rc: '1' });
    if (name !== 'virtual_subnet') {
        const fields = [...fallbackProfile];
        if (name === 'ipsec_server_enable') expectRefused(fields.join('>'), {}, '1'.repeat(127));
        else {
            fields[fallbackFields[name]] = '1'.repeat(handlerCapacities[name]);
            expectRefused(fields.join('>'));
        }
    }
}
for (const key of ['>>>>>>>'.concat('A'.repeat(25)), '<key', '>key', 'A'.repeat(33),
    ...Array.from({ length: 32 }, (_, code) => `key${String.fromCharCode(code)}x`), 'key\x7fx']) {
    expectRefused(fallbackProfile.join('>'), { auth_method_key: key, do_rc: '1' });
    const fields = [...fallbackProfile];
    fields[7] = key;
    expectRefused(fields.join('>'));
}
for (const invalid of ['', 'x', '2', '10', '-1']) {
    expectRefused(fallbackProfile.join('>'), { ipsec_server_enable: invalid });
    const fields = [...fallbackProfile];
    fields[31] = invalid;
    expectRefused(fields.join('>'));
}
for (const invalid of ['', '9', '901', '10x', '1000', '-10']) {
    const fields = [...fallbackProfile];
    fields[30] = invalid;
    expectRefused(fields.join('>'));
    expectRefused(fallbackProfile.join('>'), { ipsec_dpd: invalid });
}
for (const invalid of ['1.2.3.4/33', '1.2.3.4/2/3', '256.1.1.1', '10.0.0;id']) {
    const fields = [...fallbackProfile];
    fields[14] = invalid;
    expectRefused(fields.join('>'));
}
for (const count of [1, 7, 14, 30, 31, 37, 39, 42, 44])
    expectRefused(Array(count).fill('0').join('>'));
expectRefused('');
expectRefused('A'.repeat(1024));
assert.equal(profileUpdate(fallbackProfile.join('>'), { auth_method_key: 'A'.repeat(32), ipsec_dpd: '10', do_rc: '1' }).notifications, 1);
assert.equal(profileUpdate([...fallbackProfile, 'pubkey', 'svrCert.pem', 'always', 'svrKey.pem', '%identity'].join('>')).commits, 1);

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
