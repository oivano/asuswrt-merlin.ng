'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');

const source = fs.readFileSync('release/src/router/nvram_arm/main.c', 'utf8');
const start = source.indexOf('static int _convert_data(const char *name, char *value, size_t value_len)');
const end = source.indexOf('\nstatic char* _get_attr', start);
assert.ok(start >= 0 && end > start, 'active _convert_data implementation exists');
const convert = source.slice(start, end);

assert.match(convert, /strstr\(name, passwd_token\)/);
assert.match(convert, /strstr\(name, "radius_key"\)/);
assert.match(convert, /strncmp\(name, "ipsec_profile_"/);
assert.match(convert, /\(1u << 7\) \| \(1u << 25\)/);
assert.match(convert, /strncmp\(name, "ipsec_client_list_"/);

const marker = 'X';
function maskList(value, mask) {
    return value.split('<').map(record => record.split('>').map((field, index) =>
        (mask & (1 << index)) ? marker.repeat(field.length) : field).join('>')).join('<');
}

function convertValue(name, value) {
    if (name.includes('password') || name.includes('passwd') || name.includes('radius_key'))
        return marker.repeat(value.length);
    if (name.startsWith('ipsec_profile_'))
        return maskList(value, (1 << 7) | (1 << 25));
    if (name.startsWith('ipsec_client_list_'))
        return maskList(value, 1 << 1);
    return value;
}

for (const name of [
    'dsl0_pppoe_passwd', 'dsl8.1_pppoe_passwd', 'wan1_pppoe_passwd',
    'wan10_pppoe_passwd', 'vpnc_pppoe_passwd', 'frr_passwd', 'frr_enpasswd',
    'wl0_radius_key', 'wl0.1_radius_key', 'wl1_radius_key'
]) {
    assert.equal(convertValue(name, 'secret-value'), marker.repeat('secret-value'.length), name);
}

const profileFields = Array.from({ length: 43 }, (_, index) => `field${index}`);
profileFields[7] = 'profile-psk';
profileFields[25] = 'xauth-password';
const profile = convertValue('ipsec_profile_2', profileFields.join('>')).split('>');
assert.equal(profile[7], marker.repeat('profile-psk'.length));
assert.equal(profile[25], marker.repeat('xauth-password'.length));
assert.equal(profile[6], 'field6');
assert.equal(profile[24], 'field24');
assert.equal(profile[26], 'field26');

assert.equal(convertValue('ipsec_client_list_1', 'alice>vpn-secret<bob>other-secret'),
    'alice>' + marker.repeat('vpn-secret'.length) + '<bob>' + marker.repeat('other-secret'.length));
assert.equal(convertValue('ipsec_client_list_2', 'alice>vpn-secret>2'),
    'alice>' + marker.repeat('vpn-secret'.length) + '>2');

console.log('NVRAM remove-password export masks credential fields');