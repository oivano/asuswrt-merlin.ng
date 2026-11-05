'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const start = source.indexOf('static void find_hostname_by_mac(char *mac, char *hostname, int hostname_len)\n{');
const end = source.indexOf('\nvoid get_ipv6_client_info()', start);
assert.ok(start >= 0 && end > start, 'could not locate find_hostname_by_mac');
const body = source.slice(start, end);

assert.doesNotMatch(body, /\bmemset\s*\(/, 'lease token pointers must not be written through');
assert.match(body, /line_len == sizeof\(line\) - 1 && line_end == NULL/,
    'full fgets chunks without a newline must be treated as truncated');
assert.match(body, /while \(ch != '\\n' && ch != EOF\)/,
    'the remainder of a truncated physical line must be drained');
assert.match(body, /macaddr == NULL \|\| ipaddr == NULL \|\| host_name == NULL/,
    'records missing required fields must be rejected');
assert.match(body, /strlen\(macaddr\) != 17 \|\| \*ipaddr == '\\0'/,
    'MAC and IP fields must be validated before matching');

function findHostnameByMac(leaseText, mac) {
    for (const line of leaseText.split('\n')) {
        if (line.length > 255)
            continue;
        const fields = line.split(' ');
        if (fields.length < 4 || !/^\d+$/.test(fields[0]) ||
            fields[1].length !== 17 || fields[2].length === 0)
            continue;
        if (fields[1].toLowerCase() === mac.toLowerCase())
            return fields[3];
    }
    return '<unknown>';
}

const attackerMac = '02:11:11:11:11:11';
const otherMac = '02:22:22:22:22:22';
const longClientId = Array(255).fill('11').join(':');
const longLease = `123456 ${attackerMac} 192.0.2.10 attacker ${longClientId}`;
assert.ok(longLease.length > 255);
assert.equal(findHostnameByMac(`${longLease}\n`, otherMac), '<unknown>');
assert.equal(findHostnameByMac(`${longLease}\n123457 ${otherMac} 192.0.2.11 neighbor\n`, otherMac), 'neighbor');
assert.equal(findHostnameByMac('123456 192.0.2.10\n123457 malformed 192.0.2.11 neighbor\n', otherMac), '<unknown>');
assert.equal(findHostnameByMac(`123458 ${otherMac} 192.0.2.12 valid-host\n`, otherMac), 'valid-host');

console.log('httpd DHCP lease parser bounds passed');