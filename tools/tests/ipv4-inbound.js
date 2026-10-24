const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');

const source = fs.readFileSync(path.resolve(__dirname, '../../release/src/router/rc/firewall.c'), 'utf8');
const generators = source.split(/\nfilter_setting2?\(/).slice(1);
assert.equal(generators.length, 2);
assert(!source.includes('IPV4_INBOUND'));
for (const generator of generators) {
    const body = generator.slice(0, generator.indexOf('evalRet = eval("iptables-restore"'));
    const fallback = generator === generators[0] ? 'wan_if' : 'get_wan_ifname(wan_primary_ifunit())';
    const inputCall = `write_ipv4_inbound_rules(fp, ${fallback}, lan_ip, "INPUT", logaccept);`;
    const forwardCall = `write_ipv4_inbound_rules(fp, ${fallback}, lan_ip, "FORWARD", logaccept);`;
    assert(body.includes(inputCall + '\n\t\tfprintf(fp, "-A INPUT -j %s\\n", logdrop);'));
    assert(body.includes(forwardCall + '\n\n\t// Default rule'));
    const inputHook = body.indexOf(inputCall);
    const invalid = body.indexOf('"-A INPUT -m state --state INVALID');
    const access = body.indexOf('write_access_restriction(fp)', invalid);
    assert(invalid >= 0 && invalid < inputHook);
    assert(access >= 0 && access < inputHook);
}

const classifier = source.slice(source.indexOf('static int ipv4_rule_is_local'), source.indexOf('static void write_ipv4_inbound_rules'));
const translated = classifier.slice(classifier.indexOf('{') + 1, classifier.lastIndexOf('}'))
    .replace('struct in_addr address, lan_address;', 'let address = {}, lan_address = {};')
    .replace('const struct ifaddrs *entry;', 'let entry;')
    .replace('char host[INET_ADDRSTRLEN];', 'let host;')
    .replace('size_t length = strcspn(destination, "/");', 'let length = destination.includes("/") ? destination.indexOf("/") : destination.length;')
    .replace('sizeof(host)', '16')
    .replace('strcmp(destination + length, "/32")', '(destination.slice(length) === "/32" ? 0 : 1)')
    .replace('memcpy(host, destination, length);', 'host = destination.slice(0, length);')
    .replace("host[length] = '\\0';", '')
    .replaceAll('&address', 'address')
    .replaceAll('&lan_address', 'lan_address')
    .replace('((struct sockaddr_in *)entry->ifa_addr)->sin_addr.s_addr', 'entry.ifa_addr.sin_addr.s_addr')
    .replaceAll('->', '.');
const isLocal = new Function('destination', 'lan_ip', 'addresses', 'inet_pton', 'AF_INET', translated);
function parseAddress(family, text, output) {
    if (!net.isIPv4(text)) return 0;
    output.s_addr = text;
    return 1;
}
function interfaces(values) {
    return values.reduceRight((next, value) => ({
        ifa_next: next,
        ifa_addr: value === null ? null : {
            sa_family: value.includes(':') ? 10 : 2,
            sin_addr: {s_addr: value}
        }
    }), null);
}
const addresses = interfaces([null, 'fe80::1', '127.0.0.1', '10.0.0.51', '192.168.1.1', '10.99.99.99']);
for (const destination of ['10.0.0.51', '10.0.0.51/32', '192.168.1.1', '127.0.0.1', '10.99.99.99']) {
    assert.equal(isLocal(destination, '192.168.1.1', addresses, parseAddress, 2), 1, destination);
}
for (const destination of ['', '10.0.0.60', '10.0.0.0/24', '10.0.0.51/24', '0.0.0.0/0', '10.0.0.51/33', 'bad', '::1']) {
    assert.equal(isLocal(destination, '192.168.1.1', addresses, parseAddress, 2), 0, destination);
}
assert.equal(isLocal('192.168.1.1', '192.168.1.1', null, parseAddress, 2), 1);
assert.equal(isLocal('10.0.0.51', '192.168.1.1', null, parseAddress, 2), 0);
assert.equal(isLocal('10.0.0.51', null, addresses, parseAddress, 2), 1);

const writer = source.slice(source.indexOf('static void write_ipv4_inbound_rules'), source.indexOf('#define STOP_TIME'));
assert.match(writer, /if \(!nvram_get_int\("fw_enable_x"\)\)\s*return;/);
assert.match(writer, /getifaddrs\(&addresses\)/);
assert.match(writer, /freeifaddrs\(addresses\)/);
assert.match(writer, /\(strcmp\(chain, "INPUT"\) == 0\) != ipv4_rule_is_local\(destination, lan_ip, addresses\)/);
assert.equal((writer.match(/-A %s -i %s/g) || []).length, 3);
assert(writer.includes('chain, ifname, source_rule, destination_rule, port, logaccept'));
assert(writer.includes('chain, ifname, number, source_rule, destination_rule, logaccept'));
assert(writer.includes('strsep(&port_cursor, ",")'));
assert(writer.includes('fields >= 6 && interface && interface[0]'));

const selection = writer.match(/if \((\(strcmp\(chain, "INPUT"\) == 0\) != ipv4_rule_is_local\(destination, lan_ip, addresses\))\)/)[1];
const skipChain = new Function('chain', 'destination', 'lan_ip', 'addresses', 'strcmp', 'ipv4_rule_is_local', `return ${selection};`);
const compare = (left, right) => left === right ? 0 : 1;
const localCheck = (destination, lan, entries) => isLocal(destination, lan, entries, parseAddress, 2);
const formats = [...writer.matchAll(/fprintf\(fp, ("-A %s -i %s[^"\n]*"), (chain, ifname, [^;]+)\);/g)]
    .map(match => ({format: JSON.parse(match[1]), arguments: match[2].split(', ')}));
assert.equal(formats.length, 3);
function emit(destination, protocol, ports, sourceIP = '10.0.0.60', incoming = 'vlan4') {
    const output = [];
    for (const chain of ['INPUT', 'FORWARD']) {
        if (skipChain(chain, destination, '192.168.1.1', addresses, compare, localCheck)) continue;
        for (const port of ports.split(',')) {
            for (const [index, template] of formats.entries()) {
                if (!(protocol === ['TCP', 'UDP', 'OTHER'][index] || (protocol === 'BOTH' && index < 2))) continue;
                const values = {
                    chain, ifname: incoming || 'ppp0',
                    source_rule: sourceIP ? `-s ${sourceIP}` : '',
                    destination_rule: destination ? `-d ${destination}` : '',
                    port, number: port.split(':')[0], logaccept: 'ACCEPT'
                };
                let argument = 0;
                output.push(template.format.replace(/%s/g, () => values[template.arguments[argument++]]).trim());
            }
        }
    }
    return output;
}
assert.deepEqual(emit('10.0.0.51', 'UDP', '3784'), [
    '-A INPUT -i vlan4 -m state --state NEW -p udp -m udp -s 10.0.0.60 -d 10.0.0.51 --dport 3784 -j ACCEPT'
]);
assert.deepEqual(emit('10.0.0.51', 'UDP', '3784', '10.0.0.62'), [
    '-A INPUT -i vlan4 -m state --state NEW -p udp -m udp -s 10.0.0.62 -d 10.0.0.51 --dport 3784 -j ACCEPT'
]);
for (const destination of ['', '10.0.0.60', '10.0.0.0/24']) {
    const output = emit(destination, 'BOTH', '1:65535');
    assert.equal(output.length, 2);
    assert(output.every(rule => rule.startsWith('-A FORWARD -i vlan4 ') && rule.includes('--dport 1:65535')));
}
assert.equal(emit('10.0.0.51/32', 'BOTH', '3784,4784').length, 4);
assert(emit('10.0.0.51', 'OTHER', '89', '', '').every(rule => rule.startsWith('-A INPUT -i ppp0 -p 89 ')));

console.log('PASS: explicit router IPv4 destinations select INPUT; blank/nonlocal/subnet destinations retain FORWARD; both generators preserve drop ordering');