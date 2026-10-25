const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const source = read('release/src/router/infosvr/infosvr.c');
const common = read('release/src/router/infosvr/common.c');
const storage = read('release/src/router/infosvr/storage.c');

const hostnameCopy = storage.match(/snprintf\(st->u\.wt\.HostName, sizeof\(st->u\.wt\.HostName\), "%s", nvram_safe_get\("ddns_hostname_x"\)\);/);
assert(hostnameCopy, 'DDNS hostname must only be used as data');
const copyHostname = new Function('st', 'snprintf', 'nvram_safe_get', hostnameCopy[0]
    .replace('sizeof(st->u.wt.HostName)', '64').replace(/->/g, '.'));
for (const value of ['%n%n%s%s%x%x', 'router.example', 'A'.repeat(80) + '%n']) {
    const output = Buffer.alloc(64, 0xa5);
    copyHostname({ u: { wt: { HostName: output } } }, (target, size, format, data) => {
        assert.equal(format, '%s');
        const bytes = Buffer.from(data);
        bytes.copy(target, 0, 0, size - 1);
        target[Math.min(bytes.length, size - 1)] = 0;
    }, () => value);
    assert.equal(output.subarray(0, output.indexOf(0)).toString(), value.slice(0, 63));
}

function body(text, name) {
    const match = new RegExp('(?:static )?(?:int|DWORD|char \\*)\\s*' + name + '\\([^;{]*\\)\\s*\\{').exec(text);
    assert(match, name);
    const start = text.indexOf('{', match.index);
    let end = start + 1;
    let depth = 1;
    while (depth && end < text.length) {
        if (text[end] === '{') depth++;
        if (text[end] === '}') depth--;
        end++;
    }
    assert.equal(depth, 0);
    return text.slice(start + 1, end - 1);
}

const processPacket = body(common, 'processPacket');
assert.doesNotMatch(common, /case\s+NET_CMD_ID_GETINFO_MANU\s*:/);
assert.doesNotMatch(common, /nvram_set\s*\(\s*"asus_mfg"/);
const rejection = processPacket.match(/if \(realOPCode == NET_CMD_ID_GETINFO_MANU\)\s*return NULL;/);
assert(rejection);
assert(processPacket.indexOf(rejection[0]) < processPacket.indexOf('last_opcode =='));
assert(processPacket.indexOf(rejection[0]) < processPacket.indexOf('phdr_res->ServiceID='));
assert.match(processPacket, /case NET_CMD_ID_GETINFO:/);
assert.match(processPacket, /default:\s*return NULL;/);

for (const mode of ['0', '1']) {
    const nvram = { asus_mfg: mode, unrelated: 'preserved' };
    const before = JSON.stringify(nvram);
    let reads = 0;
    let writes = 0;
    const rejectManufacturing = vm.runInNewContext(`(function(realOPCode) {
        ${rejection[0]}
        throw new Error('manufacturing request reached dispatch');
    })`, {
        NET_CMD_ID_GETINFO_MANU: 0x34,
        NULL: null,
        nvram_set: (key, value) => { writes++; nvram[key] = value; },
        nvram_safe_get: key => { reads++; return nvram[key] || ''; }
    });
    const packet = Buffer.alloc(512);
    packet[0] = 12;
    packet[1] = 21;
    packet.writeUInt16LE(0x34, 2);
    assert.equal(rejectManufacturing(packet.readUInt16LE(2)), null);
    assert.equal(reads, 0);
    assert.equal(writes, 0);
    assert.equal(JSON.stringify(nvram), before);
}

const main = body(source, 'main');
assert.match(main, /if \(setsockopt\(sockfd, IPPROTO_IP, IP_PKTINFO, &flag, sizeof\(flag\)\) < 0\)\s*\{\s*perror\("IP_PKTINFO:"\);\s*close\(sockfd\);\s*return 1;/);
assert(main.indexOf('IP_PKTINFO') < main.indexOf('bind(sockfd'));
const receive = body(source, 'RECV');
assert.match(receive, /recvmsg\(sockfd, &message, 0\)/);
assert.match(receive, /received != dwlen \|\| \(message.msg_flags & \(MSG_TRUNC \| MSG_CTRUNC\)\)/);
assert.match(receive, /message.msg_namelen != sizeof\(struct sockaddr_in\)/);
assert.match(receive, /unsigned int ifindex = 0;/);
assert.match(receive, /header->cmsg_level == IPPROTO_IP && header->cmsg_type == IP_PKTINFO &&\s*header->cmsg_len == CMSG_LEN\(sizeof\(packet_info\)\)/);
assert.match(receive, /memcpy\(&packet_info, CMSG_DATA\(header\), sizeof\(packet_info\)\)/);
assert.match(receive, /ifindex = packet_info.ipi_ifindex;/);
assert.match(receive, /source->sin_family != AF_INET \|\| !lan_source_allowed\(source->sin_addr, ifindex\)\)\s*return -1;/);
assert(receive.indexOf('!lan_source_allowed') < receive.indexOf('return received;'));
const request = body(source, 'processReq');
assert(request.indexOf('iRcv != INFO_PDU_LENGTH') < request.indexOf('processPacket('));

function ipv4(value) {
    const parts = value.split('.');
    if (parts.length !== 4 || parts.some(part => !/^\d+$/.test(part) || Number(part) > 255)) return null;
    return parts.reduce((result, part) => (result * 256 + Number(part)) >>> 0, 0);
}

let settings = { lan_ifname: 'br0', lan_ipaddr: '192.168.1.1', lan_netmask: '255.255.255.0' };
let bridgeIndex = 7;
const policy = body(source, 'lan_source_allowed')
    .replace(/struct in_addr lan_addr, lan_mask;/, 'let lan_addr = {}, lan_mask = {};')
    .replace(/unsigned int mask, host;/, 'let mask, host;')
    .replace(/const char \*ifname =/, 'let ifname =')
    .replace(/!\*ifname/g, '!ifname.length')
    .replace(/&(lan_addr|lan_mask)\)/g, '$1)')
    .replace(/host >>/g, 'host >>>');
const allowed = vm.runInNewContext(`(function(source, ifindex) { ${policy} })`, {
    LAN_DEV: 'br0',
    nvram_safe_get: key => settings[key] || '',
    if_nametoindex: name => name === (settings.lan_ifname || 'br0') ? bridgeIndex : 0,
    ntohl: value => value >>> 0,
    inet_aton: (value, result) => {
        const parsed = ipv4(value);
        if (parsed === null) return 0;
        result.s_addr = parsed;
        return 1;
    }
});
const check = (address, index = 7) => allowed({ s_addr: ipv4(address) }, index);
for (const address of ['192.168.1.2', '192.168.1.254']) assert.equal(check(address), 1, address);
for (const address of ['192.168.1.0', '192.168.1.255', '192.168.2.2', '10.0.0.2',
    '0.0.0.0', '127.0.0.1', '224.0.0.1', '255.255.255.255']) assert.equal(check(address), 0, address);
for (const index of [0, 3, 8]) assert.equal(check('192.168.1.2', index), 0, 'WAN/guest/missing ingress');
bridgeIndex = 0;
assert.equal(check('192.168.1.2'), 0, 'missing LAN interface');
bridgeIndex = 7;
for (const mask of ['', 'invalid', '0.0.0.0', '255.0.255.0']) {
    settings.lan_netmask = mask;
    assert.equal(check('192.168.1.2'), 0, mask);
}
settings.lan_netmask = '255.255.255.192';
assert.equal(check('192.168.1.62'), 1);
assert.equal(check('192.168.1.63'), 0);
assert.equal(check('192.168.1.64'), 0);
settings.lan_ipaddr = 'invalid';
assert.equal(check('192.168.1.2'), 0);
settings = { lan_ifname: 'br1', lan_ipaddr: '10.0.0.1', lan_netmask: '255.255.0.0' };
assert.equal(check('10.0.1.2'), 1, 'configured LAN bridge/subnet');
assert.equal(check('192.168.1.2'), 0, 'old subnet');
settings.lan_ifname = '';
assert.equal(check('10.0.1.2'), 1, 'default bridge fallback');

console.log('PASS: infosvr literal DDNS hostname copy, manufacturing rejection, receive source contracts, and source-derived LAN policy');
console.log('Not compiled C or live UDP/firmware validation.');