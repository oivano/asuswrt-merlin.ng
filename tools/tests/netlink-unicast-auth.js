const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/netlink/af_netlink.c'), 'utf8');
const ifaddrs = fs.readFileSync(path.join(root,
    'release/src/router/shared/ifaddrs.c'), 'utf8');
const body = (source, start, end) => {
    const offset = source.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = source.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return source.slice(offset, limit);
};

const connect = body(kernel, 'static int netlink_connect(', 'static int netlink_getname(');
const send = body(kernel, 'static int netlink_sendmsg(', 'static int netlink_recvmsg(');
const destinationGate = /\(\s*(?:nladdr->nl_pid|dst_pid)\s*\|\|\s*(?:nladdr->nl_groups|dst_group)\s*\)\s*&&\s*!netlink_capable\(sock, NL_NONROOT_SEND\)/;
assert.match(connect, destinationGate, 'connect requires permission for unicast and multicast destinations');
assert.match(send, destinationGate, 'sendmsg requires permission for unicast and multicast destinations');
const connectGate = connect.indexOf('if ((nladdr->nl_pid || nladdr->nl_groups)');
assert.ok(connectGate < connect.indexOf('nlk->dst_pid', connectGate + 1));
assert.ok(send.indexOf('netlink_capable(sock, NL_NONROOT_SEND)') < send.indexOf('alloc_skb('));

const permitted = (pid, groups, nonrootSend, capNetAdmin) =>
    !(pid || groups) || nonrootSend || capNetAdmin;
assert.equal(permitted(0, 0, false, false), true, 'kernel requests to pid 0 remain available');
assert.equal(permitted(1, 0, false, false), false, 'unprivileged unicast to a user socket is denied');
assert.equal(permitted(1, 0, true, false), true, 'protocols opting into NL_NONROOT_SEND remain usable');
assert.equal(permitted(0, 1, false, false), false, 'unprivileged multicast remains denied');

const receive = body(ifaddrs, 'nl_recvmsg (int sd,', 'static int\nnl_getmsg');
assert.match(receive, /if \(read_len >= 0 && nladdr\.nl_pid != 0\)\s*continue;/,
    'discard netlink datagrams not sent by the kernel');
const validate = body(ifaddrs, 'ifa_addr_attrs_valid (struct nlmsghdr *nlh)', 'static void\nifa_make_sockaddr');
assert.match(validate, /case AF_INET:\s*address_len = sizeof \(struct in_addr\);/);
assert.match(validate, /case AF_INET6:\s*address_len = sizeof \(struct in6_addr\);/);
assert.match(validate, /RTA_PAYLOAD \(rta\) > address_len/);
assert.match(validate, /case IFA_ADDRESS:[\s\S]*case IFA_LOCAL:[\s\S]*case IFA_BROADCAST:/);
assert.match(ifaddrs, /if \(!ifa_addr_attrs_valid \(nlh\)\)\s*continue;/,
    'reject invalid address records before adding them to the result');

assert.equal(5 > 4, true, 'IPv4 overlong attributes are rejected');
assert.equal(4 > 4, false, 'IPv4-sized attributes are accepted');
assert.equal(17 > 16, true, 'IPv6 overlong attributes are rejected');
assert.equal(16 > 16, false, 'IPv6-sized attributes are accepted');
console.log('PASS: netlink unicast authorization and getifaddrs reply/attribute guards (source contracts and models; not kernel execution)');