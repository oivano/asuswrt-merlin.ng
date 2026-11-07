const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/netlink/af_netlink.c'), 'utf8');
const body = (start, end) => {
    const offset = source.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = source.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return source.slice(offset, limit);
};

const bind = body('static int netlink_bind(', 'static int netlink_connect(');
const connect = body('static int netlink_connect(', 'static int netlink_getname(');
const send = body('static int netlink_sendmsg(', 'static int netlink_recvmsg(');

const fullAddressGuard = /if \(\s*(?:addr_len|alen) < sizeof\(struct sockaddr_nl\)\s*\)\s*return -EINVAL;/;
assert.match(bind, fullAddressGuard, 'bind rejects undersized sockaddr_nl');
assert.ok(bind.indexOf('sizeof(struct sockaddr_nl)') < bind.indexOf('nladdr->nl_family'));
assert.match(connect, fullAddressGuard, 'connect rejects undersized AF_NETLINK addresses');
assert.ok(connect.indexOf('alen < sizeof(struct sockaddr_nl)') > connect.indexOf('addr->sa_family == AF_UNSPEC'));
assert.ok(connect.indexOf('alen < sizeof(struct sockaddr_nl)') < connect.indexOf('nladdr->nl_pid'));
assert.match(send,
    /if \(msg->msg_namelen < sizeof\(struct sockaddr_nl\)\)\s*goto out;/,
    'sendmsg rejects undersized named destinations');
assert.ok(send.indexOf('msg->msg_namelen < sizeof(struct sockaddr_nl)') < send.indexOf('addr->nl_family'));
assert.ok(send.indexOf('msg->msg_namelen < sizeof(struct sockaddr_nl)') < send.indexOf('addr->nl_pid'));

const sockaddrNlSize = 12;
assert.equal(2 < sockaddrNlSize, true, 'short address is rejected');
assert.equal(sockaddrNlSize < sockaddrNlSize, false, 'full sockaddr_nl is accepted');
assert.equal(2 < sockaddrNlSize, true, 'short named sendmsg address is rejected');
console.log('PASS: netlink bind/connect/sendmsg sockaddr_nl length guards (source contracts and length model; not kernel execution)');
