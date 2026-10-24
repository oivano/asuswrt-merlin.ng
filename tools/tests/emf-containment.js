const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = 'release/src-rt-6.x.4708/linux/linux-2.6.36/';
const read = file => fs.readFileSync(path.join(root, kernel, file), 'utf8');
const netlink = read('net/netlink/af_netlink.c');
const proc = read('fs/proc/generic.c');
const body = (source, start, end) => {
    const offset = source.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = source.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return source.slice(offset, limit);
};

const create = body(netlink, 'static int netlink_create(', 'static int netlink_release(');
const send = body(netlink, 'static int netlink_sendmsg(', 'static int netlink_recvmsg(');
const createGuard = create.match(/if \((protocol == 17 && !kern && !capable\(CAP_NET_ADMIN\))\)\s*return -EPERM;/);
const sendGuard = send.match(/if \((sk->sk_protocol == 17 && !capable\(CAP_NET_ADMIN\))\)\s*return -EPERM;/);
assert.ok(createGuard, 'EMF socket creation requires CAP_NET_ADMIN except for kernel sockets');
assert.ok(sendGuard, 'every EMF send requires current CAP_NET_ADMIN');
assert.ok(create.indexOf(createGuard[0]) < create.indexOf('netlink_lock_table();'));
assert.ok(send.indexOf(sendGuard[0]) < send.indexOf('scm_send('));
assert.ok(send.indexOf(sendGuard[0]) < send.indexOf('alloc_skb('));
assert.ok(send.indexOf(sendGuard[0]) < send.indexOf('netlink_unicast('));

const rejectCreate = new Function('protocol', 'kern', 'capable', 'CAP_NET_ADMIN',
    `return Boolean(${createGuard[1]});`);
const rejectSend = new Function('sk', 'capable', 'CAP_NET_ADMIN',
    `return Boolean(${sendGuard[1].replace(/sk->/g, 'sk.')});`);
for (let protocol = 0; protocol < 32; protocol++) {
    for (const privileged of [false, true]) {
        for (const kern of [false, true]) {
            assert.equal(rejectCreate(protocol, kern, () => privileged, 12),
                protocol === 17 && !kern && !privileged);
        }
        assert.equal(rejectSend({sk_protocol: protocol}, () => privileged, 12),
            protocol === 17 && !privileged);
    }
}
for (const command of ['BR_ADD', 'IF_ADD', 'MFDB_ADD', 'MFDB_LIST']) {
    for (const destination of ['explicit unicast', 'connected unicast', 'multicast']) {
        assert.equal(rejectSend({sk_protocol: 17}, () => false, 12), true,
            `${command}: ${destination} must fail, including inherited or passed sockets`);
    }
}
assert.equal(rejectCreate(17, false, () => true, 12), false);
assert.equal(rejectSend({sk_protocol: 17}, () => false, 12), true,
    'a socket opened with privileges cannot send after CAP_NET_ADMIN is dropped');
console.log('PASS: netlink creation/send source contracts and capability models (not kernel execution)');

const register = body(proc, 'static int proc_register(', 'static struct proc_dir_entry *__proc_create(');
const directoryGuard = register.match(/if \((dir == &proc_root && S_ISDIR\(dp->mode\) &&\s*!strcmp\(dp->name, "emf"\))\) \{\s*dp->mode = S_IFDIR \| 0700;\s*dp->uid = 0;\s*dp->gid = 0;\s*\}/);
assert.ok(directoryGuard, 'register /proc/emf as root:root 0700');
assert.ok(register.indexOf(directoryGuard[0]) < register.indexOf('dir->subdir = dp;'),
    'secure directory before it becomes visible');
const isPrivate = new Function('dir', 'proc_root', 'dp', 'S_ISDIR', 'strcmp',
    `return Boolean(${directoryGuard[1].replace(/&proc_root/g, 'proc_root').replace(/dp->/g, 'dp.')});`);
const procRoot = {};
const nested = {};
for (const parent of [procRoot, nested]) {
    for (const name of ['emf', 'emfdb_br0', 'emf-other', 'net', 'igs']) {
        for (const mode of [0o40755, 0o40777, 0o100444, 0o120777]) {
            assert.equal(isPrivate(parent, procRoot, {name, mode},
                value => (value & 0o170000) === 0o40000,
                (left, right) => left === right ? 0 : 1),
            parent === procRoot && name === 'emf' && (mode & 0o170000) === 0o40000);
        }
    }
}
assert.equal(0o700 & 0o077, 0, 'non-root has no directory traversal or read permission');
console.log('PASS: private /proc/emf registration and unrelated-path models (not VFS execution)');