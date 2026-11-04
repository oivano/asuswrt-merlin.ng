const assert = require('assert');
const fs = require('fs');

const root = require('path').resolve(__dirname, '../..');
const read = path => fs.readFileSync(require('path').join(root, path), 'utf8');

const netlinkHeader = read('release/src-rt-6.x.4708/linux/linux-2.6.36/include/linux/netlink.h');
const netlinkSource = read('release/src-rt-6.x.4708/linux/linux-2.6.36/net/netlink/af_netlink.c');
const commoncap = read('release/src-rt-6.x.4708/linux/linux-2.6.36/security/commoncap.c');
const crontab = read('release/src/router/busybox/miscutils/crontab.c');
const busyboxMake = read('release/src/router/Makefile');
const busyboxConfig = read('release/src/router/busybox/.config');

assert.match(netlinkHeader, /#define NETLINK_SKB_DST\s+0x1/);
assert.match(netlinkHeader, /__u32\s+flags;\s+kernel_cap_t\s+eff_cap;/);

const sendmsg = netlinkSource.slice(
	netlinkSource.indexOf('static int netlink_sendmsg('),
	netlinkSource.indexOf('static int netlink_recvmsg(')
);
assert.match(sendmsg, /netlink_skb_flags\s*=\s*0/);
assert.match(sendmsg, /if \(msg->msg_namelen\)[\s\S]*?netlink_skb_flags\s*\|=\s*NETLINK_SKB_DST/);
assert.match(sendmsg, /NETLINK_CB\(skb\)\.flags\s*=\s*netlink_skb_flags/);

const capSend = commoncap.slice(
	commoncap.indexOf('int cap_netlink_send('),
	commoncap.indexOf('EXPORT_SYMBOL(cap_netlink_send)')
);
assert.match(capSend, /eff_cap\s*=\s*current_cap\(\)/);
assert.match(capSend, /if \(!\(NETLINK_CB\(skb\)\.flags & NETLINK_SKB_DST\)\)/);
assert.match(capSend, /cap_intersect\(eff_cap,\s*sk->sk_socket->file->f_cred->cap_effective\)/);
assert.match(capSend, /else\s+cap_clear\(eff_cap\)/);
assert.match(commoncap, /!cap_raised\(NETLINK_CB\(skb\)\.eff_cap, cap\)/);

const crontabList = crontab.slice(
	crontab.indexOf('case OPT_l:'),
	crontab.indexOf('case OPT_e:')
);
assert(crontabList.indexOf('open(pas->pw_name, O_RDONLY)') < crontabList.indexOf('setgid(getgid())'));
assert(crontabList.indexOf('setgid(getgid())') < crontabList.indexOf('bb_copyfd_eof(fd, STDOUT_FILENO)'));
assert(crontabList.indexOf('setuid(getuid())') < crontabList.indexOf('bb_copyfd_eof(fd, STDOUT_FILENO)'));
assert.match(crontabList, /geteuid\(\) != getuid\(\)/);
assert.match(crontabList, /setgid\(getgid\(\)\) \|\| setuid\(getuid\(\)\)/);
assert.match(crontabList, /bb_copyfd_eof\(fd, STDOUT_FILENO\) < 0/);
assert.match(crontab, /APPLET\(crontab, BB_DIR_USR_BIN, BB_SUID_REQUIRE\)/);
assert.match(busyboxConfig, /^CONFIG_FEATURE_SUID=y$/m);
assert.match(busyboxConfig, /^# CONFIG_FEATURE_SUID_CONFIG is not set$/m);
assert.match(busyboxMake, /chmod 4755 \$\(INSTALLDIR\)\/\$\(BUSYBOX\)\/bin\/busybox/);

const authorize = (writer, opener, explicitDestination) =>
	explicitDestination ? writer : writer && opener;
assert.strictEqual(authorize(true, false, false), false);
assert.strictEqual(authorize(true, true, false), true);
assert.strictEqual(authorize(false, true, false), false);
assert.strictEqual(authorize(true, false, true), true);

console.log('netlink setuid crontab source contracts passed');