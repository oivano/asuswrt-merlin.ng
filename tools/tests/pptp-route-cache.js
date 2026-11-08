const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const sourcePath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/drivers/net/pptp.c';
const source = fs.readFileSync(path.join(root, sourcePath), 'utf8');
const connectStart = source.indexOf('static int pptp_connect(');
const connectEnd = source.indexOf('static int pptp_getname(', connectStart);
assert.ok(connectStart >= 0 && connectEnd > connectStart, 'pptp_connect implementation exists');

const connect = source.slice(connectStart, connectEnd);
const setup = connect.indexOf('sk_setup_caps(sk, &rt->dst);');
const put = connect.indexOf('ip_rt_put(rt);', setup);
assert.ok(setup >= 0 && put > setup, 'route is installed before legacy route release');
assert.match(connect.slice(setup, put), /#if LINUX_VERSION_CODE < KERNEL_VERSION\(2,6,0\)/,
    'only the pre-2.6 path releases the route locally');

const destructStart = source.lastIndexOf('static void pptp_sock_destruct(struct sock *sk)');
const destructEnd = source.indexOf('\n}', destructStart);
assert.ok(destructStart >= 0 && destructEnd > destructStart, 'modern PPTP destructor exists');
const destruct = source.slice(destructStart, destructEnd);
assert.match(destruct, /^static void pptp_sock_destruct\(struct sock \*sk\)\s*\{\s*sk_dst_reset\(sk\);/,
    'PPTP destructor releases its cached route before protocol teardown');
assert.match(source, /sk->sk_destruct\s*=\s*pptp_sock_destruct;/,
    'PPTP socket uses the destructor that releases its route cache');

console.log('PASS: PPTP route-cache ownership (source contract; not kernel execution)');
