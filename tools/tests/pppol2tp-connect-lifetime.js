const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36');
const core = fs.readFileSync(path.join(kernel, 'net/l2tp/l2tp_core.c'), 'utf8');
const header = fs.readFileSync(path.join(kernel, 'net/l2tp/l2tp_core.h'), 'utf8');
const ppp = fs.readFileSync(path.join(kernel, 'net/l2tp/l2tp_ppp.c'), 'utf8');

const lookupStart = core.indexOf('struct l2tp_tunnel *l2tp_tunnel_find_get(');
const lookupEnd = core.indexOf('\nEXPORT_SYMBOL_GPL(l2tp_tunnel_find_get);', lookupStart);
assert.ok(lookupStart >= 0 && lookupEnd > lookupStart,
    'missing referenced tunnel lookup');
const lookup = core.slice(lookupStart, lookupEnd);
assert.match(lookup, /rcu_read_lock_bh\(\)/);
assert.match(lookup, /atomic_inc_not_zero\(&tunnel->ref_count\)/);
assert.ok(lookup.indexOf('atomic_inc_not_zero(&tunnel->ref_count)') <
    lookup.indexOf('rcu_read_unlock_bh()'),
    'tunnel reference must be acquired before leaving RCU');

const connectStart = ppp.indexOf('static int pppol2tp_connect(');
const connectEnd = ppp.indexOf('\n#ifdef CONFIG_L2TP_V3', connectStart);
assert.ok(connectStart >= 0 && connectEnd > connectStart,
    'missing pppol2tp_connect');
const connect = ppp.slice(connectStart, connectEnd);
assert.match(connect, /l2tp_tunnel_find_get\(sock_net\(sk\), tunnel_id\)/);
assert.match(connect,
    /write_lock_bh\(&tunnel->hlist_lock\);[\s\S]*?tunnel->closing \|\| tunnel->sock == NULL \|\|[\s\S]*?atomic_inc_not_zero\(&tunnel->sock->sk_refcnt\)/);
assert.match(connect, /inet_sk\(tunnel_sock\)/);
assert.match(connect, /ps->tunnel_sock\s*=\s*tunnel_sock/);
assert.match(connect, /sk_dst_get\(tunnel_sock\)/);
assert.ok(connect.lastIndexOf('sock_put(tunnel_sock)') <
    connect.lastIndexOf('l2tp_tunnel_dec_refcount(tunnel)'),
    'common exit must release the socket and tunnel references');

const destructStart = core.indexOf('void l2tp_tunnel_destruct(');
const destructEnd = core.indexOf('\nEXPORT_SYMBOL(l2tp_tunnel_destruct);', destructStart);
assert.ok(destructStart >= 0 && destructEnd > destructStart,
    'missing tunnel destructor');
const destruct = core.slice(destructStart, destructEnd);
assert.match(destruct,
    /write_lock_bh\(&tunnel->hlist_lock\);\s*tunnel->closing = 1;\s*write_unlock_bh\(&tunnel->hlist_lock\);[\s\S]*?l2tp_tunnel_closeall\(tunnel\)/);
assert.match(destruct,
    /write_lock_bh\(&tunnel->hlist_lock\);\s*tunnel->sock = NULL;\s*write_unlock_bh\(&tunnel->hlist_lock\);/);
assert.match(header, /int\s+closing;\s*\/\* reject new sessions during teardown \*\//);

const createStart = core.indexOf('struct l2tp_session *l2tp_session_create(');
const createEnd = core.indexOf('\nEXPORT_SYMBOL_GPL(l2tp_session_create);', createStart);
assert.ok(createStart >= 0 && createEnd > createStart,
    'missing l2tp_session_create');
const create = core.slice(createStart, createEnd);
assert.match(create,
    /write_lock_bh\(&tunnel->hlist_lock\);[\s\S]*?sock = tunnel->sock;[\s\S]*?tunnel->closing \|\| sock == NULL \|\|[\s\S]*?atomic_inc_not_zero\(&sock->sk_refcnt\)/);
assert.ok(create.indexOf('hlist_add_head(&session->hlist') <
    create.lastIndexOf('write_unlock_bh(&tunnel->hlist_lock)'),
    'session publication must remain serialized with teardown');
assert.doesNotMatch(create, /sock_hold\(tunnel->sock\)/);

console.log('PPPoL2TP connect/teardown lifetime contracts passed');