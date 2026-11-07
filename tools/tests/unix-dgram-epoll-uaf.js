const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const kernel = path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36');
const source = fs.readFileSync(path.join(kernel, 'net/unix/af_unix.c'), 'utf8');
const header = fs.readFileSync(path.join(kernel, 'include/net/af_unix.h'), 'utf8');

assert.match(header, /wait_queue_t\s+peer_wake;/);
assert.match(source,
    /init_waitqueue_func_entry\(&u->peer_wake, unix_dgram_peer_wake_relay\);/);

const relayStart = source.indexOf('static int unix_dgram_peer_wake_relay(');
const relayEnd = source.indexOf('static void unix_dgram_peer_wake_connect(', relayStart);
const relay = source.slice(relayStart, relayEnd);
assert.match(relay, /container_of\(q, struct unix_sock, peer_wake\)/);
assert.match(relay, /__remove_wait_queue\(&u_other->peer_wait, q\)/);
assert.match(relay, /u->peer_wake\.private = NULL/);
assert.match(relay, /wake_up_interruptible_poll\(u_sleep, key\)/);

const connectStart = source.indexOf('static void unix_dgram_peer_wake_connect(');
const disconnectStart = source.indexOf('static void unix_dgram_peer_wake_disconnect(', connectStart);
const connect = source.slice(connectStart, disconnectStart);
assert.match(connect, /spin_lock\(&u_other->peer_wait\.lock\)/);
assert.match(connect, /u->peer_wake\.private = other/);
assert.match(connect, /__add_wait_queue\(&u_other->peer_wait, &u->peer_wake\)/);

const disconnectEnd = source.indexOf('static void unix_dgram_peer_wake_disconnect_wakeup(',
    disconnectStart);
const disconnect = source.slice(disconnectStart, disconnectEnd);
assert.match(disconnect, /spin_lock\(&u_other->peer_wait\.lock\)/);
assert.match(disconnect, /u->peer_wake\.private == other/);
assert.match(disconnect, /__remove_wait_queue\(&u_other->peer_wait, &u->peer_wake\)/);
assert.match(disconnect, /u->peer_wake\.private = NULL/);

const pollStart = source.indexOf('static unsigned int unix_dgram_poll(');
const pollEnd = source.indexOf('\n#ifdef CONFIG_PROC_FS', pollStart);
const poll = source.slice(pollStart, pollEnd);
assert.match(poll, /unix_state_lock\(sk\)/);
assert.match(poll, /unix_dgram_peer_wake_connect\(sk, other\)/);
assert.doesNotMatch(poll, /sock_poll_wait\(file,\s*&unix_sk\(other\)->peer_wait/);

const dgramDisconnect = source.slice(
    source.indexOf('static void unix_dgram_disconnected('),
    source.indexOf('static long unix_wait_for_peer('));
assert.match(dgramDisconnect,
    /unix_dgram_peer_wake_disconnect_wakeup\(sk, other\)/);

const connectFnStart = source.lastIndexOf('static int unix_dgram_connect(');
const connectFnEnd = source.indexOf('static long unix_wait_for_peer(', connectFnStart);
const connectFn = source.slice(connectFnStart, connectFnEnd);
const reconnectDetach = connectFn.indexOf('unix_dgram_peer_wake_disconnect(sk, old_peer)');
assert.ok(reconnectDetach >= 0);
assert.ok(reconnectDetach < connectFn.indexOf('unix_state_double_unlock(sk, other)',
    reconnectDetach));

const releasePeer = source.slice(source.indexOf('skpair = unix_peer(sk);'),
    source.indexOf('/* Try to flush out this socket.', source.indexOf('skpair = unix_peer(sk);')));
assert.ok(releasePeer.indexOf('unix_dgram_peer_wake_disconnect(sk, skpair)') <
    releasePeer.indexOf('sock_put(skpair)'));

console.log('AF_UNIX datagram epoll peer-wait lifetime contracts passed');