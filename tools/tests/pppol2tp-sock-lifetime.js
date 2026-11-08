const assert = require('assert');
const fs = require('fs');

const base = 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/l2tp/';
const ppp = fs.readFileSync(`${base}l2tp_ppp.c`, 'utf8');
const core = fs.readFileSync(`${base}l2tp_core.c`, 'utf8');
const header = fs.readFileSync(`${base}l2tp_core.h`, 'utf8');

assert(ppp.includes('struct sock __rcu\t*sk;'));
assert(ppp.includes('atomic_inc_not_zero(&sk->sk_refcnt)'));
assert(!/ps->sock\b/.test(ppp));
assert(!ppp.includes('pppol2tp_session_sock_hold'));
assert(ppp.includes('struct pppol2tp_session *ps = l2tp_session_priv(session);'));

const release = ppp.slice(ppp.indexOf('static int pppol2tp_release('), ppp.indexOf('static struct proto pppol2tp_sk_proto'));
assert(release.includes('hlist_del_init(&session->hlist)'));
assert(release.includes('rcu_assign_pointer(ps->sk, NULL)'));
assert(release.includes('__l2tp_session_unhash(session)'));
assert(release.includes('call_rcu(&ps->rcu, pppol2tp_put_sk)'));

const close = ppp.slice(ppp.indexOf('static void pppol2tp_session_close('), ppp.indexOf('static void pppol2tp_session_destruct('));
const queuePurge = close.slice(close.indexOf('while ((skb = skb_dequeue(&session->reorder_q)))'), close.indexOf('release_sock(sk);'));
assert(!queuePurge.includes('sock_put(sk)'));

const lookup = core.slice(core.indexOf('struct l2tp_session *l2tp_session_find_get('), core.indexOf('EXPORT_SYMBOL_GPL(l2tp_session_find_get)'));
assert(lookup.indexOf('read_lock_bh(&tunnel->hlist_lock)') < lookup.indexOf('atomic_inc_not_zero(&session->ref_count)'));
assert(lookup.indexOf('atomic_inc_not_zero(&session->ref_count)') < lookup.indexOf('read_unlock_bh(&tunnel->hlist_lock)'));
assert(core.includes('session = l2tp_session_find_get(tunnel, session_id);') ||
    core.includes('session = l2tp_session_get(tunnel->l2tp_net, tunnel, session_id, 1);'));
assert(header.includes('l2tp_session_find_get'));
assert(header.includes('__l2tp_session_unhash'));

console.log('PPPoL2TP socket lifetime source contracts passed');