const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/tcp_input.c'), 'utf8');
const body = (start, end) => {
    const offset = source.indexOf(start);
    assert.ok(offset >= 0, `missing ${start}`);
    const limit = source.indexOf(end, offset + start.length);
    assert.ok(limit > offset, `missing ${end}`);
    return source.slice(offset, limit);
};

const collapse = body('static void tcp_collapse_ofo_queue(',
    '/*\n * Purge the out-of-order queue.');
assert.match(collapse, /range_truesize = skb->truesize;/);
assert.match(collapse, /range_truesize \+= skb->truesize;/);
assert.match(collapse, /range_truesize != head->truesize \|\|\s*end - start >= SKB_WITH_OVERHEAD\(SK_MEM_QUANTUM\)/);
assert.match(collapse, /sum_tiny \+= range_truesize;\s*if \(sum_tiny > \(sk->sk_rcvbuf >> 3\)\)\s*return;/);

const prune = body('static int tcp_prune_ofo_queue(',
    '/* Reduce allocated memory if we can');
assert.match(prune, /goal = sk->sk_rcvbuf >> 3;/);
assert.match(prune, /skb = skb_peek_tail\(&tp->out_of_order_queue\);/);
assert.match(prune, /skb_queue_prev\(&tp->out_of_order_queue, skb\)/);
assert.match(prune, /__skb_unlink\(skb, &tp->out_of_order_queue\);\s*__kfree_skb\(skb\);/);
assert.match(prune, /if \(!prev \|\| goal == 0\) \{\s*sk_mem_reclaim\(sk\);/);
assert.match(prune, /atomic_read\(&sk->sk_rmem_alloc\) <= sk->sk_rcvbuf &&\s*!tcp_memory_pressure/);
assert.match(prune, /if \(res && tp->rx_opt.sack_ok\)\s*tcp_sack_reset\(&tp->rx_opt\);/);

console.log('PASS: TCP out-of-order collapse guards and batched-prune source contracts (not kernel execution)');