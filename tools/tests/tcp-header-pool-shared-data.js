const assert = require('assert');
const fs = require('fs');

const source = fs.readFileSync(
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/core/skbuff.c',
    'utf8'
);
const match = source.match(/skb_tcph_pool_free\(tcph_pool_t \*tcph_pool, struct sk_buff \*skb\)\s*\{([\s\S]*?)\n\}/);

assert(match, 'TCP header pool free function must exist');

const body = match[1];
const sharedBranch = body.indexOf('atomic_sub_return(');
const shellFree = body.indexOf('kfree_skbmem(skb);', sharedBranch);
const replacementAlloc = body.indexOf('skb = dev_alloc_skb(tcph_pool->obj_size);', shellFree);
const replacementMark = body.indexOf('skb->tcpf_hdrbuf = 1;', replacementAlloc);
const poolInsert = body.indexOf('skb->next = (struct sk_buff *)tcph_pool->head;', replacementMark);

assert(sharedBranch >= 0, 'cloned pool buffers must drop their shared data reference');
assert(shellFree > sharedBranch, 'a still-shared skb shell must not return to the pool');
assert(replacementAlloc > shellFree, 'the pool should be replenished with a fresh skb');
assert(replacementMark > replacementAlloc, 'replacement skb must use the pool free path');
assert(poolInsert > replacementMark, 'only the replacement skb may be inserted into the pool');
assert(body.includes('if (skb == NULL)\n\t\t\treturn;'), 'allocation failure must safely leave the pool smaller');