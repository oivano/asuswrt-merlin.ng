const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const ipv6 = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/netfilter/nf_conntrack_l3proto_ipv6.c'), 'utf8');
const conntrack = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/nf_conntrack_core.c'), 'utf8');

const defragStart = ipv6.indexOf('static unsigned int ipv6_defrag(');
const defragEnd = ipv6.indexOf('static unsigned int __ipv6_conntrack_in(', defragStart);
assert.ok(defragStart >= 0 && defragEnd > defragStart);
const defrag = ipv6.slice(defragStart, defragEnd);
const output = defrag.indexOf('nf_ct_frag6_output(');
assert.ok(output >= 0);
assert.match(defrag.slice(output),
    /^nf_ct_frag6_output\([\s\S]*?\);\s*return NF_STOLEN;\s*\}/);
assert.doesNotMatch(defrag.slice(output), /nf_ct_get|ip_conntrack_ipct_add/);

const confirmStart = ipv6.indexOf('static unsigned int ipv6_confirm(');
const confirmEnd = ipv6.indexOf('static enum ip6_defrag_users', confirmStart);
assert.ok(confirmStart >= 0 && confirmEnd > confirmStart);
const confirm = ipv6.slice(confirmStart, confirmEnd);
assert.match(confirm,
    /ret = nf_conntrack_confirm\(skb\);\s*if \(ret == NF_ACCEPT\) \{\s*ct = nf_ct_get\(skb, &ctinfo\);\s*ip_conntrack_ipct_add\(skb, hooknum, ct, ctinfo, NULL\);\s*\}\s*return ret;/);
const hookOps = ipv6.slice(ipv6.indexOf('static struct nf_hook_ops ipv6_conntrack_ops'));
assert.match(hookOps,
    /\.hook\s*= ipv6_confirm,[\s\S]*?\.hooknum\s*= NF_INET_POST_ROUTING,[\s\S]*?\.priority\s*= NF_IP6_PRI_LAST/);

const addStart = conntrack.indexOf('ip_conntrack_ipct_add(struct sk_buff');
const addEnd = conntrack.indexOf('\nint\nip_conntrack_ipct_delete', addStart);
assert.ok(addStart >= 0 && addEnd > addStart);
const add = conntrack.slice(addStart, addEnd);
assert.match(add,
    /if \(\(skb == NULL\) \|\| \(ct == NULL\)\)\s*return;\s*if \(\(hooknum != NF_INET_POST_ROUTING\) \|\| !nf_ct_is_confirmed\(ct\) \|\|\s*nf_ct_is_dying\(ct\)\)\s*return;/);

console.log('PASS: defrag returns after output; IPv6 CTF insertion follows final POST_ROUTING confirmation; shared CTF add requires a confirmed, live flow (source contracts only)');