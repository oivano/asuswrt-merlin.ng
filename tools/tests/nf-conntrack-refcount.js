#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const kernel = path.join(__dirname, '../../release/src-rt-6.x.4708/linux/linux-2.6.36');
const core = fs.readFileSync(path.join(kernel, 'net/netfilter/nf_conntrack_core.c'), 'utf8');
const netlink = fs.readFileSync(path.join(kernel, 'net/netfilter/nf_conntrack_netlink.c'), 'utf8');
const xtCt = fs.readFileSync(path.join(kernel, 'net/netfilter/xt_CT.c'), 'utf8');

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert.notStrictEqual(start, -1, `missing function: ${signature}`);
    const open = source.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < source.length; index++) {
        if (source[index] === '{') {
            depth++;
        } else if (source[index] === '}' && --depth === 0) {
            return source.slice(open + 1, index);
        }
    }
    assert.fail(`unterminated function: ${signature}`);
}

const keyEqual = functionBody(core, 'static inline bool nf_ct_key_equal');
assert.match(keyEqual, /nf_ct_tuple_equal\(tuple, &h->tuple\)/);
assert.match(keyEqual, /nf_ct_zone\(ct\) == zone/);
assert.match(keyEqual, /nf_ct_is_confirmed\(ct\)/);

const lookup = functionBody(core, 'nf_conntrack_find_get(struct net *net');
assert.match(lookup, /!nf_ct_key_equal\(h, tuple, zone\)/);
assert.match(core, /if \(nf_ct_key_equal\(h, tuple, zone\)\)/);

const alloc = functionBody(core, 'struct nf_conn *nf_conntrack_alloc');
assert.match(alloc, /atomic_set\(&ct->ct_general\.use, 0\)/);
const free = functionBody(core, 'void nf_conntrack_free');
assert.match(free, /NF_CT_ASSERT\(atomic_read\(&ct->ct_general\.use\) == 0\)/);

const init = functionBody(core, 'init_conntrack(struct net *net');
assert(init.indexOf('if (!l4proto->new') < init.indexOf('nf_conntrack_get(&ct->ct_general)'));
assert(init.indexOf('nf_conntrack_get(&ct->ct_general)') < init.indexOf('&net->ct.unconfirmed'));

const create = functionBody(netlink, 'ctnetlink_create_conntrack(struct net *net');
assert(create.indexOf('nf_conntrack_get(&ct->ct_general)') < create.indexOf('nf_conntrack_hash_insert(ct)'));

const template = functionBody(xtCt, 'static int xt_ct_tg_check');
assert(template.indexOf('__set_bit(IPS_CONFIRMED_BIT') < template.indexOf('nf_conntrack_get(&ct->ct_general)'));
assert(template.indexOf('nf_conntrack_get(&ct->ct_general)') < template.indexOf('info->ct = ct'));

console.log('conntrack refcount and lookup contracts passed');