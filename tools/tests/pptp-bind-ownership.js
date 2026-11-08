const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/drivers/net/pptp.c'), 'utf8');

const bindStart = source.indexOf('static int pptp_bind(');
const bindEnd = source.indexOf('\nstatic int pptp_connect(', bindStart);
assert.notEqual(bindStart, -1);
assert.notEqual(bindEnd, -1);
const bind = source.slice(bindStart, bindEnd);

const deadCheck = bind.indexOf('if (SK_STATE(sk) & PPPOX_DEAD)');
const boundCheck = bind.indexOf('if (opt->src_addr.call_id)');
const addressWrite = bind.indexOf('opt->src_addr=sp->sa_addr.pptp;');
assert.ok(deadCheck >= 0 && deadCheck < addressWrite,
    'dead sockets are rejected before changing the source call id');
assert.ok(boundCheck > deadCheck && boundCheck < addressWrite,
    'bound sockets are rejected before changing the source call id');
assert.match(bind,
    /old_addr = opt->src_addr;\s*opt->src_addr=sp->sa_addr\.pptp;\s*if \(add_chan\(po\)\) \{\s*opt->src_addr = old_addr;\s*error=-EBUSY;/,
    'failed channel registration restores the prior address');

const deleteStart = source.indexOf('static void del_chan(');
const deleteEnd = source.indexOf('\nstatic int pptp_xmit(', deleteStart);
assert.notEqual(deleteStart, -1);
assert.notEqual(deleteEnd, -1);
const delChan = source.slice(deleteStart, deleteEnd);
assert.match(delChan, /clear_bit\(sock->proto\.pptp\.src_addr\.call_id,callid_bitmap\)/);
assert.match(delChan,
    /callid_sock\[sock->proto\.pptp\.src_addr\.call_id\] = NULL/);

console.log('PASS: PPTP bind ownership source checks; not compiled-kernel execution');
