const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const corePath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/nf_conntrack_core.c';
const pppoePath = 'release/src-rt-6.x.4708/linux/linux-2.6.36/drivers/net/pppoe.c';
const core = fs.readFileSync(path.join(root, corePath), 'utf8');
const pppoe = fs.readFileSync(path.join(root, pppoePath), 'utf8');
const firewall = fs.readFileSync(path.join(root, 'release/src/router/rc/firewall.c'), 'utf8');

const addStart = core.indexOf('ip_conntrack_ipct_add(struct sk_buff *skb');
const addEnd = core.indexOf('\nint\nip_conntrack_ipct_delete', addStart);
assert.ok(addStart >= 0 && addEnd > addStart, 'conntrack cache-add function exists');
const add = core.slice(addStart, addEnd);
const insertAt = add.indexOf('ctf_ipc_add(kcih, &ipc_entry');
assert.ok(insertAt >= 0, 'CTF entry insertion exists');
const beforeInsert = add.slice(0, insertAt);

const pppoeMetadata = beforeInsert.slice(beforeInsert.indexOf('if(ctfppp.psk.pppox_protocol == PX_PROTO_OE)'));
assert.match(pppoeMetadata, /if \(ipc_entry\.ppp_ifp != skb_dst\(skb\)->dev\)\s*goto PX_PROTO_PPPOE;[\s\S]*?ipc_entry\.pppoe_sid = po->pppoe_pa\.sid;/,
    'PPPoE transmit metadata is only applied when PPP is the egress device');
assert.match(beforeInsert, /else if \(\(skb->dev->flags & IFF_POINTOPOINT\) && \(skb->ctf_pppoe_cb\[0\] == 1\)\) \{\s*ipc_entry\.action \|= CTF_ACTION_PPPOE_DEL;\s*ipc_entry\.pppoe_sid = \*\(uint16 \*\)&skb->ctf_pppoe_cb\[2\];/,
    'received PPPoE entries retain the receive session and delete action');

for (const field of [
    'ipc_entry.pppoe_sid = po->pppoe_pa.sid;',
    'ipc_entry.txif = (void *)vlan_dev_real_dev(pppoe_netdev);',
    'ipc_entry.txif = pppoe_netdev;',
    'memcpy(ipc_entry.dhost.octet, po->pppoe_pa.remote, ETH_ALEN);',
    'memcpy(ipc_entry.shost.octet, pppoe_netdev->dev_addr, ETH_ALEN);'
]) {
    assert.ok(beforeInsert.includes(field), `${field} is set before cache insertion`);
}

assert.ok(!core.includes('ctf_pppoe_cb[4]'), 'conntrack code does not stash a cache-entry pointer in skb control data');
assert.ok(!pppoe.includes('ctf_pppoe_cb[4]'), 'PPPoE transmit does not recover a cache-entry pointer from skb control data');

const xmitStart = pppoe.indexOf('static int __pppoe_xmit(');
const xmitEnd = pppoe.indexOf('\nstatic int pppoe_xmit(', xmitStart);
assert.ok(xmitStart >= 0 && xmitEnd > xmitStart, 'PPPoE transmit function exists');
const xmit = pppoe.slice(xmitStart, xmitEnd);
assert.ok(!/ctf_ipc_t\s*\*|ipc->(?:txif|vid|action|pppoe_sid|dhost|shost)/.test(xmit),
    'PPPoE transmit does not dereference or mutate a CTF cache entry');

const mangleStart = firewall.indexOf('mangle_setting(char *wan_if');
const mangleEnd = firewall.indexOf('\n#if defined(RTCONFIG_DUALWAN)', mangleStart);
assert.ok(mangleStart >= 0 && mangleEnd > mangleStart, 'WAN mangle rule generator exists');
const mangle = firewall.slice(mangleStart, mangleEnd);
assert.ok(!mangle.includes('if (!strncmp(wan_if, "ppp", 3))'),
    'PPP forwarding is not unconditionally excluded from CTF');

console.log('PASS: PPPoE CTF metadata is initialized before insertion without skb pointer handoff');