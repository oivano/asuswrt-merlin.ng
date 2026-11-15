const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const sourcePath = path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv6/mcast.c');
const source = fs.readFileSync(sourcePath, 'utf8');

const availableIndex = source.indexOf('#define AVAILABLE(skb)');
const addGrheadIndex = source.indexOf('static struct sk_buff *add_grhead');
assert(availableIndex >= 0 && availableIndex < addGrheadIndex,
    'available-space macro must precede its first use');
assert.match(source,
    /#define AVAILABLE\(skb\)[\s\S]*?min_t\(int, skb_tailroom\(skb\), \(skb\)->dev->mtu - \(skb\)->len\)/,
    'available space must be clamped to both skb tailroom and remaining MTU');
assert.match(source,
    /if \(AVAILABLE\(skb\) < sizeof\(\*pgr\)\)[\s\S]*?skb = mld_newpack\(dev, dev->mtu\);[\s\S]*?if \(AVAILABLE\(skb\) < sizeof\(\*pgr\)\)[\s\S]*?kfree_skb\(skb\);[\s\S]*?return NULL;[\s\S]*?pgr = \(struct mld2_grec \*\)skb_put\(skb, sizeof\(struct mld2_grec\)\);/,
    'group header insertion must recheck space, retry, and fail closed');

function available(length, mtu, tailroom, hasDevice = true) {
    if (!hasDevice)
        return tailroom;
    return length < mtu ? Math.min(tailroom, mtu - length) : 0;
}

assert.equal(available(100, 16436, 3800), 3800,
    'a high-MTU loopback skb is limited by its allocated tailroom');
assert.equal(available(100, 1500, 3800), 1400,
    'reports remain within the device MTU');
assert.equal(available(1500, 1500, 3800), 0,
    'no space is reported after the MTU is reached');
assert.equal(available(100, 1500, 3800, false), 3800,
    'device-less skb space remains bounded by tailroom');

console.log('MLDv2 report tailroom regression: ok');