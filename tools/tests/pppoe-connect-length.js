const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/drivers/net/pppoe.c'), 'utf8');

function functionBody(text, signature) {
    const start = text.indexOf(signature);
    assert(start >= 0, `${signature} is present`);
    const open = text.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < text.length; index++) {
        if (text[index] === '{')
            depth++;
        else if (text[index] === '}' && --depth === 0)
            return text.slice(open, index + 1);
    }
    assert.fail(`${signature} has a closing brace`);
}

const connect = functionBody(source, 'static int pppoe_connect(');
const lengthCheck = connect.indexOf(
    'if (sockaddr_len != sizeof(struct sockaddr_pppox))');
assert(lengthCheck >= 0, 'connect requires the complete PPPoX sockaddr');
assert.match(connect.slice(lengthCheck),
    /^if \(sockaddr_len != sizeof\(struct sockaddr_pppox\)\)\s+return -EINVAL;/,
    'a short or oversized sockaddr is rejected with -EINVAL');

for (const addressRead of [
    'lock_sock(sk)',
    'sp->sa_protocol',
    'sp->sa_addr.pppoe.sid',
    'dev_get_by_name(net, sp->sa_addr.pppoe.dev)',
    'memcpy(&po->pppoe_pa'
]) {
    const position = connect.indexOf(addressRead);
    assert(position >= 0, `${addressRead} remains in connect`);
    assert(lengthCheck < position, `${addressRead} follows the length check`);
}

const getname = functionBody(source, 'static int pppoe_getname(');
assert.match(getname,
    /len = sizeof\(struct sockaddr_pppox\)[\s\S]*?memcpy\(uaddr, &sp, len\)[\s\S]*?\*usockaddr_len = len;/,
    'getname returns the full address only after a full-length connect was accepted');

const flush = functionBody(source, 'static void pppoe_flush_dev(');
assert.match(flush,
    /if \(po->pppoe_dev == dev\) \{[\s\S]*?po->pppoe_dev = NULL;\s*dev_put\(dev\);/,
    'device flush releases a matching device reference regardless of socket state');
assert.doesNotMatch(flush.slice(flush.indexOf('if (po->pppoe_dev == dev)')),
    /sk->sk_state\s*&/,
    'device flush does not gate reference release on socket state');

const release = functionBody(source, 'static int pppoe_release(');
assert.match(release,
    /if \(po->pppoe_dev\) \{\s*dev_put\(po->pppoe_dev\);\s*po->pppoe_dev = NULL;/,
    'socket release drops a held device reference regardless of socket state');
assert.doesNotMatch(release.slice(release.indexOf('if (po->pppoe_dev)')),
    /sk->sk_state\s*&/,
    'socket release does not gate reference release on socket state');

function releaseReference(state, hasDevice) {
    const holdsReference = hasDevice;
    return { state, puts: holdsReference ? 1 : 0 };
}

assert.equal(releaseReference('ZOMBIE', true).puts, 1,
    'closing a PADT-zombified socket releases its held device reference');
assert.equal(releaseReference('ZOMBIE', false).puts, 0,
    'closing a socket zombified by device flush does not put NULL');

console.log('PPPoE connect sockaddr length checks passed');