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

console.log('PPPoE connect sockaddr length checks passed');