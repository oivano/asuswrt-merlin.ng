const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/drivers/net/pptp.c'), 'utf8');

function functionRegion(signature, nextSignature) {
    const start = source.indexOf(signature);
    assert.notEqual(start, -1, `missing ${signature}`);
    const end = source.indexOf(nextSignature, start + signature.length);
    assert.notEqual(end, -1, `missing next function after ${signature}`);
    return source.slice(start, end);
}

for (const [name, signature, nextSignature, fieldRead] of [
    ['bind', 'static int pptp_bind(', 'static int pptp_connect(', /sp->sa_addr\.pptp/],
    ['connect', 'static int pptp_connect(', 'static int pptp_getname(', /sp->sa_(?:protocol|addr)/]
]) {
    const body = functionRegion(signature, nextSignature);
    const guard = body.match(/if \(sockaddr_len < sizeof\(struct sockaddr_pppox\)\)\s*return -EINVAL;/);
    assert.ok(guard, `${name} rejects undersized sockaddr_pppox addresses`);
    const read = body.search(fieldRead);
    assert.ok(read >= 0, `${name} reads its expected address fields`);
    assert.ok(guard.index < read, `${name} checks length before reading address fields`);
}

console.log('PASS: PPTP bind/connect reject undersized sockaddr_pppox before field reads; source-contract check only');