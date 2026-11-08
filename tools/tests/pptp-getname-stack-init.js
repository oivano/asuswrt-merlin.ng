const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src-rt-6.x.4708/linux/linux-2.6.36/drivers/net/pptp.c'), 'utf8');
const match = source.match(/static int pptp_getname\([\s\S]*?\n\}/);

assert(match, 'pptp_getname exists');
const body = match[0];
const clear = body.indexOf('memset(&sp, 0, sizeof(sp));');
const firstWrite = body.indexOf('sp.sa_family');
const copy = body.indexOf('memcpy(uaddr, &sp, len);');

assert(clear !== -1 && clear < firstWrite,
    'the complete sockaddr_pppox is zeroed before any field is assigned');
assert.match(body, /int len = sizeof\(struct sockaddr_pppox\);/,
    'the returned length covers the complete sockaddr_pppox');
assert(copy !== -1 && firstWrite < copy,
    'the initialized sockaddr_pppox is copied to userspace');

console.log('pptp_getname stack initialization checks passed');
