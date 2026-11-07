const assert = require('node:assert/strict');
const fs = require('node:fs');

const source = fs.readFileSync(
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/dns_resolver/dns_key.c',
    'utf8');
const start = source.indexOf('static long dns_resolver_read(');
const end = source.indexOf('\n}', start);
assert.ok(start >= 0 && end > start, 'dns_resolver_read() exists');
const read = source.slice(start, end);

assert.match(read, /int err = key->type_data\.x\[0\];/,
    'read method obtains the stored DNS error');
assert.match(read,
    /if \(err\)\s*return err;[\s\S]*return user_read\(key, buffer, buflen\);/,
    'error keys return before payload access; normal keys use user_read');
assert.match(source, /\.read\s*= dns_resolver_read,/,
    'dns_resolver key type uses the guarded read method');

let delegated = false;
const readResult = (error, userRead) => {
    if (error)
        return error;
    delegated = true;
    return userRead();
};
assert.equal(readResult(-6, () => 0), -6, 'dnserror=6 returns -6');
assert.equal(delegated, false, 'error result never reaches user_read');
assert.equal(readResult(0, () => 7), 7, 'ordinary payload is read normally');
assert.equal(delegated, true, 'ordinary payload delegates to user_read');

console.log('PASS: dns_resolver error reads return before user_read (source contract/model; not kernel execution)');