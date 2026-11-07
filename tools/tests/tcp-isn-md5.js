const assert = require('assert');
const fs = require('fs');
const path = require('path');

const kernel = path.join(__dirname, '../../release/src-rt-6.x.4708/linux/linux-2.6.36');
const read = (file) => fs.readFileSync(path.join(kernel, file), 'utf8');
const random = read('drivers/char/random.c');
const sequence = read('net/core/secure_seq.c');
const hashHeader = read('include/linux/cryptohash.h');
const hashSource = read('lib/md5.c');

assert.match(hashHeader, /#define MD5_DIGEST_WORDS 4/);
assert.match(hashHeader, /#define MD5_MESSAGE_BYTES 64/);
assert.match(hashHeader, /void md5_transform\(__u32 \*hash, __u32 const \*in\);/);
assert.match(hashSource, /void md5_transform\(__u32 \*hash, __u32 const \*in\)/);
assert.match(hashSource, /EXPORT_SYMBOL\(md5_transform\);/);
assert.match(read('lib/Makefile'), /sha1\.o md5\.o irq_regs\.o/);
assert.match(read('crypto/md5.c'), /#include <linux\/cryptohash\.h>/);
assert.doesNotMatch(read('crypto/md5.c'), /static void md5_transform/);

assert.match(read('net/core/Makefile'), /net_namespace\.o secure_seq\.o/);
assert.match(sequence, /static u32 net_secret\[MD5_MESSAGE_BYTES \/ 4\]/);
assert.match(sequence, /get_random_bytes\(net_secret, sizeof\(net_secret\)\)/);
assert.match(sequence, /return seq \+ \(ktime_to_ns\(ktime_get_real\(\)\) >> 6\);/);
assert.match(sequence, /EXPORT_SYMBOL\(secure_tcpv6_sequence_number\);/);

for (const name of ['secure_tcp_sequence_number', 'secure_tcpv6_sequence_number']) {
    const definition = new RegExp(`(?:__u32|u32)\\s+${name}\\s*\\([\\s\\S]*?\\n}`, 'g');
    const bodies = [...sequence.matchAll(definition)];
    assert.strictEqual(bodies.length, 1, `${name} must have one definition`);
    assert.match(bodies[0][0], /md5_transform\(/, `${name} must use full MD5`);
    assert.doesNotMatch(bodies[0][0], /half_md4_transform|twothirdsMD4Transform|HASH_MASK|keyptr->count/);
}

assert.doesNotMatch(random, /(?:__u32|u32)\s+secure_tcpv6?_sequence_number\s*\(/);
assert.match(read('include/linux/random.h'), /secure_tcp_sequence_number/);
assert.match(read('include/linux/random.h'), /secure_tcpv6_sequence_number/);

console.log('TCP IPv4/IPv6 ISNs use the boot-time full-width MD5 generator');