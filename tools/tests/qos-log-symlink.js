const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const qosSources = [
    'release/src/router/rc/qos.c',
    'release/src/router/rc/qos_multiwan.c',
].map((file) => fs.readFileSync(path.join(root, file), 'utf8'));
const defaults = fs.readFileSync(
    path.join(root, 'release/src/router/shared/defaults.c'),
    'utf8',
);

for (const source of qosSources) {
    assert(source.includes('nvram_match("qos_debug", "1")'));
    assert(source.includes('logmessage("QOS", "[QOS][%s:(%d)]"fmt'));
    assert(!source.includes('/tmp/QOS_LOG'));
    assert(!source.includes('/tmp/QOS_DEBUG'));
    assert(!source.includes('system(info)'));
}

assert(defaults.includes('{ "qos_debug", "0",'));
console.log('QoS debug logging uses a disabled-by-default NVRAM gate and no shell/file sink.');