const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const source = fs.readFileSync(path.resolve(__dirname,
    '../../release/src-rt-6.x.4708/linux/linux-2.6.36/drivers/usb/core/config.c'), 'utf8');

function body(start, end) {
    const from = source.indexOf(start);
    assert(from >= 0, `missing ${start}`);
    const to = source.indexOf(end, from + start.length);
    assert(to > from, `missing ${end}`);
    return source.slice(from, to);
}

const configParser = body('static int usb_parse_configuration(', '/* hub-only!!');
const interfaceParser = body('static int usb_parse_interface(',
    'static int usb_parse_configuration(');

const shortBufferCheck = configParser.indexOf('if (size < USB_DT_CONFIG_SIZE)');
const headerCopy = configParser.indexOf('memcpy(&config->desc, buffer, USB_DT_CONFIG_SIZE)');
assert(shortBufferCheck >= 0 && shortBufferCheck < headerCopy,
    'received size must be checked before copying the fixed-size header');
assert.match(configParser,
    /config->desc\.bNumInterfaces = 0;\s*if \(size < USB_DT_CONFIG_SIZE\)/);
assert.match(configParser,
    /memcpy\(&config->desc, buffer, USB_DT_CONFIG_SIZE\);\s*nintf_orig = config->desc\.bNumInterfaces;\s*config->desc\.bNumInterfaces = 0;/);
assert.match(configParser,
    /config->desc\.bLength < USB_DT_CONFIG_SIZE \|\|\s*config->desc\.bLength > size/);
assert.match(interfaceParser, /struct usb_host_config \*config, int nintf,/);
assert.match(interfaceParser, /for \(i = 0; i < nintf; \+\+i\)/);
assert.doesNotMatch(interfaceParser, /config->desc\.bNumInterfaces/);
assert.match(configParser, /nintf = nintf_orig;[\s\S]*?nintf = USB_MAXINTERFACES;/);
assert.match(configParser, /else if \(n < USB_MAXINTERFACES\)/);
assert.match(configParser,
    /retval = usb_parse_interface\(ddev, cfgno, config, nintf,[\s\S]*?if \(retval < 0\)\s*goto err;/);
assert.match(configParser,
    /config->desc\.bNumInterfaces = nintf;\s*return 0;\s*err:\s*for \(i = 0; i < nintf; \+\+i\)/);
assert.match(configParser,
    /kref_put\(&config->intf_cache\[i\]->ref,\s*usb_release_interface_cache\);\s*config->intf_cache\[i\] = NULL;/);

const reported = Buffer.from([0x05, 0x02, 0x09, 0x00, 0xff, 0x01, 0x00, 0x80, 0x32]);
assert.equal(reported[4], 0xff, 'fixture must declare 255 interfaces');
assert.equal(reported[0], 5, 'fixture must carry a short bLength');
function headerAccepted(bytes, received) {
    return received >= 9 && bytes[0] >= 9 && bytes[0] <= received;
}
assert.equal(headerAccepted(reported, reported.length), false,
    'the complete received header must still be rejected for its short bLength');
for (let received = 0; received < 9; received++)
    assert.equal(headerAccepted(reported, received), false,
        `a ${received}-byte response must be rejected before the header copy`);

console.log('USB configuration descriptor bounds contracts passed');