const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/openconnect/ppp.c'), 'utf8');

function functionBody(name) {
    const start = source.indexOf(`static int ${name}(`);
    assert.notEqual(start, -1, `${name} exists`);
    const openingBrace = source.indexOf('{', start);
    let depth = 1;

    for (let index = openingBrace + 1; index < source.length; index++) {
        if (source[index] === '{') depth++;
        if (source[index] === '}' && --depth === 0)
            return source.slice(openingBrace + 1, index);
    }

    assert.fail(`${name} has a closing brace`);
}

const validator = functionBody('validate_config_options');
assert.match(validator, /while\s*\(remaining\)/);
assert.match(validator, /remaining\s*<\s*2\s*\|\|\s*p\[1\]\s*<\s*2\s*\|\|\s*p\[1\]\s*>\s*remaining/,
    'options shorter than the two-byte header and options extending past the payload are rejected');
assert.match(validator, /remaining\s*-=?\s*p\[1\]/);
assert.match(validator, /p\s*\+=\s*p\[1\]/,
    'accepted options always advance the cursor');

for (const name of ['handle_config_request', 'handle_config_rejnak']) {
    const body = functionBody(name);
    const validation = body.indexOf('validate_config_options(payload, len)');
    const optionLoop = body.indexOf('for (p = payload');
    assert(validation >= 0 && optionLoop > validation,
        `${name} validates the complete packet before walking or applying options`);
}

function validOptions(bytes) {
    let offset = 0;
    let remaining = bytes.length;

    while (remaining) {
        if (remaining < 2 || bytes[offset + 1] < 2 || bytes[offset + 1] > remaining)
            return false;
        remaining -= bytes[offset + 1];
        offset += bytes[offset + 1];
    }
    return true;
}

const reportPacket = [0x01, 0x01, 0x00, 0x06, 0x01, 0x00];
assert.equal(validOptions(reportPacket.slice(4)), false,
    'the reported LCP Configure-Request zero-length option is rejected');
assert.equal(validOptions([]), true, 'an empty option list is valid');
assert.equal(validOptions([0x07, 0x02]), true, 'a two-byte option is valid');
assert.equal(validOptions([0x01, 0x04, 0x12, 0x34, 0x02, 0x02]), true,
    'multiple complete options are accepted');
assert.equal(validOptions([0x01, 0x01]), false, 'a one-byte option is rejected');
assert.equal(validOptions([0x01, 0x03]), false, 'an option extending past the payload is rejected');
assert.equal(validOptions([0x01, 0x02, 0x00]), false, 'a trailing partial option header is rejected');

console.log('PASS: OpenConnect rejects malformed PPP Configure-Request, Nak, and Reject option framing (source contract and boundary model; C not compiled)');