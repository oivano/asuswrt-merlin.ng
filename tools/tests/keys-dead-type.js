const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const keysDir = 'release/src-rt-6.x.4708/linux/linux-2.6.36/security/keys';
const read = (name) => fs.readFileSync(path.join(root, keysDir, name), 'utf8');

const key = read('key.c');
const deadType = key.match(/static struct key_type key_type_dead = \{([^}]*)\}/);
assert.ok(deadType, 'internal dead key type is registered');
assert.match(deadType[1], /\.name\s*=\s*"\.dead"/,
    'dead key type uses the reserved dot-prefixed name');

const keyctl = read('keyctl.c');
const parserStart = keyctl.indexOf('static int key_get_type_from_user(');
const parserEnd = keyctl.indexOf('/*****************************************************************************/', parserStart);
assert.ok(parserStart >= 0 && parserEnd > parserStart, 'user type parser present');
const parser = keyctl.slice(parserStart, parserEnd);
assert.match(parser, /if \(type\[0\] == '\.'\)\s*return -EPERM;/,
    'user type parser rejects reserved names');

const requestStart = keyctl.indexOf('SYSCALL_DEFINE4(request_key');
const requestEnd = keyctl.indexOf('\n}', requestStart);
assert.ok(requestStart >= 0 && requestEnd > requestStart, 'request_key syscall present');
const request = keyctl.slice(requestStart, requestEnd);
const parseCall = request.indexOf('key_get_type_from_user(type, _type');
const lookupCall = request.indexOf('key_type_lookup(type)');
assert.ok(parseCall >= 0 && lookupCall > parseCall,
    'request_key rejects reserved type names before type lookup');

const deadName = deadType[1].match(/"([^"]+)"/)[1];
assert.equal(deadName[0], '.', 'the internal name is rejected by the parser');

console.log('PASS: dead key type is hidden from request_key (source contract/model; not kernel execution)');