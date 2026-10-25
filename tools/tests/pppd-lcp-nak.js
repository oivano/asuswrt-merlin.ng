const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../release/src/router/pppd');
const source = fs.readFileSync(path.join(root, 'pppd/lcp.c'), 'utf8');
const constants = {};
for (const file of ['pppd/lcp.c', 'pppd/lcp.h', 'pppd/fsm.h', 'pppd/pppd.h',
    'pppd/chap-new.h', 'include/linux/ppp_defs.h']) {
    const text = fs.readFileSync(path.join(root, file), 'utf8');
    for (const match of text.matchAll(/^#define\s+(\w+)\s+(0x[\da-fA-F]+|\d+)\b/gm)) {
        constants[match[1]] = Number(match[2]);
    }
}
constants.PPP_EAP = 0xc227;
const { PPP_MRU, CONFACK, CONFNAK, CONFREJ, CI_AUTHTYPE, PPP_CHAP, PPP_PAP, PPP_EAP } = constants;
assert.match(source, /static u_char nak_buffer\[PPP_MRU\]/);

const start = source.indexOf('lcp_reqci(f, inp, lenp, reject_if_disagree)');
assert(start >= 0);
const end = source.indexOf('\n}\n', start);
const body = source.slice(source.indexOf('{', start) + 1, end);

function translate(text) {
    return text.replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/sizeof\(\*ho\)/g, '0')
        .replace(/sizeof\(nak_buffer\)/g, String(PPP_MRU))
        .replace(/\*lenp/g, 'lenp.value')
        .replace(/lcp_options \*(\w+) = &(\w+)\[f->unit\];/g, 'let $1 = $2[f.unit];')
        .replace(/\b(?:u_char|u_short|u_int32_t|int)\s+([^;]+);/g,
            (_, declaration) => `let ${declaration.replace(/\*/g, '')};`)
        .replace(/->/g, '.')
        .replace(/BZERO\(ho, 0\);/, 'Object.assign(ho, options());')
        .replace(/cip = p = next;/, 'cip = p = next; option: {')
        .replace(/goto endswitch;/g, 'break option;')
        .replace(/endswitch:/, '}')
        .replace(/p\[1\]/g, 'memory[p + 1]')
        .replace(/GET(CHAR|SHORT|LONG)\((\w+), (\w+)\);/g,
            (_, type, value, pointer) => `[${value}, ${pointer}] = get(${pointer}, ${width(type)});`)
        .replace(/PUT(CHAR|SHORT|LONG)\((.*), (\w+)\);/g,
            (_, type, value, pointer) => `${pointer} = put(${value}, ${pointer}, ${width(type)});`)
        .replace(/INCPTR\((\w+), (\w+)\);/g, '$2 += $1;')
        .replace(/LCPDEBUG\(\([^\n]*\)\);/g, '');
}
function width(type) {
    return { CHAR: 1, SHORT: 2, LONG: 4 }[type];
}
function options() {
    const result = { endpoint: { value: Buffer.alloc(20) } };
    for (const name of ['neg_mru', 'mru', 'neg_asyncmap', 'asyncmap', 'neg_upap', 'neg_chap',
        'neg_eap', 'chap_mdtype', 'neg_lqr', 'lqr_period', 'neg_magicnumber', 'magicnumber',
        'neg_pcompression', 'neg_accompression', 'neg_mrru', 'neg_ssnhf', 'neg_endpoint']) result[name] = 0;
    return result;
}
const digest = mask => mask & 1 ? 0x81 : mask & 2 ? 5 : mask & 4 ? 0x80 : 0;
const digestMask = value => value === 0x81 ? 1 : value === 5 ? 2 : value === 0x80 ? 4 : 0;
const names = [...Object.keys(constants), 'memory', 'nak_buffer', 'lcp_gotoptions',
    'lcp_hisoptions', 'lcp_allowoptions', 'multilink', 'get', 'put', 'BCOPY', 'options',
    'CHAP_DIGEST', 'CHAP_MDTYPE_D', 'CHAP_CANDIGEST', 'magic', 'dbglog', 'f', 'inp', 'lenp',
    'reject_if_disagree'];

function run(input, { allow = {}, got = {}, reject = 0, check = true, code = body } = {}) {
    const memory = Buffer.alloc(8192, 0xa5);
    const nakBase = 64;
    const inputBase = 4096;
    input.copy(memory, inputBase);
    const before = Buffer.from(memory);
    const lenp = { value: input.length };
    const get = (pointer, length) => [memory.readUIntBE(pointer, length), pointer + length];
    const put = (value, pointer, length) => {
        if (check) assert(pointer >= nakBase && pointer + length <= nakBase + Math.min(PPP_MRU, input.length),
            'Nak write exceeds static buffer or caller capacity');
        memory.writeUIntBE(value >>> 0, pointer, length);
        return pointer + length;
    };
    const copy = (from, to, length) => {
        if (Buffer.isBuffer(to)) return memory.copy(to, 0, from, from + length);
        if (check) assert(to >= inputBase && to + length <= inputBase + input.length,
            'reply copy exceeds original request');
        memory.copy(memory, to, from, from + length);
    };
    const invoke = new Function(...names, translate(code));
    const result = invoke(...Object.values(constants), memory, nakBase,
        [{ ...options(), ...got }], [options()],
        [{ ...options(), neg_chap: 1, chap_mdtype: 2, ...allow }], 0,
        get, put, copy, options, digest, digestMask, (mask, value) => mask & digestMask(value),
        () => 0x12345678, () => {}, { unit: 0 }, inputBase, lenp, reject);
    if (check) {
        assert(lenp.value <= input.length);
        assert.deepEqual(memory.subarray(nakBase + PPP_MRU, inputBase), before.subarray(nakBase + PPP_MRU, inputBase));
        assert.deepEqual(memory.subarray(inputBase + input.length), before.subarray(inputBase + input.length));
    }
    return { result, reply: memory.subarray(inputBase, inputBase + lenp.value), memory, before, nakBase, inputBase };
}

const auth = protocol => Buffer.from([CI_AUTHTYPE, 4, protocol >> 8, protocol & 255]);
const repeated = (option, count) => Buffer.concat(Array(count).fill(option));
const unknown = auth(0xffff);
for (const protocol of [0xffff, PPP_EAP, PPP_PAP]) {
    for (const count of [1, 2, 299, 300, 301, 371, 372]) {
        for (const reject of [0, 1]) {
            const input = repeated(auth(protocol), count);
            const actual = run(input, { reject });
            assert.equal(actual.result, CONFREJ);
            assert(actual.reply.length > 0);
            if (reject) assert.deepEqual(actual.reply, input);
        }
    }
}

const padding = repeated(Buffer.from([constants.CI_PCOMPRESSION, 2]), 2);
const input = Buffer.concat([unknown, padding]);
const normal = run(input, { allow: { neg_pcompression: 1 } });
assert.equal(normal.result, CONFNAK);
assert.deepEqual(normal.reply, Buffer.from([CI_AUTHTYPE, 5, PPP_CHAP >> 8, PPP_CHAP & 255, 5]));
assert.deepEqual(run(auth(PPP_PAP), { allow: { neg_upap: 1 } }).reply, auth(PPP_PAP));
assert.equal(run(auth(PPP_PAP), { allow: { neg_upap: 1 } }).result, CONFACK);
for (const allow of [{ neg_eap: 1 }, { neg_chap: 0, neg_upap: 1 }]) {
    const actual = run(repeated(unknown, 372), { allow });
    assert.equal(actual.result, CONFNAK);
    assert.equal(actual.reply.length, 1488);
    assert.equal(actual.reply[3], allow.neg_eap ? PPP_EAP & 255 : PPP_PAP & 255);
}

const bad = Buffer.from([255, 2]);
assert.equal(run(Buffer.concat([bad, repeated(unknown, 372)])).result, CONFREJ);
for (const input of [Buffer.alloc(0), Buffer.from([1]), Buffer.from([1, 0]), Buffer.from([1, 9, 0, 0])]) {
    const actual = run(input);
    assert.equal(actual.result, input.length ? CONFREJ : CONFACK);
}

const nakCases = [
    { option: Buffer.from([constants.CI_MRU, 4, 0, 1]), allow: { neg_mru: 1 } },
    { option: Buffer.from([constants.CI_ASYNCMAP, 6, 0, 0, 0, 0]), allow: { neg_asyncmap: 1, asyncmap: 1 } },
    { option: Buffer.from([CI_AUTHTYPE, 5, PPP_CHAP >> 8, PPP_CHAP & 255, 0]), allow: {} },
    { option: Buffer.from([CI_AUTHTYPE, 5, PPP_CHAP >> 8, PPP_CHAP & 255, 5]), allow: { neg_chap: 0, neg_upap: 1 } },
    { option: Buffer.from([constants.CI_QUALITY, 8, 0, 0, 0, 0, 0, 0]), allow: { neg_lqr: 1 } },
    { option: Buffer.from([constants.CI_MAGICNUMBER, 6, 0, 0, 0, 0]), got: { neg_magicnumber: 1 } },
];
for (const test of nakCases) {
    for (const reject of [0, 1]) {
        const actual = run(test.option, { ...test, reject });
        assert.equal(actual.result, reject && test.option[0] !== constants.CI_MAGICNUMBER ? CONFREJ : CONFNAK);
        run(Buffer.concat([repeated(unknown, 299), test.option]), { ...test, reject });
        run(repeated(test.option, Math.ceil(1600 / test.option.length)), { ...test, reject });
    }
}

const exact = Buffer.concat([repeated(unknown, 300), repeated(Buffer.from([7, 2]), 150)]);
assert.equal(run(exact, { allow: { neg_pcompression: 1 } }).reply.length, PPP_MRU);
assert.equal(run(exact, { allow: { neg_pcompression: 1 } }).result, CONFNAK);
const oversized = run(repeated(unknown, 400));
assert.equal(oversized.result, CONFREJ);

const unguarded = body.replace(/\s*if \(nakend - nakp < [\s\S]*?\) \{\s*orc = CONFREJ;\s*break;\s*\}/g, '');
assert.equal((body.match(/nakend - nakp </g) || []).length, 9);
assert.doesNotMatch(unguarded, /nakend - nakp </);
const regression = run(repeated(unknown, 372), { check: false, code: unguarded });
assert.equal(regression.result, CONFNAK);
assert.equal(regression.reply.length, 1860);
assert.notDeepEqual(regression.memory.subarray(regression.nakBase + PPP_MRU, regression.nakBase + 1860),
    regression.before.subarray(regression.nakBase + PPP_MRU, regression.nakBase + 1860));
assert.notDeepEqual(regression.memory.subarray(regression.inputBase + 1496, regression.inputBase + 1860),
    regression.before.subarray(regression.inputBase + 1496, regression.inputBase + 1860));
assert.throws(() => run(repeated(unknown, 372), { code: unguarded }), /Nak write exceeds/);

console.log('pppd-lcp-nak: source-translated control flow, bounds/canaries and vulnerable mutation passed (not compiled C)');