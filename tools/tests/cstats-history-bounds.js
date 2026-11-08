const assert = require('assert');
const fs = require('fs');
const net = require('net');

const source = fs.readFileSync('release/src/router/cstats/cstats.c', 'utf8');

function functionBody(name) {
    const signature = new RegExp(`\\b${name}\\s*\\([^;]*\\)\\s*\\{`, 'm');
    const match = signature.exec(source);
    assert(match, `missing function ${name}`);

    const open = source.indexOf('{', match.index);
    let depth = 1;
    for (let index = open + 1; index < source.length; index++) {
        if (source[index] === '{') depth++;
        else if (source[index] === '}' && --depth === 0)
            return source.slice(open + 1, index);
    }
    assert.fail(`unterminated function ${name}`);
}

function validHistoryRecord(record) {
    return typeof record.ipaddr === 'string' &&
        record.ipaddr.length < 16 && net.isIPv4(record.ipaddr) &&
        Number.isInteger(record.dailyp) && record.dailyp >= 0 && record.dailyp < 62 &&
        Number.isInteger(record.monthlyp) && record.monthlyp >= 0 && record.monthlyp < 25;
}

const validator = functionBody('valid_history_record');
assert(validator.includes("memchr(record->ipaddr, '\\0', sizeof(record->ipaddr))"));
assert(validator.includes('inet_pton(AF_INET, record->ipaddr, &addr) != 1'));
assert(validator.includes('record->dailyp < 0 || record->dailyp >= MAX_NDAILY'));
assert(validator.includes('record->monthlyp < 0 || record->monthlyp >= MAX_NMONTHLY'));

const loader = functionBody('load_history_to_tree');
assert(loader.indexOf('valid_history_record(&tmp)') < loader.indexOf('find_word(exclude, tmp.ipaddr)'));
assert(loader.indexOf('valid_history_record(&tmp)') < loader.indexOf('memcpy(ptr->daily'));

const printer = functionBody('Node_print_datajs');
assert(printer.includes('if (p < 0 || p >= max) p = 0;'));
assert(printer.indexOf('if (p < 0 || p >= max) p = 0;') < printer.indexOf('p = (p + 1) % max;'));

const bump = functionBody('bump');
assert(bump.includes('if (t < 0 || t >= max) t = 0;'));
assert(bump.indexOf('if (t < 0 || t >= max) t = 0;') < bump.indexOf('data[t].xtime'));

const valid = { ipaddr: '192.0.2.1', dailyp: 0, monthlyp: 0 };
assert(validHistoryRecord(valid));
assert(validHistoryRecord({ ...valid, dailyp: 61, monthlyp: 24 }));
for (const record of [
    { ...valid, dailyp: -3 },
    { ...valid, dailyp: 62 },
    { ...valid, monthlyp: -1 },
    { ...valid, monthlyp: 25 },
    { ...valid, ipaddr: '192.0.2.1'.padEnd(16, 'x') },
    { ...valid, ipaddr: 'not-an-ip' },
]) assert(!validHistoryRecord(record));

function boundedCursor(cursor, max) {
    return cursor < 0 || cursor >= max ? 0 : cursor;
}

for (const max of [62, 25]) {
    for (const cursor of [-3, -1, 0, max - 1, max, 0x7fffffff]) {
        const bounded = boundedCursor(cursor, max);
        assert(bounded >= 0 && bounded < max);
    }
}

console.log('cstats history cursor and IP bounds checks passed');