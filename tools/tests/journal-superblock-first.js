const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const kernelDir = path.resolve(__dirname, '../../release/src-rt-6.x.4708/linux/linux-2.6.36/fs');
const implementations = [
    { name: 'JBD', file: 'jbd/journal.c' },
    { name: 'JBD2', file: 'jbd2/journal.c' },
];

for (const implementation of implementations) {
    const source = fs.readFileSync(path.join(kernelDir, implementation.file), 'utf8');
    const loader = source.match(/static int journal_get_superblock\(journal_t \*journal\)\s*\{([\s\S]*?)\n\}/);
    assert.ok(loader, `${implementation.name}: loader exists`);

    const body = loader[1];
    const maxLengthValidation = body.indexOf('be32_to_cpu(sb->s_maxlen) > journal->j_maxlen');
    const firstRead = body.indexOf('first = be32_to_cpu(sb->s_first);');
    const rejection = body.indexOf('if (first == 0 || first >= journal->j_maxlen)');
    const success = body.indexOf('return 0;');

    assert.ok(maxLengthValidation >= 0, `${implementation.name}: validates journal length`);
    assert.ok(firstRead > maxLengthValidation, `${implementation.name}: reads start after max length validation`);
    assert.ok(rejection > firstRead && rejection < success, `${implementation.name}: rejects invalid start before success`);
    assert.match(body.slice(rejection, success), /Invalid start block \(%u\)/);
    assert.match(body.slice(rejection, success), /goto out;/);

    const invalid = (first, maxLength) => first === 0 || first >= maxLength;
    for (const maxLength of [1, 2, 1023, 4096]) {
        assert.equal(invalid(0, maxLength), true, `${implementation.name}: rejects zero for maxlen ${maxLength}`);
        assert.equal(invalid(maxLength, maxLength), true, `${implementation.name}: rejects maxlen`);
        assert.equal(invalid(maxLength + 1, maxLength), true, `${implementation.name}: rejects above maxlen`);
        if (maxLength > 1) {
            assert.equal(invalid(1, maxLength), false, `${implementation.name}: permits first block`);
            assert.equal(invalid(maxLength - 1, maxLength), false, `${implementation.name}: permits last valid block`);
        }
    }
}

console.log('JBD/JBD2 journal start-block validation: ok');