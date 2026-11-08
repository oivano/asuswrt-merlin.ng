const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(
    path.join(root, 'release/src/router/udpxy/mkpg.c'), 'utf8');

const escapeFunction = source.match(/static int\s+html_escape\([^]*?\n\}/);
const clientsFunction = source.match(/static int\s+mk_client_entries\([^]*?\n\}/);
const statusFunction = source.match(/int\s+mk_status_page\([^]*?\n\}/);
assert(escapeFunction && clientsFunction && statusFunction);

for (const [character, entity] of [
    ['&', '&amp;'], ['<', '&lt;'], ['>', '&gt;'], ['"', '&quot;'], ["'", '&#39;']
]) {
    const cCharacter = character === "'" ? "'\\''" : `'${character}'`;
    assert(escapeFunction[0].includes(`case ${cCharacter}: entity = "${entity}"; break;`));
}
assert.match(escapeFunction[0], /entity_len >= dstlen - used/);
assert.match(escapeFunction[0], /memcpy\( dst \+ used, entity, entity_len \)/);
assert.match(escapeFunction[0], /dst\[ used \] = '\\0'/);

for (const field of ['src_addr', 'mcast_addr', 'tail'])
    assert.match(clientsFunction[0], new RegExp(`html_escape\\( client->${field},`));
const record = clientsFunction[0].match(/n = prbuf_printf\( pb, ACLIENT_REC_FMT[^]*?\);/);
assert(record);
for (const field of ['escaped_src_addr', 'escaped_mcast_addr', 'escaped_tail'])
    assert(record[0].includes(field));
assert.match(clientsFunction[0], /char escaped_src_addr\[ IPADDR_STR_SIZE \* 6 \+ 1 \]/);
assert.match(clientsFunction[0], /char escaped_mcast_addr\[ IPADDR_STR_SIZE \* 6 \+ 1 \]/);
assert.match(clientsFunction[0], /char escaped_tail\[ MAX_TAIL_LEN \* 6 \+ 1 \]/);
assert.match(statusFunction[0], /IPADDR_STR_SIZE \* 6/);
assert.match(statusFunction[0], /6 \* strlen\(ctx->cl\[i\]\.tail\)/);

const entities = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
const htmlEscape = value => Array.from(value, character => entities[character] || character).join('');
const payload = '<script>alert(1)</script>&"\'';
assert.equal(htmlEscape(payload), '&lt;script&gt;alert(1)&lt;/script&gt;&amp;&quot;&#39;');
assert.doesNotMatch(htmlEscape(payload), /<script/i);

const maxTail = '"'.repeat(255);
const escapedMaxTail = htmlEscape(maxTail);
assert.equal(escapedMaxTail.length, 255 * 6);
assert(escapedMaxTail.length < 255 * 6 + 1);
assert.equal(htmlEscape('&<>"\'').length, 24);

console.log('udpxy status XSS regression checks passed');