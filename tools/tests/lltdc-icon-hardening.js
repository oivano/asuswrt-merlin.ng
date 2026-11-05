const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const state = read('release/src/router/lltdc/src/ctstate.c');
const main = read('release/src/router/lltdc/src/ctmain.c');
const globals = read('release/src/router/lltdc/src/globals.h');
const machines = read('release/src/router/lltdc/src/statemachines.h');

assert.match(globals, /#define MAX_PERSISTENT_ICONS 64/);
assert.match(globals, /#define MAX_ICON_STORAGE_BYTES \(5 \* 1024 \* 1024\)/);
assert.match(globals, /g_icon_query_seqnum/);
assert.match(globals, /g_icon_query_active/);
assert.match(machines, /state_cleanup_stale_icons\(void\)/);
assert.match(machines, /state_discard_icon\(void\)/);
assert.match(main, /g_icon_query_seqnum = query_seqnum;\s*g_icon_query_active = TRUE;\s*packetio_send_query_large_tlv\(query_seqnum, &qryMAC\);/);
assert.ok(main.indexOf('state_cleanup_stale_icons();') < main.indexOf('osl_drop_privs(g_osl);'),
    'remove stale transient files before dropping privileges');
assert.match(main, /g_icon_query_active = FALSE;[\s\S]*?state_discard_icon\(\);/);
assert.match(state, /!g_icon_query_active \|\| g_sequencenum != g_icon_query_seqnum/,
    'ignore responses without the active query sequence');
assert.match(state, /ETHERADDR_EQUALS\(&bhdr->tbh_realsrc, &qryMAC\)/,
    'only persist an icon for the station currently queried');
assert.match(state, /ETHERADDR_PRINT\(&qryMAC\)/,
    'derive the stored filename from the queried station, not the Ethernet source');
assert.match(state, /payload_len = g_rcvd_pkt_len - header_len/);
assert.match(state, /\(size_t\)icon_copy_len > payload_len/,
    'reject frame-declared bytes not present in the received packet');
assert.match(state, /icon_copy_len < 1328/,
    'bound the first-fragment signature comparison to received icon data');
assert.match(state, /icon_storage_available\(src_mac, ICONMAXSZ \+ ICON_BASE64_MAX\)/,
    'reserve bounded cache capacity before opening an icon file');
assert.match(state, /log_count >= MAX_PERSISTENT_ICONS/);
assert.match(state, /MAX_ICON_STORAGE_BYTES - total_bytes/);
assert.match(state, /unlink\(path\)/, 'remove abandoned transient .ico files');
const staleCleanup = state.slice(state.indexOf('state_cleanup_stale_icons(void)'),
    state.indexOf('openvpn_base64_encode(const'));
assert.match(staleCleanup, /\.ico/);
assert.doesNotMatch(staleCleanup, /\.log/, 'preserve persistent user-managed icon logs');
assert.match(state, /canonical_mac\[i\] = canonical_mac\[i\] - 'a' \+ 'A'/,
    'match uppercase files created by the icon uploader');
assert.match(state, /char \*base64 = NULL/);
assert.match(state, /openvpn_base64_encode \(buffer, lSize, &base64\)/,
    'use the encoder-owned allocation rather than leaking an initial buffer');
assert.match(state, /free\(base64\)/);
assert.match(state, /unlink\(file_path\)/,
    'remove the raw transient file after conversion');

function acceptsResponse({ active, seq, expectedSeq, sourceMatches, frameBytes, payloadBytes, totalBytes }) {
    return active && seq === expectedSeq && sourceMatches && frameBytes >= 34 &&
        payloadBytes <= frameBytes - 34 && totalBytes + payloadBytes <= 32768;
}

const valid = {
    active: true, seq: 42, expectedSeq: 42, sourceMatches: true,
    frameBytes: 1400, payloadBytes: 1366, totalBytes: 0
};
assert.equal(acceptsResponse(valid), true);
assert.equal(acceptsResponse({ ...valid, seq: 0, expectedSeq: 0 }), true,
    'sequence zero is accepted only when it is the active query sequence');
assert.equal(acceptsResponse({
    ...valid, frameBytes: 42, payloadBytes: 8,
    totalBytes: 32760
}), true, 'the exact cumulative icon-size limit is accepted');
for (const invalid of [
    { ...valid, active: false },
    { ...valid, seq: 0 },
    { ...valid, sourceMatches: false },
    { ...valid, frameBytes: 34, payloadBytes: 1 },
    { ...valid, totalBytes: 32760, payloadBytes: 9 },
])
    assert.equal(acceptsResponse(invalid), false);

function withinStoreLimit(iconCount, bytes, addBytes, targetExists = false) {
    return (targetExists || iconCount < 64) && bytes + addBytes <= 5 * 1024 * 1024;
}
assert.equal(withinStoreLimit(63, 5 * 1024 * 1024 - 100, 100), true);
assert.equal(withinStoreLimit(64, 0, 0), false);
assert.equal(withinStoreLimit(64, 0, 100, true), true,
    'an existing client icon does not consume another file-count slot');
assert.equal(withinStoreLimit(1, 5 * 1024 * 1024 - 99, 100), false);

console.log('PASS: LLTD icon response, payload, persistent quota, and cleanup contracts (source/model checks; not C execution)');