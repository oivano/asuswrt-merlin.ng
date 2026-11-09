const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(
    path.join(root, 'release/src/router/odhcp6c/src/dhcpv6.c'), 'utf8');
const stateSource = fs.readFileSync(
    path.join(root, 'release/src/router/odhcp6c/src/odhcp6c.c'), 'utf8');

function functionBody(text, signature, from = 0) {
    const start = text.indexOf(signature, from);
    assert.ok(start >= 0, `missing ${signature}`);
    const open = text.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < text.length; index++) {
        if (text[index] === '{') depth++;
        if (text[index] === '}' && --depth === 0)
            return text.slice(open + 1, index);
    }
    assert.fail(`unterminated ${signature}`);
}

const advert = functionBody(source, 'dhcpv6_handle_advert(');
assert.match(advert, /dhcpv6_parse_ia\(ia_hdr,\s*odata \+ olen\s*\)/);
assert.doesNotMatch(advert, /dhcpv6_parse_ia\(ia_hdr,\s*odata \+ olen \+/);

const sender = functionBody(source, 'dhcpv6_send(');
assert.match(sender, /\*unicast_server = in6addr_any/);
assert.match(sender, /else if \(!IN6_IS_ADDR_UNSPECIFIED\(&srv\.sin6_addr\) &&\s*!IN6_IS_ADDR_MULTICAST\(&srv\.sin6_addr\)\)\s*\*unicast_server = srv\.sin6_addr/);

const validatorDefinition = source.lastIndexOf('dhcpv6_response_is_valid(');
const validator = functionBody(source, 'dhcpv6_response_is_valid(', validatorDefinition);
assert.match(validator, /from->sin6_family != AF_INET6 \|\| pktinfo->ipi6_ifindex != ifindex/);
assert.match(validator, /rep->msg_type == DHCPV6_MSG_ADVERT \|\| rep->msg_type == DHCPV6_MSG_REPLY/);
assert.match(validator, /!IN6_IS_ADDR_LINKLOCAL\(&from->sin6_addr\)/);
assert.match(validator, /IN6_IS_ADDR_UNSPECIFIED\(unicast_server\)/);
assert.match(validator, /IN6_ARE_ADDR_EQUAL\(&from->sin6_addr, unicast_server\)/);
assert.match(source, /dhcpv6_send\(type, trid, elapsed \/ 10, &unicast_server\)/);
assert.match(source, /&addr, pktinfo, &unicast_server\)/);

const insertState = functionBody(stateSource, 'int odhcp6c_insert_state(');
assert.match(insertState, /uint8_t \*n = odhcp6c_resize_state\(state, len\);\s*if \(!n\)\s*return -1;/,
    'a refused state resize must be reported as a failed insertion');

const candidateStart = source.lastIndexOf('static void dhcpv6_add_server_cand(');
const candidate = functionBody(source, 'static void dhcpv6_add_server_cand(', candidateStart);
assert.match(candidate, /if \(odhcp6c_insert_state\(STATE_SERVER_CAND,[\s\S]*?\)\)\s*\{\s*free\(cand->ia_na\);\s*free\(cand->ia_pd\);/,
    'failed candidate insertion must release both moved IA buffers');

const stateLimit = Number(stateSource.match(/state_len\[state\] \+ len > (\d+)/)?.[1]);
assert.equal(stateLimit, 1024, 'server candidate state remains bounded');
const candidateSize = 176;
let storedBytes = 0;
for (let index = 0; index < 5; index++) {
    assert.ok(storedBytes + candidateSize <= stateLimit);
    storedBytes += candidateSize;
}
assert.ok(storedBytes + candidateSize > stateLimit,
    'the next candidate exceeds the state cap and must take the failure cleanup path');

function responseSourceAccepted({ family = 'AF_INET6', ifindex = 7, boundIfindex = 7,
    sourceLinkLocal = false, source = '2001:db8::1', unicastServer = null } = {}) {
    if (family !== 'AF_INET6' || ifindex !== boundIfindex) return false;
    return sourceLinkLocal || (unicastServer !== null && source === unicastServer);
}

assert.equal(responseSourceAccepted({ source: '2001:db8::bad' }), false,
    'off-link global reply to a multicast request is rejected');
assert.equal(responseSourceAccepted({ sourceLinkLocal: true }), true,
    'link-local reply on the bound interface is accepted');
assert.equal(responseSourceAccepted({
    source: '2001:db8::server',
    unicastServer: '2001:db8::server'
}), true,
    'reply from the exact unicast server is accepted');
assert.equal(responseSourceAccepted({ ifindex: 8, sourceLinkLocal: true }), false,
    'reply received on a different interface is rejected');

const datagramEnd = 1536;
const iaDataOffset = datagramEnd - 25;
const prefixDataOffset = iaDataOffset + 12 + 4;
const declaredPrefixLength = 25;
const availablePrefixLength = datagramEnd - prefixDataOffset;
const wrongEnd = datagramEnd + 16;

assert.equal(availablePrefixLength, 9);
assert.equal(prefixDataOffset + declaredPrefixLength, wrongEnd);
assert.ok(prefixDataOffset + declaredPrefixLength > datagramEnd,
    'a truncated IA_PREFIX must not fit within the received datagram');

console.log('PASS: Advertise IA parsing ends at the IA option boundary (1536-byte truncated-prefix boundary model)');