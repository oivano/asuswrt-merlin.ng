const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(
    path.join(root, 'release/src/router/odhcp6c/src/dhcpv6.c'), 'utf8');

function functionBody(signature, from = 0) {
    const start = source.indexOf(signature, from);
    assert.ok(start >= 0, `missing ${signature}`);
    const open = source.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < source.length; index++) {
        if (source[index] === '{') depth++;
        if (source[index] === '}' && --depth === 0)
            return source.slice(open + 1, index);
    }
    assert.fail(`unterminated ${signature}`);
}

const advert = functionBody('dhcpv6_handle_advert(');
assert.match(advert, /dhcpv6_parse_ia\(ia_hdr,\s*odata \+ olen\s*\)/);
assert.doesNotMatch(advert, /dhcpv6_parse_ia\(ia_hdr,\s*odata \+ olen \+/);

const sender = functionBody('dhcpv6_send(');
assert.match(sender, /\*unicast_server = in6addr_any/);
assert.match(sender, /else if \(!IN6_IS_ADDR_UNSPECIFIED\(&srv\.sin6_addr\) &&\s*!IN6_IS_ADDR_MULTICAST\(&srv\.sin6_addr\)\)\s*\*unicast_server = srv\.sin6_addr/);

const validatorDefinition = source.lastIndexOf('dhcpv6_response_is_valid(');
const validator = functionBody('dhcpv6_response_is_valid(', validatorDefinition);
assert.match(validator, /from->sin6_family != AF_INET6 \|\| pktinfo->ipi6_ifindex != ifindex/);
assert.match(validator, /rep->msg_type == DHCPV6_MSG_ADVERT \|\| rep->msg_type == DHCPV6_MSG_REPLY/);
assert.match(validator, /!IN6_IS_ADDR_LINKLOCAL\(&from->sin6_addr\)/);
assert.match(validator, /IN6_IS_ADDR_UNSPECIFIED\(unicast_server\)/);
assert.match(validator, /IN6_ARE_ADDR_EQUAL\(&from->sin6_addr, unicast_server\)/);
assert.match(source, /dhcpv6_send\(type, trid, elapsed \/ 10, &unicast_server\)/);
assert.match(source, /&addr, pktinfo, &unicast_server\)/);

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