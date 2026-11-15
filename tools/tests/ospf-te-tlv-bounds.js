const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(
    path.join(root, 'release/src/router/frr-8.1/ospfd/ospf_te.c'), 'utf8');

function functionBody(name) {
    const signature = source.indexOf(name);
    assert.notEqual(signature, -1, `${name} exists`);

    const open = source.indexOf('{', signature);
    let depth = 0;
    for (let cursor = open; cursor < source.length; cursor++) {
        if (source[cursor] === '{') depth++;
        if (source[cursor] === '}' && --depth === 0)
            return source.slice(open, cursor + 1);
    }
    assert.fail(`${name} has a complete body`);
}

const tlvValidator = functionBody('static bool ospf_te_tlv_valid(');
const updateLink = functionBody('static void ospf_te_update_link(');
const routerLsa = functionBody('static int ospf_te_parse_router_lsa(');
const teLsa = functionBody('static int ospf_te_parse_te(');
const riLsa = functionBody('static int ospf_te_parse_ri(');
const extLinkLsa = functionBody('static int ospf_te_parse_ext_link(');

assert.match(tlvValidator,
    /remaining < TLV_HDR_SIZE[\s\S]*?padded_len <= remaining - TLV_HDR_SIZE/,
    'TLV header and padded body fit in the remaining LSA');
assert.match(updateLink,
    /edge = get_edge\([\s\S]*?if \(!edge \|\| !edge->attributes\)\s*return;[\s\S]*?attr = edge->attributes;/,
    'Router-LSA edge creation failure is checked before dereference');
assert.match(routerLsa,
    /if \(!vertex \|\| !vertex->node\)\s*return -1;/,
    'Router-LSA vertex creation failure is checked');
assert.match(routerLsa,
    /link_data\.s_addr == INADDR_ANY[\s\S]*?break;/,
    'zero-address point-to-point links do not create TED entries');
assert.match(teLsa,
    /ospf_te_tlv_valid\(tlvh, sub_remaining\)[\s\S]*?TE_LINK_SUBTLV_UNRSV_SIZE[\s\S]*?if \(!edge \|\| !edge->attributes\)/,
    'TE sub-TLVs are bounded and the resulting edge attributes are checked');
assert.match(riLsa,
    /for \(tlvh = TLV_HDR_TOP\(lsah\); remaining > 0;\)[\s\S]*?sizeof\(node->algo\)[\s\S]*?remaining = lsa->size - OSPF_LSA_HEADER_SIZE;/,
    'RI TLVs are fully validated and SR algorithms fit node->algo');
assert.match(extLinkLsa,
    /for \(remaining = sub_remaining; remaining > 0;\)[\s\S]*?EXT_SUBTLV_LAN_ADJ_SID_SIZE[\s\S]*?if \(!edge \|\| !edge->attributes\)/,
    'extended-link sub-TLVs are prevalidated before edge mutation');

function tlvFits(remaining, valueLength) {
    const paddedLength = Math.ceil(valueLength / 4) * 4;
    return remaining >= 4 && paddedLength <= remaining - 4;
}

assert.equal(tlvFits(8, 4), true, 'complete TLV fits');
assert.equal(tlvFits(7, 4), false, 'truncated padded body is rejected');
assert.equal(tlvFits(3, 0), false, 'truncated TLV header is rejected');

console.log('PASS: OSPF TE TED NULL and TLV bounds source contracts');