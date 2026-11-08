const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src/router/frr-8.1/bgpd/bgp_attr.c'), 'utf8');
const start = source.indexOf('static int bgp_attr_aggregator(');
const end = source.indexOf('/* New Aggregator attribute */', start);
assert(start >= 0 && end > start, 'AGGREGATOR parser must exist');
const parser = source.slice(start, end);
const negotiated = parser.match(/const bool use32bit = ([^;]+);/);
assert(negotiated, 'one negotiated-AS4 predicate must control the parser width');
assert.match(negotiated[1], /CHECK_FLAG\(peer->cap, PEER_CAP_AS4_RCV\)/);
assert.match(negotiated[1], /&&\s*CHECK_FLAG\(peer->cap, PEER_CAP_AS4_ADV\)/);
assert.match(parser, /if \(use32bit\)\s*wantedlen = 8;/);
assert.match(parser, /if \(length != wantedlen\)[\s\S]*?return bgp_attr_malformed/);
assert.match(parser, /if \(use32bit\)\s*aggregator_as = stream_getl\(peer->curr\);\s*else\s*aggregator_as = stream_getw\(peer->curr\);/);
assert.match(parser, /stream_get_ipv4\(peer->curr\)/);

const negotiatedExpression = negotiated[1].replace(/peer->cap/g, 'peer.cap');
const getUse32bit = vm.runInNewContext(`(function(peer) {
    return !!(${negotiatedExpression});
})`, {
    CHECK_FLAG: (cap, flag) => (cap & flag) !== 0,
    PEER_CAP_AS4_RCV: 1,
    PEER_CAP_AS4_ADV: 2
});

function parseAggregator(bytes, cap) {
    const use32bit = getUse32bit({ cap });
    const wantedLength = use32bit ? 8 : 6;
    if (bytes.length !== wantedLength) return null;

    const asLength = use32bit ? 4 : 2;
    const aggregatorAs = use32bit
        ? bytes.readUInt32BE(0) : bytes.readUInt16BE(0);
    const address = [...bytes.subarray(asLength, asLength + 4)];
    const consumed = asLength + address.length;
    return { aggregatorAs, address, consumed };
}

const sixByteValue = Buffer.from([0x12, 0x34, 192, 0, 2, 1]);
const eightByteValue = Buffer.from([0, 1, 0x12, 0x34, 192, 0, 2, 1]);
let cases = 0;
for (const rcv of [false, true]) {
    for (const adv of [false, true]) {
        const cap = (rcv ? 1 : 0) | (adv ? 2 : 0);
        const negotiatedAs4 = rcv && adv;
        const expected = negotiatedAs4 ? eightByteValue : sixByteValue;
        const rejected = negotiatedAs4 ? sixByteValue : eightByteValue;
        const parsed = parseAggregator(expected, cap);
        assert(parsed, `expected ${expected.length}-byte AGGREGATOR for cap ${cap}`);
        assert.equal(parsed.consumed, expected.length, 'parser must consume exactly the attribute');
        assert.deepEqual(parsed.address, [192, 0, 2, 1]);
        assert.equal(parseAggregator(rejected, cap), null,
            'reject the width not negotiated by both peers');
        cases++;
    }
}

const oldReadWidth = cap => cap & 1 ? 4 : 2;
assert.equal(sixByteValue.length === 6 && oldReadWidth(1) + 4 === 8, true,
    'negative control: the old RCV-only read width overruns the accepted six-byte case');
console.log(`PASS: AGGREGATOR negotiated-AS4 width and exact consumption (${cases} capability combinations; source contract/model, not compiled bgpd)`);