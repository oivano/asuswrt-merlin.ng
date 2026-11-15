const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const sourcePath = '../../release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/nf_conntrack_proto_tcp.c';
const source = fs.readFileSync(path.resolve(__dirname, sourcePath), 'utf8');
const windowStart = source.indexOf('static bool tcp_in_window(');
const windowEnd = source.indexOf('\n/* table of valid flag combinations', windowStart);
assert.ok(windowStart >= 0 && windowEnd > windowStart, 'tcp_in_window implementation exists');
const windowCheck = source.slice(windowStart, windowEnd);

assert.match(windowCheck, /const struct tcphdr \*tcph,\s*u_int8_t pf,\s*bool strict\)/,
    'window validation can require strict control-packet handling');
assert.match(windowCheck,
    /if \(strict && \(!sender->td_maxwin \|\| !receiver->td_maxwin\)\)\s*return false;/,
    'strict checks reject packets when either direction has no usable window history');
assert.match(windowCheck,
    /if \(!strict && !tcph->rst &&\s*\(sender->flags & IP_CT_TCP_FLAG_BE_LIBERAL \|\|\s*nf_ct_tcp_be_liberal\)\)\s*res = true;/,
    'liberal mode cannot accept an out-of-window RST');

const packetStart = source.indexOf('static int BCMFASTPATH_HOST tcp_packet(');
const packetEnd = source.indexOf('\n/* Called when a new connection', packetStart);
assert.ok(packetStart >= 0 && packetEnd > packetStart, 'tcp_packet implementation exists');
const packet = source.slice(packetStart, packetEnd);
const ctfStart = packet.indexOf('if (ct->ctf_flags & CTF_FLAGS_CACHED)');
const ctfEnd = packet.indexOf('\n\t}\n#endif /* HNDCTF */', ctfStart);
assert.ok(ctfStart >= 0 && ctfEnd > ctfStart, 'cached CTF branch exists');
const cached = packet.slice(ctfStart, ctfEnd);
const evict = cached.indexOf('ip_conntrack_ipct_delete(ct, 0);');
const validate = cached.indexOf('tcp_in_window(');
const reject = cached.indexOf('return -NF_ACCEPT;', validate);
const advance = cached.indexOf('goto in_window;', validate);
assert.ok(evict >= 0 && validate > evict && reject > validate && advance > reject,
    'CTF FIN/RST evicts acceleration state, then validates before conntrack state advancement');
assert.match(cached.slice(validate, reject), /th, pf, true\)/,
    'CTF FIN/RST validation is strict');
assert.match(packet, /skb, dataoff, th, pf, th->rst\)\)/,
    'uncached RST validation is strict while other packets retain normal policy');

function accepted({ knownWindow, inWindow, rst, liberal, strict }) {
    if (strict && !knownWindow) return false;
    return inWindow || (!strict && !rst && liberal);
}

function applyControl(state, timeout, packet, policy) {
    if (!accepted({ ...policy, ...packet })) return { state, timeout };
    return {
        state: packet.rst ? 'CLOSE' : packet.fin ? 'FIN_WAIT' : state,
        timeout: packet.rst ? 10 : packet.fin ? 120 : timeout
    };
}

const established = { state: 'ESTABLISHED', timeout: 432000 };
assert.deepEqual(applyControl(established.state, established.timeout,
    { knownWindow: true, inWindow: false, rst: true, liberal: true, strict: true }), established,
    'spoofed out-of-window RST leaves conntrack state and timeout unchanged');
assert.deepEqual(applyControl(established.state, established.timeout,
    { knownWindow: true, inWindow: false, rst: false, fin: true, liberal: true, strict: false }),
    { state: 'FIN_WAIT', timeout: 120 },
    'liberal handling remains enabled for non-CTF FIN traffic');
assert.deepEqual(applyControl(established.state, established.timeout,
    { knownWindow: true, inWindow: false, rst: false, fin: true, liberal: true, strict: true }),
    established, 'out-of-window CTF FIN leaves conntrack state and timeout unchanged');
assert.deepEqual(applyControl(established.state, established.timeout,
    { knownWindow: false, inWindow: true, rst: true, liberal: true, strict: true }),
    established, 'RST with unavailable window history leaves conntrack state unchanged');
assert.deepEqual(applyControl(established.state, established.timeout,
    { knownWindow: true, inWindow: true, rst: false, fin: true, liberal: true, strict: true }),
    { state: 'FIN_WAIT', timeout: 120 }, 'in-window CTF FIN may advance conntrack state');
assert.deepEqual(applyControl(established.state, established.timeout,
    { knownWindow: true, inWindow: true, rst: true, liberal: true, strict: true }),
    { state: 'CLOSE', timeout: 10 }, 'in-window RST may close the conntrack entry');

console.log('PASS: nf_conntrack TCP RST/FIN validation (source contract and policy model)');