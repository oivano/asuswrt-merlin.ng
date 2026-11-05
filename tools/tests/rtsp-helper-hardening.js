const assert = require('assert');
const fs = require('fs');

const helper = fs.readFileSync(
    'release/src-rt-6.x.4708/linux/linux-2.6.36/net/netfilter/nf_conntrack_rtsp.c',
    'utf8'
);
const common = fs.readFileSync('release/src/router/rc/common.c', 'utf8');
const conntrackHeader = fs.readFileSync(
    'release/src-rt-6.x.4708/linux/linux-2.6.36/include/net/netfilter/nf_conntrack.h',
    'utf8'
);
const helperDispatch = helper.slice(helper.indexOf('static int help('));

assert.match(helper, /RTSP_CLIENT_PORT_MIN\s+49152/);
assert.match(helper, /value > \(65535 - digit\) \/ 10/);
assert.match(helper, /seq != info->next_seq/);
assert.match(helper, /rtsp_validate_packet\(pdata, datalen\)/);
assert.match(helper, /seq = ntohl\(th->seq\) \+ th->syn/);
assert.ok(
    helperDispatch.indexOf('rtsp_stream_check(ct, seq, rb_ptr, datalen)') <
    helperDispatch.indexOf('ctinfo != IP_CT_ESTABLISHED'),
    'validate first payload before waiting for established state'
);
assert.match(helper, /headers_complete/);
assert.match(helper, /entitylen > tcplen - \*ptcpoff/);
assert.match(
    helper,
    /nf_ct_expect_init\(exp,[\s\S]*?&ct->tuplehash\[!dir\]\.tuple\.src\.u3,[\s\S]*?&ct->tuplehash\[!dir\]\.tuple\.dst\.u3/
);
assert.match(conntrackHeader, /struct nf_ct_rtsp_master ct_rtsp_info/);
assert.match(common, /ct_modprobe\("rtsp", "ports=554"\)/);
assert.doesNotMatch(common, /ct_modprobe\("rtsp", "ports=554,8554"\)/);

function rtspRequestLine(line) {
    return /^(OPTIONS|DESCRIBE|ANNOUNCE|SETUP|PLAY|PAUSE|TEARDOWN|GET_PARAMETER|SET_PARAMETER|REDIRECT|RECORD) \S+ RTSP\/1\.[0-9]$/.test(line);
}

function makeStream() {
    return { state: 'unknown', nextSeq: 0 };
}

function acceptStreamPacket(stream, seq, messages) {
    if (stream.state === 'invalid' ||
        (stream.state === 'valid' && seq !== stream.nextSeq) ||
        !messages.length || messages.some(message => !rtspRequestLine(message))) {
        stream.state = 'invalid';
        return false;
    }
    stream.state = 'valid';
    stream.nextSeq = seq + messages.join('').length;
    return true;
}

function isDynamicClientPort(value) {
    return Number.isInteger(value) && value >= 49152 && value <= 65535;
}

const browserFlow = makeStream();
assert.strictEqual(acceptStreamPacket(browserFlow, 1000, ['POST / HTTP/1.1']), false);
assert.strictEqual(acceptStreamPacket(browserFlow, 1024, ['SETUP rtsp://x RTSP/1.0']), false);

const rtspFlow = makeStream();
assert.strictEqual(acceptStreamPacket(rtspFlow, 500, ['OPTIONS * RTSP/1.0']), true);
const setupSeq = rtspFlow.nextSeq;
assert.strictEqual(acceptStreamPacket(rtspFlow, setupSeq, ['SETUP rtsp://camera RTSP/1.0']), true);
assert.strictEqual(acceptStreamPacket(rtspFlow, setupSeq + 1, ['SETUP rtsp://camera RTSP/1.0']), false);
assert.strictEqual(isDynamicClientPort(5353), false);
assert.strictEqual(isDynamicClientPort(49152), true);
assert.strictEqual(isDynamicClientPort(65535), true);
assert.strictEqual(isDynamicClientPort(65536), false);

console.log('RTSP helper hardening checks passed');