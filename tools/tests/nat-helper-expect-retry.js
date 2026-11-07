const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const kernel = path.join(root, 'release/src-rt-6.x.4708/linux/linux-2.6.36/net/ipv4/netfilter');

function functionBody(source, name) {
    const signature = new RegExp('static (?:unsigned int|int)\\s+' + name + '\\s*\\(');
    const match = signature.exec(source);
    assert(match, `missing function ${name}`);

    const start = source.indexOf('{', match.index);
    let depth = 0;
    for (let index = start; index < source.length; index++) {
        if (source[index] === '{') depth++;
        if (source[index] === '}' && --depth === 0) return source.slice(start, index + 1);
    }
    throw new Error(`unterminated function ${name}`);
}

function assertSingleExpectation(source, name, protocol, failure) {
    const body = functionBody(source, name);
    assert(body.includes('ret = nf_ct_expect_related(exp);'), `${name}: expectation result is captured`);
    assert(body.includes('if (ret == 0)'), `${name}: success ends the search`);
    assert(body.includes('if (ret != -EBUSY)'), `${name}: only EBUSY retries`);
    assert(body.includes(failure), `${name}: non-EBUSY error takes the failure path`);
    assert(body.includes(`exp->tuple.dst.u.${protocol}.port = htons(`), `${name}: selected port is applied`);
}

function assertPairExpectation(source, name) {
    const body = functionBody(source, name);
    assert(body.includes('ret = nf_ct_expect_related(rtp_exp);'), `${name}: RTP result is captured`);
    assert(body.includes('if (ret == -EBUSY)'), `${name}: RTP collision retries`);
    assert(body.includes('ret = nf_ct_expect_related(rtcp_exp);'), `${name}: RTCP result is captured`);
    assert(body.includes('nf_ct_unexpect_related(rtp_exp);'), `${name}: inserted RTP expectation is removed when RTCP fails`);
    assert(body.includes('if (ret != -EBUSY)'), `${name}: non-EBUSY RTCP error stops the search`);
    assert(body.includes('port = 0;') || body.includes('nated_port = 0;'), `${name}: non-EBUSY error reaches existing failure handling`);
}

const ftp = fs.readFileSync(path.join(kernel, 'nf_nat_ftp.c'), 'utf8');
const h323 = fs.readFileSync(path.join(kernel, 'nf_nat_h323.c'), 'utf8');
const sip = fs.readFileSync(path.join(kernel, 'nf_nat_sip.c'), 'utf8');

assertSingleExpectation(ftp, 'nf_nat_ftp', 'tcp', 'return NF_DROP;');
assertPairExpectation(h323, 'nat_rtp_rtcp');
assertSingleExpectation(h323, 'nat_t120', 'tcp', 'nated_port = 0;');
assertSingleExpectation(h323, 'nat_h245', 'tcp', 'nated_port = 0;');
assertSingleExpectation(h323, 'nat_q931', 'tcp', 'nated_port = 0;');
assertSingleExpectation(h323, 'nat_callforwarding', 'tcp', 'nated_port = 0;');
assertSingleExpectation(sip, 'ip_nat_sip_expect', 'udp', 'return NF_DROP;');
assertPairExpectation(sip, 'ip_nat_sdp_media');

console.log('NAT helper expectation retry regression checks passed');