const assert = require('assert');
const fs = require('fs');

const root = `${__dirname}/../..`;
const callback = fs.readFileSync(`${root}/release/src/router/nfs-utils-1.3.4/utils/statd/callback.c`, 'utf8');
const usb = fs.readFileSync(`${root}/release/src/router/rc/usb.c`, 'utf8');
const firewall = fs.readFileSync(`${root}/release/src/router/rc/firewall.c`, 'utf8');
const rcHeader = fs.readFileSync(`${root}/release/src/router/rc/rc.h`, 'utf8');

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert.notStrictEqual(start, -1, `missing function ${signature}`);
    const open = source.indexOf('{', start);
    let depth = 0;
    let state = 'code';
    let escaped = false;
    for (let index = open; index < source.length; index++) {
        const current = source[index];
        const next = source[index + 1];
        if (state === 'line-comment') {
            if (current === '\n') state = 'code';
            continue;
        }
        if (state === 'block-comment') {
            if (current === '*' && next === '/') {
                state = 'code';
                index++;
            }
            continue;
        }
        if (state === 'string' || state === 'character') {
            if (escaped) escaped = false;
            else if (current === '\\') escaped = true;
            else if ((state === 'string' && current === '"') || (state === 'character' && current === "'")) state = 'code';
            continue;
        }
        if (current === '/' && next === '/') {
            state = 'line-comment';
            index++;
        } else if (current === '/' && next === '*') {
            state = 'block-comment';
            index++;
        } else if (current === '"') state = 'string';
        else if (current === "'") state = 'character';
        else if (current === '{') depth++;
        else if (current === '}' && --depth === 0) return source.slice(open, index + 1);
    }
    assert.fail(`unterminated function ${signature}`);
}

const callbackBody = functionBody(callback, 'sm_notify_1_svc(');
const peerGuard = callbackBody.indexOf('!nfs_is_v4_loopback(sap)');
assert(peerGuard >= 0, 'SM_NOTIFY must reject every non-loopback transport peer');
assert(peerGuard < callbackBody.indexOf('ha_callout('), 'reject before calling external hooks');
assert(peerGuard < callbackBody.indexOf('nlist_insert(&notify'), 'reject before queuing lockd notifications');
assert.match(rcHeader, /#define NFS_STATD_PORT "4000"/);
assert.match(usb, /eval\("\/usr\/sbin\/statd", "-p", NFS_STATD_PORT\)/);

for (const name of ['\nfilter_setting(', '\nfilter_setting2(']) {
    const start = firewall.indexOf(name);
    assert(start >= 0, `missing firewall generator ${name.trim()}`);
    const firstAccept = firewall.indexOf('-A INPUT -m state --state RELATED,ESTABLISHED', start);
    assert(firstAccept > start, `${name.trim()} must contain input acceptance rules`);
    const prefix = firewall.slice(start, firstAccept);
    for (const protocol of ['tcp', 'udp']) {
        const drop = prefix.indexOf(`-p ${protocol} --dport %s -j DROP`);
        assert(drop >= 0, `${name.trim()} must block statd over ${protocol}`);
        assert(prefix.includes(`fp_ipv6, "-A INPUT ! -i lo -p ${protocol} --dport %s -j DROP\\n", NFS_STATD_PORT`),
            `${name.trim()} must block statd over IPv6 ${protocol}`);
    }
}

console.log('NFS statd SM_NOTIFY isolation checks passed');