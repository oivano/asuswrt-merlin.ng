const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const sysinfo = read('release/src/router/httpd/sysinfo.c');
const ajax = read('release/src/router/www/ajax_vpn_status.asp');
const page = read('release/src/router/www/Advanced_VPNStatus.asp');

const escapeStart = sysinfo.indexOf('static int websWriteJsonString(');
const handlerStart = sysinfo.indexOf('int ej_show_sysinfo(', escapeStart);
const escapeHelper = sysinfo.slice(escapeStart, handlerStart);
assert(escapeStart >= 0 && handlerStart > escapeStart);
for (const escape of [
    'case \'"\'', 'case \'\\\\\'', 'case \'/\'', 'case \'<\'', 'case \'>\'',
    'case \'&\'', 'case \'\\n\'', 'case \'\\r\'', 'case \'\\t\'',
    '0xe2', '0x80', '0xa8', '0xa9', '\\u003c', '\\u003e', '\\u0026',
    '\\u2028', '\\u2029'
]) {
    assert(escapeHelper.includes(escape), `missing JavaScript escape ${escape}`);
}
assert.match(sysinfo, /strncmp\(type,"vpnstatus",9\)[\s\S]*?json_result = 1/);
assert.match(sysinfo, /if \(json_result\)\s*retval \+= websWriteJsonString\(wp, result\)/);
assert.equal((ajax.match(/^vpn_(?:server|client)[1-5]_status = <% sysinfo\("vpnstatus\.[^\n]+;\s*%>;/gm) || []).length, 7);
assert.doesNotMatch(ajax, /^vpn_(?:server|client)[1-5]_status = "<% sysinfo\("vpnstatus\./m);

function escapeJsString(value) {
    return JSON.stringify(value)
        .replace(/</g, '\\u003c')
        .replace(/>/g, '\\u003e')
        .replace(/&/g, '\\u0026')
        .replace(/\u2028/g, '\\u2028')
        .replace(/\u2029/g, '\\u2029');
}

let alertCalls = 0;
const payload = `";alert(1);//\\</script>\u0000\u001f\u2028\u2029`;
const literal = escapeJsString(payload);
assert.equal(vm.runInNewContext(literal, { alert: () => alertCalls++ }), payload);
assert.equal(alertCalls, 0);
assert.doesNotMatch(literal, /[<>&\u2028\u2029]/);

const parseStart = page.indexOf('function parseStatus(');
const parseEnd = page.indexOf('\n}\n', parseStart) + 2;
const parseStatus = page.slice(parseStart, parseEnd);
assert(parseStart >= 0 && parseEnd > parseStart);
for (const field of [
    'clientTableHeaders[8]', 'clientTableHeaders[0]', 'clientTableEntries[i][8]',
    'clientTableHeaders[1]', 'clientTableHeaders[2]',
    'clientTableHeaders[6]', 'clientTableHeaders[11]',
    'clientTableEntries[i][0]', 'clientTableEntries[i][1]', 'clientTableEntries[i][2]',
    'clientTableEntries[i][6]', 'clientTableEntries[i][11]', 'routeTableHeaders[i]',
    'routeTableEntries[i][j]', 'statsTableEntries[i][0]', 'staticstatsTableEntries[i][0]', 'ipaddress'
]) {
    assert(parseStatus.includes(`htmlEnDeCode.htmlEncode(${field})`), `unencoded HTML field ${field}`);
}
assert(parseStatus.includes('htmlEnDeCode.htmlEncode(clientTableHeaders[4].replace("Bytes","MBytes"))'));
assert(parseStatus.includes('htmlEnDeCode.htmlEncode(clientTableHeaders[5].replace("Bytes","MBytes"))'));
assert.match(parseStatus, /Number\(clientTableEntries\[i\]\[4\]\/1024\/1024\)/);
assert.match(parseStatus, /Number\(clientTableEntries\[i\]\[5\]\/1024\/1024\)/);
assert.match(parseStatus, /Number\(staticstatsTableEntries\[i\]\[1\]\)/);

const encode = value => String(value).replace(/[&<>"']/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
})[character]);
let output = '';
const context = {
    document: { getElementById: () => ({ set innerHTML(value) { output = value; }, get innerHTML() { return output; } }) },
    htmlEnDeCode: { htmlEncode: encode }
};
const clientHeaders = Array(12).fill('Header');
const statusPayload = '<img src=x onerror=alert(1)';
clientHeaders[0] = statusPayload;
clientHeaders[8] = statusPayload;
clientHeaders[11] = statusPayload;
const clientRow = [statusPayload, statusPayload, statusPayload, 'ipv6', '1048576', '2097152', statusPayload, 'time', statusPayload, 'id', 'peer', statusPayload];
const status = [
    `HEADER,CLIENT_LIST,${clientHeaders.join(',')}`,
    `CLIENT_LIST,${clientRow.join(',')}`,
    `HEADER,ROUTING_TABLE,${statusPayload},Route,Address,Last Ref,`,
    `ROUTING_TABLE,${statusPayload},${statusPayload},${statusPayload},now,`,
    'OpenVPN STATISTICS',
    `${statusPayload},7`,
    'END'
].join('>');
vm.runInNewContext(`${parseStatus}\nparseStatus(status, 'block', '127.0.0.1', '${payload.replace(/\\/g, '\\\\').replace(/'/g, "\\'")}');`, {
    ...context,
    status
});
assert(output.includes(encode(statusPayload)), 'peer-provided status text is preserved as escaped visible text');
assert(!output.includes(statusPayload), 'raw peer-provided markup must not reach innerHTML');
assert.match(output, /<table[\s\S]*Clients[\s\S]*Routes[\s\S]*Statistics/);

console.log('PASS: OpenVPN status JavaScript serialization and peer-field HTML encoding (source/model checks; not compiled C or browser/hardware validation)');