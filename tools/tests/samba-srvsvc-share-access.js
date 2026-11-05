const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root,
    'release/src/router/samba-3.6.x_opwrt/source/source3/rpc_server/srvsvc/srv_srvsvc_nt.c'), 'utf8');

function functionBody(name) {
    const start = source.indexOf(`WERROR _srvsvc_${name}(`);
    assert.ok(start >= 0, `${name} handler exists`);
    const end = source.indexOf('\n/***********************************************************************************', start);
    assert.ok(end > start, `${name} handler has a terminator`);
    return source.slice(start, end);
}

const admission = source.match(/static bool srvsvc_share_access_allowed\([\s\S]*?\n}\n/);
assert.ok(admission, 'shared admission helper exists');
assert.match(admission[0], /session_info->guest\)\s*\{\s*return lp_guest_ok\(snum\);/);
assert.match(admission[0], /return user_ok_token\(session_info->unix_name,[\s\S]*?session_info->security_token, snum\);/);
assert.match(admission[0], /session_info->info3 == NULL/);

for (const name of ['NetGetFileSecurity', 'NetSetFileSecurity']) {
    const body = functionBody(name);
    const admissionCheck = body.indexOf('if (!srvsvc_share_access_allowed(p, snum))');
    const connection = body.indexOf('create_conn_struct(');
    const pathConversion = body.indexOf('filename_convert(');
    assert.ok(admissionCheck >= 0 && admissionCheck < connection,
        `${name}: share admission is checked before connecting to the share`);
    assert.ok(connection < pathConversion,
        `${name}: admission happens before path conversion`);
    assert.match(body.slice(admissionCheck, connection), /werr = WERR_ACCESS_DENIED;/,
        `${name}: denied callers receive access denied`);
}

const setBody = functionBody('NetSetFileSecurity');
const writeCheck = setBody.indexOf('if (!srvsvc_share_write_allowed(conn))');
assert.ok(writeCheck >= 0 && writeCheck < setBody.indexOf('filename_convert('),
    'NetSetFileSecurity enforces write policy before resolving the requested path');
assert.match(source, /is_share_read_only_for_token\([\s\S]*?session_info->security_token, conn\)/,
    'write policy honors read-only, read-list and write-list settings');
assert.match(source, /share_access_check\(session_info->security_token,[\s\S]*?FILE_WRITE_DATA, NULL\)/,
    'write policy honors the share security descriptor');

console.log('PASS: srvsvc file-security handlers enforce share admission and Set write policy before path access; source contracts only, not compiled Samba or RPC execution');