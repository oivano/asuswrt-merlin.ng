const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const files = read('release/src/router/samba-3.6.x_opwrt/source/source3/smbd/files.c');
const proto = read('release/src/router/samba-3.6.x_opwrt/source/source3/smbd/proto.h');
const reply = read('release/src/router/samba-3.6.x_opwrt/source/source3/smbd/reply.c');
const service = read('release/src/router/samba-3.6.x_opwrt/source/source3/smbd/service.c');
const connection = read('release/src/router/samba-3.6.x_opwrt/source/source3/smbd/conn.c');
const ipc = read('release/src/router/samba-3.6.x_opwrt/source/source3/smbd/ipc.c');
const smb2Tcon = read('release/src/router/samba-3.6.x_opwrt/source/source3/smbd/smb2_tcon.c');
const defaults = read('release/src/router/shared/defaults.c');
const config = read('release/src/router/libdisk/write_smb_conf.c');
const ui = read('release/src/router/www/Advanced_AiDisk_samba.asp');

const closeUser = files.slice(files.indexOf('void file_close_user('), files.indexOf('\n/*', files.indexOf('void file_close_user(')));
assert.match(proto, /void file_close_user\(struct smb_request \*req, int vuid\);/);
assert.match(proto, /void file_close_conn\(struct smb_request \*req, connection_struct \*conn\);/);
assert.match(proto, /void close_cnum\(struct smb_request \*req, connection_struct \*conn, uint16 vuid\);/);
assert.match(closeUser, /struct smbd_server_connection \*sconn = req->sconn;/);
assert.match(closeUser, /close_file\(req, fsp, SHUTDOWN_CLOSE\);/);
assert.match(reply, /file_close_user\(req, req->vuid\);/);
assert.match(files, /void file_close_conn\(struct smb_request \*req, connection_struct \*conn\)[\s\S]*?close_file\(req, fsp, SHUTDOWN_CLOSE\);/);
assert.match(service, /void close_cnum\(struct smb_request \*req, connection_struct \*conn, uint16 vuid\)[\s\S]*?file_close_conn\(req, conn\);/);
assert.match(reply, /close_cnum\(req, conn, req->vuid\);/);
assert.match(connection, /close_cnum\(NULL, conn,/);
assert.match(ipc, /close_cnum\(req, conn,/);
assert.match(smb2Tcon, /close_cnum\(NULL, tcon->compat_conn,/);
assert.match(files, /if \(\(req != NULL\) && \(fsp == req->chain_fsp\)\)\s*\{\s*req->chain_fsp = NULL;/);

assert.match(defaults, /\{ "smbd_protocol", "1", CKN_STR1/);
assert.match(config, /if \(nvram_get_int\("smbd_protocol"\) == 0\)\s*fprintf\(fp, "max protocol = NT1\\n"\);/);
assert.match(config, /if \(nvram_get_int\("smbd_protocol"\) == 1\)\s*fprintf\(fp, "min protocol = SMB2\\n"\);/);
for (const value of ['0', '1', '2']) {
    assert.match(ui, new RegExp(`<option class="content_input_fd" value="${value}"`));
}

console.log('SMB chain FSP invalidation and SMB2 factory default checks passed');
