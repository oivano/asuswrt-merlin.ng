const assert = require('assert');
const fs = require('fs');
const vm = require('vm');

const page = fs.readFileSync('release/src/router/www/Advanced_AiDisk_ftp.asp', 'utf8');
const dropbear = fs.readFileSync('release/src/router/dropbear/src/svr-chansession.c', 'utf8');
const form = page.match(/<form\b[^>]*name="sftpForm"[\s\S]*?<\/form>/)[0];
const handler = page.match(/function switchSftpStatus\(state\)\s*\{[^}]*\}/)[0];

assert.match(form, /action="\/start_apply\.htm"/);
assert.match(form, /name="action_mode" value="apply"/);
assert.match(form, /name="action_script" value=""/);
assert.match(form, /name="current_page" value="Advanced_AiDisk_ftp\.asp"/);
assert.match(form, /name="sshd_sftp"/);
assert.strictEqual((page.match(/name="sshd_sftp"/g) || []).length, 1);
assert.match(dropbear, /strncmp\(chansess->cmd, "sftp", 4\) == 0\s*&&\s*nvram_match\("sshd_sftp", "1"\)/);

for (const state of [0, 1]) {
    let submitted = false;
    let loading = false;
    const sftpForm = {
        sshd_sftp: { value: 1 - state },
        submit() { submitted = true; }
    };
    const context = { document: { sftpForm }, showLoading() { loading = true; } };
    vm.runInNewContext(handler + '\nswitchSftpStatus(' + state + ');', context);
    assert.strictEqual(sftpForm.sshd_sftp.value, state);
    assert.ok(submitted && loading);
}

console.log('SFTP toggle checks passed');