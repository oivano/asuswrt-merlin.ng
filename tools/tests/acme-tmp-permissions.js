const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const common = read('release/src/router/rc/common.c');
const init = read('release/src/router/rc/init.c');
const acme = read('release/src/router/acme.sh/acme.sh');
const hook = read('release/src/router/acme.sh/dnsapi/dns_asusapi.sh');
const clients = [
    read('release/src/router/inadyn/plugins/asuscomm.c'),
    read('release/src/router/inadyn/plugins/asuscommv2.c')
];

const prepare = common.slice(common.indexOf('static int le_status_fd_secure'), common.indexOf('int le_fw_script_is_safe'));
const wrapper = common.slice(common.indexOf('int le_acme_main_safe'), common.indexOf('#endif', common.indexOf('int le_acme_main_safe')));
assert.match(prepare, /O_WRONLY \| O_NOFOLLOW \| O_NONBLOCK/);
assert.match(prepare, /O_CREAT \| O_EXCL \| O_NOFOLLOW/);
assert.match(prepare, /st\.st_uid != 0/);
assert.match(prepare, /st\.st_nlink != 1/);
assert.match(prepare, /fchmod\(fd, 0600\)/);
assert.match(prepare, /le_status_file_prepare\("\/tmp\/acme_err"\)/);
assert.ok(wrapper.indexOf('le_workdir_prepare()') < wrapper.indexOf('le_acme_main(argc, argv)'));
assert.ok(init.indexOf('le_workdir_prepare()') < init.indexOf('start_services();'));
assert.match(acme, /echo -n "\$errordetail" > \/tmp\/acme_err/);
assert.match(hook, /echo -n "\$txtvalue" > \/tmp\/\.le\/acme\.txt/);
assert.doesNotMatch(hook, /\/tmp\/acme\.txt/);
for (const client of clients)
    assert.match(client, /open\("\/tmp\/\.le\/acme\.txt", O_RDONLY\)/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'acme-tmp-permissions-'));
try {
    const victim = path.join(temporary, 'victim');
    const status = path.join(temporary, 'acme_err');
    fs.writeFileSync(victim, 'preserve me');
    fs.symlinkSync(victim, status);

    let descriptor;
    try {
        descriptor = fs.openSync(status, fs.constants.O_WRONLY |
            fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    } catch (error) {
        assert.ok(['ELOOP', 'ENOENT'].includes(error.code));
    }
    if (descriptor !== undefined)
        fs.closeSync(descriptor);
    fs.unlinkSync(status);
    descriptor = fs.openSync(status, fs.constants.O_WRONLY | fs.constants.O_CREAT |
        fs.constants.O_EXCL | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK, 0o600);
    fs.closeSync(descriptor);
    assert.equal(fs.readFileSync(victim, 'utf8'), 'preserve me');
    assert.equal(fs.lstatSync(status).isFile(), true);

    fs.writeFileSync(status, 'existing error');
    assert.equal(fs.readFileSync(status, 'utf8'), 'existing error');
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}

console.log('acme-tmp-permissions: source contracts and planted-symlink check passed');