const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const config = read('release/src/router/libdisk/write_smb_conf.c');
const vfs = read('release/src/router/samba-3.6.x_opwrt/source/source3/modules/vfs_default.c');
const trans2 = read('release/src/router/samba-3.6.x_opwrt/source/source3/smbd/trans2.c');
const auth = read('release/src/router/samba-3.6.x_opwrt/source/source3/auth/auth_util.c');
const services = read('release/src/router/rc/services.c');
for (const setting of ['follow symlinks = no', 'unix extensions = no', 'wide links = no', 'guest account = nobody']) {
    assert.ok(config.includes(`"${setting}\\n"`), setting);
}
assert.equal((config.match(/guest account =/g) || []).length, 1);
assert.match(services, /nobody:x:65534:65534:/);
const guest = auth.slice(auth.indexOf('static NTSTATUS make_new_server_info_guest('), auth.indexOf('static NTSTATUS make_system_session_info_from_pw('));
const guestGuard = guest.match(/if \((\(\*server_info\)->utok.uid == 0)\)\s*\{([\s\S]*?)\n\t\}/);
assert.ok(guestGuard);
assert.match(guestGuard[2], /TALLOC_FREE\(\*server_info\);\s*status = NT_STATUS_ACCESS_DENIED;\s*goto done;/);
assert.ok(guest.indexOf('create_local_token(*server_info)') < guest.indexOf(guestGuard[0]));
assert.ok(guest.indexOf(guestGuard[0]) < guest.indexOf('user_session_key ='));
const rootGuest = new Function('uid', `return ${guestGuard[1].replace('(*server_info)->utok.uid', 'uid')};`);
for (const uid of [0, 100, 500, 65534]) assert.equal(rootGuest(uid), uid === 0);
const link = trans2.slice(trans2.indexOf('static NTSTATUS smb_set_file_unix_link('), trans2.indexOf('static NTSTATUS smb_set_file_unix_hlink('));
assert.ok(link.indexOf('if (!lp_symlinks(SNUM(conn)))') < link.indexOf('SMB_VFS_SYMLINK('));
assert.match(link, /if \(!lp_symlinks\(SNUM\(conn\)\)\)\s*\{\s*return NT_STATUS_ACCESS_DENIED;/);
assert.match(vfs, /if \(!lp_symlinks\(SNUM\(handle->conn\)\)\)\s*\{\s*result = vfswrap_open_nosymlinks/);

const helper = vfs.slice(vfs.indexOf('static int vfswrap_open_nosymlinks('), vfs.indexOf('static int vfswrap_open('));
assert.match(helper, /defined\(__linux__\).*defined\(O_NOFOLLOW\).*defined\(O_DIRECTORY\).*defined\(AT_FDCWD\)/);
assert.match(helper, /#else\s*errno = ENOSYS;\s*return -1;/);
assert.match(helper, /flags \|= O_LARGEFILE;/);
assert.match(helper, /saved_errno = errno;[\s\S]*close\(dir_fd\);[\s\S]*errno = saved_errno;/);

// Execute the C helper's control flow with descriptor-relative host filesystem operations.
let body = helper.slice(helper.indexOf('\n\tchar *path'), helper.indexOf('\n#else'));
body = body.replace(/^#(?:ifdef O_LARGEFILE|endif)\n/gm, '')
    .replace(/\bchar \*(\w+) = NULL;/g, 'let $1 = null;')
    .replace(/\bint (\w+)( = -1)?;/g, 'let $1$2;')
    .replace(/\bNULL\b/g, 'null')
    .replace(/conn->connectpath/g, 'conn.connectpath')
    .replace(/talloc_strdup\(talloc_tos\(\), name\)/g, 'name')
    .replace(/separator = strchr\(component, '\/'\);/g, "separator = component.indexOf('/'); if (separator === -1) separator = null;")
    .replace(/\*separator = '\\0';/g, "remainder = component.slice(separator + 1); component = component.slice(0, separator);")
    .replace(/component\[0\] == '\\0'/g, "component.length === 0")
    .replace(/strcmp\(component, "\.\."\) == 0/g, "component === '..'")
    .replace(/component = separator \+ 1;/g, 'component = remainder;')
    .replace(/goto out;/g, 'break walk;')
    .replace(/out:\n/, '}\n')
    .replace(/TALLOC_FREE\(path\);/g, '')
    .replace(/dir_fd = sys_open\(/, 'walk: {\ndir_fd = sys_open(');
body = body.replace(/name\[0\] == '\\0'/g, 'name.length === 0');

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'samba-containment-'));
const share = path.join(temporary, 'share');
const outside = path.join(temporary, 'outside');
fs.mkdirSync(share);
fs.mkdirSync(outside);
const { O_RDONLY, O_DIRECTORY, O_NOFOLLOW, O_WRONLY, O_CREAT, O_TRUNC, O_EXCL } = fs.constants;
let opened = new Set();
let hook = () => {};
function openAt(dirfd, component, flags, mode) {
    hook(dirfd, component);
    return openHost(`/proc/self/fd/${dirfd}/${component}`, flags, mode);
}
let error;
function openHost(name, flags, mode) {
    try {
        const fd = fs.openSync(name, flags, mode);
        opened.add(fd);
        return fd;
    } catch (failure) {
        error = failure.code;
        return -1;
    }
}
function close(fd) {
    fs.closeSync(fd);
    opened.delete(fd);
}
const run = new Function('conn', 'name', 'flags', 'mode', 'sys_open', 'openat', 'close',
    'O_RDONLY', 'O_DIRECTORY', 'O_NOFOLLOW', 'O_LARGEFILE',
    `let errno = 0, remainder; const EACCES = 13, ENOMEM = 12; ${body}`);
function attempt(name, flags = O_WRONLY | O_CREAT | O_TRUNC) {
    error = undefined;
    const fd = run({ connectpath: share }, name, flags, 0o600, openHost, openAt, close,
        O_RDONLY, O_DIRECTORY, O_NOFOLLOW, 0);
    if (fd !== -1) close(fd);
    assert.equal(opened.size, 0, 'no leaked descriptors');
    return fd !== -1;
}
try {
    fs.mkdirSync(path.join(share, 'dir'));
    assert.equal(attempt('dir/normal'), true);
    assert.equal(attempt('dir/normal', O_RDONLY), true);
    assert.equal(attempt('.', O_RDONLY | O_DIRECTORY), true);
    assert.equal(attempt('dir/normal', O_WRONLY | O_CREAT | O_EXCL), false);
    assert.equal(error, 'EEXIST');
    for (const name of ['', '/absolute', '../outside/new', 'dir/../../outside/new', 'dir//new']) {
        assert.equal(attempt(name), false, name);
    }
    for (const target of [path.join(outside, 'new'), '../outside/new', 'dir/normal']) {
        fs.symlinkSync(target, path.join(share, 'link'));
        assert.equal(attempt('link'), false, target);
        assert.equal(error, 'ELOOP');
        fs.unlinkSync(path.join(share, 'link'));
    }
    fs.writeFileSync(path.join(outside, 'existing'), 'unchanged');
    fs.symlinkSync(path.join(outside, 'existing'), path.join(share, 'existing'));
    assert.equal(attempt('existing'), false);
    assert.equal(fs.readFileSync(path.join(outside, 'existing'), 'utf8'), 'unchanged');
    fs.symlinkSync(outside, path.join(share, 'alias'));
    assert.equal(attempt('alias/new'), false);
    assert.equal(fs.existsSync(path.join(outside, 'new')), false);

    // Swap a checked directory before the walker opens it.
    hook = (dirfd, component) => {
        if (component !== 'dir') return;
        hook = () => {};
        fs.renameSync(path.join(share, 'dir'), path.join(share, 'saved'));
        fs.symlinkSync(outside, path.join(share, 'dir'));
    };
    assert.equal(attempt('dir/raced'), false);
    assert.equal(fs.existsSync(path.join(outside, 'raced')), false);
    fs.unlinkSync(path.join(share, 'dir'));
    fs.renameSync(path.join(share, 'saved'), path.join(share, 'dir'));

    hook = (dirfd, component) => {
        if (component !== 'dir') return;
        hook = () => {};
        fs.renameSync(path.join(share, 'dir'), path.join(share, 'saved'));
        fs.mkdirSync(path.join(share, 'dir'));
        fs.symlinkSync(path.join(outside, 'replacement'), path.join(share, 'dir/replacement'));
    };
    assert.equal(attempt('dir/replacement'), false);
    assert.equal(error, 'ELOOP');
    assert.equal(fs.existsSync(path.join(outside, 'replacement')), false);
    fs.rmSync(path.join(share, 'dir'), { recursive: true });
    fs.renameSync(path.join(share, 'saved'), path.join(share, 'dir'));

    // Swap after the parent descriptor has been pinned.
    hook = (dirfd, component) => {
        if (component !== 'pinned') return;
        hook = () => {};
        fs.renameSync(path.join(share, 'dir'), path.join(share, 'saved'));
        fs.symlinkSync(outside, path.join(share, 'dir'));
    };
    assert.equal(attempt('dir/pinned'), true);
    assert.equal(fs.existsSync(path.join(share, 'saved/pinned')), true);
    assert.equal(fs.existsSync(path.join(outside, 'pinned')), false);

    // Replace the final name after validation, immediately before opening.
    hook = (dirfd, component) => {
        if (component !== 'final') return;
        hook = () => {};
        fs.symlinkSync(path.join(outside, 'final'), path.join(share, 'final'));
    };
    assert.equal(attempt('final'), false);
    assert.equal(error, 'ELOOP');
    assert.equal(fs.existsSync(path.join(outside, 'final')), false);

    // Negative control: the former pathname-based open escapes through the alias.
    const fd = fs.openSync(path.join(share, 'alias/control'), O_WRONLY | O_CREAT, 0o600);
    fs.closeSync(fd);
    assert.equal(fs.existsSync(path.join(outside, 'control')), true);
    fs.symlinkSync(path.join(outside, 'dangling-control'), path.join(share, 'dangling-control'));
    const danglingFd = fs.openSync(path.join(share, 'dangling-control'), O_WRONLY | O_CREAT, 0o600);
    fs.closeSync(danglingFd);
    assert.equal(fs.existsSync(path.join(outside, 'dangling-control')), true);
    console.log('PASS: Samba policy contracts and source-translated open control flow with real host filesystem race fixtures (not compiled C or SMB sessions)');
} finally {
    for (const fd of opened) fs.closeSync(fd);
    fs.rmSync(temporary, { recursive: true, force: true });
}