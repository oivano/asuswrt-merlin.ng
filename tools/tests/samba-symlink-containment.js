const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const config = read('release/src/router/libdisk/write_smb_conf.c');
const sambaMakefile = read('release/src/router/samba-3.6.x_opwrt/Makefile');
const tdb = read('release/src/router/samba-3.6.x_opwrt/source/lib/tdb/common/open.c');
const vfs = read('release/src/router/samba-3.6.x_opwrt/source/source3/modules/vfs_default.c');
const trans2 = read('release/src/router/samba-3.6.x_opwrt/source/source3/smbd/trans2.c');
const auth = read('release/src/router/samba-3.6.x_opwrt/source/source3/auth/auth_util.c');
const smbpasswd = read('release/src/router/samba-3.6.x_opwrt/source/source3/utils/owrt_smbpasswd.c');
const services = read('release/src/router/rc/services.c');
const usb = read('release/src/router/rc/usb.c');
const diskShare = read('release/src/router/libdisk/disk_share.c');
for (const setting of ['follow symlinks = no', 'unix extensions = no', 'wide links = no', 'guest account = nobody']) {
    assert.ok(config.includes(`"${setting}\\n"`), setting);
}
for (const setting of ['lock', 'state', 'cache']) {
    assert.ok(config.includes(`"${setting} directory = /var/run/samba/locks\\n"`), `${setting} directory`);
    assert.ok(sambaMakefile.includes(`--with-${setting}dir=/var/run/samba/locks`), `${setting} build directory`);
}
const prepareSambaDir = usb.slice(usb.indexOf('static int prepare_samba_dir('), usb.indexOf('void\nstart_samba(void)'));
assert.match(prepareSambaDir, /mkdir\(path, mode\)/);
assert.match(prepareSambaDir, /lstat\(path, &st\).*S_ISDIR\(st\.st_mode\).*st\.st_uid != 0/s);
assert.match(prepareSambaDir, /st\.st_mode & 0022/);
const sambaStartSection = usb.slice(usb.indexOf('start_samba(void)'), usb.indexOf('stop_samba(int force)'));
assert.ok(sambaStartSection.indexOf('prepare_samba_dir(SAMBA_RUNTIME_DIR, 0755)') < sambaStartSection.indexOf('system("/sbin/write_smb_conf")'));
assert.ok(sambaStartSection.indexOf('prepare_samba_dir(SAMBA_LOCK_DIR, 0700)') < sambaStartSection.indexOf('xstart("/usr/sbin/nmbd"'));
assert.match(tdb, /open\(name, open_flags \| O_NOFOLLOW, mode\)/);
assert.match(tdb, /tdb->open_flags \|= O_NOFOLLOW/);
assert.match(tdb, /open\(tdb->name, tdb->open_flags & ~\(O_CREAT\|O_TRUNC\), 0\)/);
const tdbNewDatabase = tdb.slice(tdb.indexOf('static int tdb_new_database('), tdb.indexOf('\n\n\nstatic int tdb_already_open'));
assert.match(tdbNewDatabase, /fstat\(tdb->fd, &st\)/);
assert.match(tdbNewDatabase, /!S_ISREG\(st\.st_mode\) \|\| st\.st_uid != geteuid\(\) \|\| st\.st_nlink != 1/);
assert.ok(tdbNewDatabase.indexOf('st.st_nlink != 1') < tdbNewDatabase.indexOf('ftruncate(tdb->fd, 0)'));
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

const smbUpdateStart = usb.indexOf('static int update_smbpasswd_account(');
const smbUpdateEnd = usb.indexOf('void add_usb_host_modules', smbUpdateStart);
const smbUpdate = usb.slice(smbUpdateStart, smbUpdateEnd);
assert.ok(smbUpdateStart >= 0 && smbUpdateEnd > smbUpdateStart);
assert.match(smbUpdate, /char \*argv\[\] = \{ "\/usr\/sbin\/smbpasswd", \(char \*\)username, NULL \}/);
assert.match(smbUpdate, /dup2\(password_pipe\[0\], STDIN_FILENO\)/);
assert.match(smbUpdate, /execve\(argv\[0\], argv, envp\)/);
assert.match(smbUpdate, /char \*envp\[\] = \{ NULL \}/);
assert.doesNotMatch(smbUpdate, /"\/usr\/sbin\/smbpasswd"[^;]*\(char \*\)password/);
assert.match(smbUpdate, /_eval\(argv, NULL, 0, NULL\)/);
assert.match(smbUpdate, /!strcmp\(username, nvram_safe_get\("http_username"\)\)\)\s*return 0;/);
assert.doesNotMatch(smbUpdate, /system\(|str_escape_quotes/);
const startSamba = usb.slice(usb.indexOf('start_samba(void)'), usb.indexOf('stop_samba(int force)'));
assert.equal((startSamba.match(/update_smbpasswd_account\(char_user, char_passwd\)/g) || []).length, 2);
assert.match(startSamba, /update_smbpasswd_account\("nobody", ""\)/);
assert.doesNotMatch(startSamba, /str_escape_quotes|system\(cmd\)/);
assert.match(smbpasswd, /int uid;[\s\S]*?uid = find_uid_for_user\(argv\[1\]\);/);
assert.match(smbpasswd, /getchar\(\).*'\\n'/s);
assert.match(smbpasswd, /E_md4hash\(password, new_nt_p16\)/);
assert.doesNotMatch(smbpasswd, /E_md4hash\(argv\[2\]/);
const uidGuard = smbpasswd.match(/if\((uid <= 0)\)\s*exit\(2\);/);
assert.ok(uidGuard);
const rejectsUid = new Function('uid', `return ${uidGuard[1]};`);
for (const uid of [-1, 0, 1, 100, 65534]) assert.equal(rejectsUid(uid), uid <= 0);
assert.match(smbpasswd, /"%s:%d:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX:", argv\[1\], uid/);
assert.match(diskShare, /int samba_account_name_valid\(const char \*account\)/);
assert.match(diskShare, /int samba_account_password_valid\(const char \*password\)/);
assert.equal((diskShare.match(/samba_account_name_valid\(account\)/g) || []).length, 4);
assert.equal((diskShare.match(/samba_account_name_valid\(new_account\)/g) || []).length, 2);
assert.equal((diskShare.match(/samba_account_password_valid\(password\)/g) || []).length, 2);
assert.equal((diskShare.match(/samba_account_password_valid\(new_password\)/g) || []).length, 2);

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
const { O_RDONLY, O_DIRECTORY, O_NOFOLLOW, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_EXCL } = fs.constants;
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
    const victim = path.join(outside, 'tdb-victim');
    const tdbLink = path.join(share, 'locking.tdb');
    fs.writeFileSync(victim, 'preserve this file');
    fs.symlinkSync(victim, tdbLink);
    assert.throws(() => fs.openSync(tdbLink, O_RDWR | O_NOFOLLOW), { code: 'ELOOP' });
    assert.equal(fs.readFileSync(victim, 'utf8'), 'preserve this file');
    fs.unlinkSync(tdbLink);
    fs.linkSync(victim, tdbLink);
    assert.equal(fs.statSync(tdbLink).nlink, 2);
    assert.equal(fs.readFileSync(victim, 'utf8'), 'preserve this file');
    fs.unlinkSync(tdbLink);
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