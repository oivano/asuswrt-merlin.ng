const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const archive = fs.readFileSync(path.join(root,
    'release/src/router/busybox/archival/libarchive/data_extract_all.c'), 'utf8');
const body = (source, name) => {
    const match = source.match(new RegExp(`\\b${name}\\([^\\n]*\\)\\n\\{([\\s\\S]*?)\\n\\}`));
    assert(match, name);
    return match[1];
};
const translateSpool = code => code.replaceAll('spool->', 'spool.')
    .replaceAll('&spool.identity', 'spool.identity')
    .replaceAll('&st', 'st').replaceAll('&opened', 'opened')
    .replaceAll('NULL', 'null');
const emptySpool = () => ({ directory: '', path: '', file: null, identity: {}, complete: 0 });
const clearCode = translateSpool(body(web, 'httpd_spool_clear'))
    .replace('memset(spool, 0, sizeof(*spool));', 'Object.assign(spool, emptySpool());');
const clear = new Function('spool', 'api', 'emptySpool', `with (api) { ${clearCode} }`);
const createCode = translateSpool(body(web, 'httpd_spool_create'))
    .replace('int fd;', 'let fd;').replace('struct stat st;', 'const st = {};')
    .replace('strlcpy(spool.directory, "/tmp/httpd-restore-XXXXXX", sizeof(spool.directory));',
        'spool.directory = "/tmp/httpd-restore-XXXXXX";')
    .replace('mkdtemp(spool.directory)', '(spool.directory = mkdtemp(spool.directory))')
    .replace("spool.directory[0] = '\\0';", 'spool.directory = "";')
    .replace('snprintf(spool.path, sizeof(spool.path), "%s/data", spool.directory);',
        'spool.path = spool.directory + "/data";')
    .replaceAll('goto fail;', 'throw rejected;');
const [createOperations, createFailure] = createCode.split('\nfail:');
assert(createOperations && createFailure);
const create = new Function('spool', 'api', `with (api) {
    const rejected = {};
    try { ${createOperations} } catch (error) {
        if (error !== rejected) throw error;
        ${createFailure}
    }
}`);
const validCode = translateSpool(body(web, 'httpd_spool_valid'))
    .replace('struct stat st, opened;', 'const st = {}, opened = {};');
const valid = new Function('spool', 'api', `with (api) { ${validCode} }`);

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'httpd-restore-test-'));
let activeSpool;
let fault = '';
const api = {
    ...fs.constants,
    S_ISREG: mode => (mode & 0o170000) === 0o100000,
    S_ISDIR: mode => (mode & 0o170000) === 0o040000,
    S_ISLNK: mode => (mode & 0o170000) === 0o120000,
    errno: 0,
    ENOENT: 2,
    mkdtemp: template => {
        assert.equal(template, '/tmp/httpd-restore-XXXXXX');
        return fault === 'mkdtemp' ? '' : fs.mkdtempSync(path.join(temp, 'spool-'));
    },
    open: (name, flags, mode) => {
        if (fault === 'open') return -1;
        assert.equal(flags, fs.constants.O_RDWR | fs.constants.O_CREAT |
            fs.constants.O_EXCL | fs.constants.O_NOFOLLOW);
        assert.equal(mode, 0o600);
        return fs.openSync(name, flags, mode);
    },
    fchmod: (fd, mode) => {
        if (fault === 'fchmod') return -1;
        fs.fchmodSync(fd, mode);
        return 0;
    },
    fdopen: (fd, mode) => {
        assert.equal(mode, 'w+');
        return fault === 'fdopen' ? null : { fd };
    },
    fileno: file => file.fd,
    close: fd => fs.closeSync(fd),
    fclose: file => fs.closeSync(file.fd),
    unlink: name => { try { fs.unlinkSync(name); } catch (error) {
        if (error.code !== 'ENOENT') throw error;
    } },
    rmdir: name => fs.rmdirSync(name),
    httpd_spool_clear: spool => clear(spool, api, emptySpool),
    bb_error_msg_and_die: () => { throw new Error('unsafe archive path'); },
    bb_perror_msg_and_die: () => { throw new Error('archive path check failed'); }
};
function assignStat(stat, result) {
    Object.assign(result, {
        st_mode: stat.mode, st_uid: stat.uid === process.getuid() ? 0 : stat.uid,
        st_nlink: stat.nlink, st_dev: stat.dev, st_ino: stat.ino
    });
    if (fault === 'owner') result.st_uid = 65534;
    return 0;
}
api.fstat = (fd, result) => fault === 'fstat' ? -1 : assignStat(fs.fstatSync(fd), result);
api.lstat = (name, result) => {
    try { return assignStat(fs.lstatSync(name), result); } catch (error) {
        api.errno = error.code === 'ENOENT' ? api.ENOENT : -1;
        return -1;
    }
};

try {
    for (const kind of ['fifo', 'symlink', 'regular']) {
        const legacy = path.join(temp, `settings_u.prf-${kind}`);
        const outside = path.join(temp, `outside-${kind}`);
        fs.writeFileSync(outside, 'unchanged');
        if (kind === 'fifo') execFileSync('mkfifo', [legacy]);
        else if (kind === 'symlink') fs.symlinkSync(outside, legacy);
        else fs.writeFileSync(legacy, 'attacker data', { mode: 0o666 });
        assert.throws(() => fs.openSync(legacy, fs.constants.O_RDWR | fs.constants.O_CREAT |
            fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600));
        const spool = activeSpool = emptySpool();
        assert(create(spool, api));
        assert.equal(fs.statSync(spool.directory).mode & 0o777, 0o700);
        assert.equal(fs.statSync(spool.path).mode & 0o777, 0o600);
        assert(!valid(spool, api), 'incomplete uploads cannot be consumed');
        fs.writeSync(spool.file.fd, 'administrator backup');
        spool.complete = 1;
        assert(valid(spool, api));
        assert.equal(fs.readFileSync(outside, 'utf8'), 'unchanged');
        if (kind === 'regular') assert.equal(fs.readFileSync(legacy, 'utf8'), 'attacker data');
        const directory = spool.directory;
        api.httpd_spool_clear(spool);
        assert(!fs.existsSync(directory));
        api.httpd_spool_clear(spool);
    }
    for (fault of ['mkdtemp', 'open', 'fstat', 'owner', 'fchmod', 'fdopen']) {
        const spool = activeSpool = emptySpool();
        assert.equal(create(spool, api), null, fault);
        assert.deepEqual(spool, emptySpool(), fault);
        assert(!fs.readdirSync(temp).some(name => name.startsWith('spool-')), fault);
    }
    fault = '';
    const spool = activeSpool = emptySpool();
    assert(create(spool, api));
    spool.complete = 1;
    assert(valid(spool, api));
    fault = 'owner';
    assert(!valid(spool, api));
    fault = '';
    fs.chmodSync(spool.directory, 0o755);
    assert(!valid(spool, api));
    fs.chmodSync(spool.directory, 0o700);
    fs.chmodSync(spool.path, 0o666);
    assert(!valid(spool, api));
    fs.chmodSync(spool.path, 0o600);
    fs.linkSync(spool.path, path.join(spool.directory, 'alias'));
    assert(!valid(spool, api));
    fs.unlinkSync(path.join(spool.directory, 'alias'));
    assert(valid(spool, api));
    fs.unlinkSync(spool.path);
    fs.writeFileSync(spool.path, 'replacement', { mode: 0o600 });
    assert(!valid(spool, api), 'same pathname is not the uploaded inode');
    api.httpd_spool_clear(spool);

    let pathCode = body(archive, 'check_extract_path')
        .replace('char *path = xstrdup(name);', "const path = [...name, '\\0'];")
        .replace('char *component = path;', 'let component = 0;')
        .replace('char *cursor;', 'let cursor;').replace('struct stat st;', 'const st = {};')
        .replace('char saved = *cursor;', 'const saved = path[cursor];')
        .replace('cursor = path', 'cursor = 0').replaceAll('cursor != path', 'cursor != 0')
        .replaceAll('component[0]', 'path[component]')
        .replaceAll('component[1]', 'path[component + 1]').replaceAll('*cursor', 'path[cursor]')
        .replace('lstat(path, &st)', "lstat(path.slice(0, path.indexOf('\\0')).join(''), st)")
        .replace('is_created_link(&st)', 'is_created_link(st)')
        .replace('free(path);', '');
    const createdLinks = new Set();
    api.is_created_link = st => createdLinks.has(`${st.st_dev}:${st.st_ino}`);
    const remember = name => {
        const st = fs.lstatSync(name);
        createdLinks.add(`${st.dev}:${st.ino}`);
    };
    assert.match(archive, /res = symlink\(file_header->link_target, dst_name\);\s*if \(res == 0\)\s*remember_created_link\(dst_name\);/);
    assert.match(archive, /res = link\(hard_link, dst_name\);\s*if \(res == 0\)\s*remember_created_link\(dst_name\);/);
    const checkPath = new Function('name', 'include_leaf', 'api', `with (api) { ${pathCode} }`);
    const destination = path.join(temp, 'jffs');
    const outside = path.join(temp, 'etc');
    fs.mkdirSync(destination);
    fs.mkdirSync(outside);
    const passwd = path.join(outside, 'passwd');
    fs.writeFileSync(passwd, 'unchanged');
    const link = path.join(destination, 'a');
    checkPath(link, 0, api);
    fs.symlinkSync(outside, link);
    // Pre-existing system symlink (rootfs /etc -> tmp/etc) must stay traversable, e.g. restore_cert.
    checkPath(path.join(link, 'passwd'), 0, api);
    checkPath(link, 1, api);
    remember(link);
    assert.throws(() => checkPath(path.join(link, 'passwd'), 0, api), /unsafe archive/);
    assert.throws(() => checkPath(link, 1, api), /unsafe archive/);
    assert.throws(() => checkPath(`${destination}/./a/passwd`, 0, api), /unsafe archive/);
    assert.throws(() => checkPath(`${destination}/../etc/passwd`, 0, api), /unsafe archive/);
    assert.throws(() => fs.openSync(link, fs.constants.O_WRONLY | fs.constants.O_TRUNC |
        fs.constants.O_NOFOLLOW));
    fs.symlinkSync('missing', path.join(destination, 'dangling'));
    remember(path.join(destination, 'dangling'));
    assert.throws(() => checkPath(path.join(destination, 'dangling/file'), 0, api));
    const hardAlias = path.join(destination, 'hard-alias');
    fs.linkSync(link, hardAlias);
    assert.throws(() => checkPath(path.join(hardAlias, 'passwd'), 0, api), /unsafe archive/);
    fs.mkdirSync(path.join(destination, 'normal'));
    checkPath(path.join(destination, 'normal/file'), 0, api);
    checkPath(path.join(destination, 'new/subdir/file'), 0, api);
    checkPath(`${destination}/./normal/`, 1, api);
    assert.equal(fs.readFileSync(passwd, 'utf8'), 'unchanged');
} finally {
    if (activeSpool) api.httpd_spool_clear(activeSpool);
    fs.rmSync(temp, { recursive: true, force: true });
}

assert.doesNotMatch(web, /"\/tmp\/(?:settings_u\.prf|backup_jffs\.tar|settings)"/);
const upload = body(web, 'do_upload_post');
const restore = body(web, 'do_upload_cgi');
assert.match(upload, /fwrite\(buf, 1, count, fifo\) != count/);
assert.match(upload, /filelen > 0 \|\| ferror\(fifo\) \|\| fflush\(fifo\) != 0/);
assert.match(upload, /httpd_spool_create\(&settings_spool\)/);
assert.match(upload, /if \(ret != 0\)\s*httpd_spool_clear\(&settings_spool\)/);
assert.match(restore, /ret == 0 && httpd_spool_valid\(&settings_spool\) &&\s*sys_upload\(settings_spool.path\) == 0/);
assert(restore.indexOf('sys_upload(') < restore.indexOf('nvram_commit()'));
assert(restore.indexOf('sys_upload(') < restore.indexOf('sys_reboot()'));
const jffsUpload = body(web, 'do_jffsupload_post');
assert.match(jffsUpload, /fwrite\(post_buf, 1, count, fifo\) != count/);
assert.match(jffsUpload, /filelen <= trailer_len \|\| ferror\(fifo\) \|\| fflush\(fifo\) != 0/);
assert.match(jffsUpload, /memcmp\(received, trailer, trailer_len\) != 0/);
assert.match(jffsUpload, /ftruncate\(fileno\(fifo\), filelen - trailer_len\) != 0/);
assert(jffsUpload.indexOf('ftruncate(') < jffsUpload.indexOf('jffs_spool.complete = 1'));
assert.match(body(web, 'do_jffsupload_cgi'), /ret == 0 && httpd_spool_valid\(&jffs_spool\)/);
assert.match(body(web, 'do_jffs_file'), /httpd_spool_valid\(&backup\)/);
assert.match(body(web, 'prf_file'), /backup.complete = save_result == 0/);
assert.match(body(web, 'prf_file'), /httpd_spool_clear\(&backup\)/);
const extract = body(archive, 'data_extract_all');
assert(extract.indexOf('check_extract_path(dst_name,') < extract.indexOf('bb_make_directory('));
assert(extract.indexOf('check_extract_path(hard_link, 1)') < extract.indexOf('link(hard_link, dst_name)'));
assert.match(extract, /if \(hard_link\[0\] == '\/'\)/);
assert(extract.indexOf('flags |= O_NOFOLLOW;') < extract.indexOf('dst_fd = xopen3('));

console.log('httpd restore spools: source-translated lifecycle and real filesystem checks passed');
console.log('BusyBox extraction: source-translated symlink/traversal guards passed; not compiled C or actual tar/HTTP/device execution');
console.log('Stat ownership is modeled for the invoking uid; real root/nobody access and firmware validation remain required');