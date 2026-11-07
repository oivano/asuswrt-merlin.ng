const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/libdisk/disk_share.c'), 'utf8');
const smbWriter = fs.readFileSync(path.join(root, 'release/src/router/libdisk/write_smb_conf.c'), 'utf8');
const openerStart = source.indexOf('static FILE *open_metadata_file(');
const openerEnd = source.indexOf('\n#ifdef RTCONFIG_PERMISSION_MANAGEMENT', openerStart);
const opener = source.slice(openerStart, openerEnd);
const folderStart = source.indexOf('extern int get_all_folder(');
const folderEnd = source.indexOf('\nextern int get_var_file_name(', folderStart);
const folders = source.slice(folderStart, folderEnd);

assert.notEqual(openerStart, -1);
assert.match(opener, /open\(directory, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(opener, /openat\(directory_fd, base, flags\)/);
assert.match(opener, /O_CREAT \| O_EXCL/);
assert.match(opener, /O_NOFOLLOW \| O_NONBLOCK/);
assert.ok(opener.indexOf('fstat(fd, &st)') < opener.indexOf('ftruncate(fd, 0)'));
assert.match(opener, /!S_ISREG\(st\.st_mode\)/);
assert.equal([...source.matchAll(/fopen\((?:var_file|test_file|list_file),\s*"[wa]/g)].length, 0,
    'all metadata file writes must use open_metadata_file');
assert.match(source, /open_metadata_file\(test_file, "w"\)/);
assert.match(source, /open_metadata_file\(list_file, "w"\)/);
assert.match(source, /\*p < 0x20 \|\| \*p == 0x7f/);
assert.match(source, /int smb_share_name_is_safe\(const char \*name\)/);
assert.match(source, /strcmp\(name, "\."\).*strcmp\(name, "\.\."\).*strchr\(name, '\/'\)/s);
assert.match(source, /strchr\("\/\[\];#=%", \*p\)/);
const pathGuardStart = source.indexOf('int smb_share_path_is_safe(');
const pathGuardEnd = source.indexOf('\nstatic FILE *open_metadata_file', pathGuardStart);
const pathGuard = source.slice(pathGuardStart, pathGuardEnd);
assert.notEqual(pathGuardStart, -1);
assert.match(pathGuard, /lstat\(share_path, &st\).*S_ISDIR\(st\.st_mode\)/s);
assert.match(pathGuard, /realpath\(mount_path, canonical_mount\)/);
assert.match(pathGuard, /realpath\(share_path, canonical_share\)/);
assert.match(pathGuard, /strncmp\(canonical_share, canonical_mount, mount_len\)/);
assert.match(folders, /smb_share_name_is_safe\(dp->d_name\)/);
assert.equal((smbWriter.match(/smb_share_path_is_safe\(follow_partition->mount_point, folder_list\[n\]\)/g) || []).length, 3);
assert.equal((smbWriter.match(/fprintf\(fp, "path = %s\/%s\\n", follow_partition->mount_point, folder_list\[n\]\);/g) || []).length, 3);

function safeOpen(filename, mode) {
    let flags = fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK;
    const writing = mode !== 'r';
    if (mode === 'r') flags |= fs.constants.O_RDONLY;
    else if (mode === 'w') flags |= fs.constants.O_WRONLY;
    else flags |= fs.constants.O_RDWR | fs.constants.O_APPEND;

    let descriptor;
    try {
        descriptor = fs.openSync(filename, flags);
    } catch (error) {
        if (!writing || error.code !== 'ENOENT') throw error;
        try {
            descriptor = fs.openSync(filename, flags | fs.constants.O_CREAT | fs.constants.O_EXCL, 0o600);
        } catch (createError) {
            if (createError.code !== 'EEXIST') throw createError;
            descriptor = fs.openSync(filename, flags);
        }
    }
    if (!fs.fstatSync(descriptor).isFile()) {
        fs.closeSync(descriptor);
        throw new Error('not a regular file');
    }
    if (mode === 'w') fs.ftruncateSync(descriptor, 0);
    return descriptor;
}

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'libdisk-metadata-'));
try {
    const media = path.join(temporary, 'media');
    const tmpTarget = path.join(temporary, 'tmp', 'target');
    const cronTarget = path.join(temporary, 'var', 'spool', 'cron', 'crontabs', 'admin');
    const jffsTarget = path.join(temporary, 'jffs', 'target');
    fs.mkdirSync(media);
    for (const target of [tmpTarget, cronTarget, jffsTarget]) {
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, `sentinel:${target}`);
    }

    const links = [
        ['.___var.txt', cronTarget],
        ['.__admin_var.txt', tmpTarget],
        ['.__folder_list.txt', jffsTarget],
        ['.share.txt.12', tmpTarget],
        ['.___var.txt.dangling', path.join(temporary, 'absent')],
    ];
    for (const [name, target] of links) {
        const linkPath = path.join(media, name);
        fs.symlinkSync(target, linkPath);
        assert.throws(() => safeOpen(linkPath, 'w'));
    }
    assert.equal(fs.existsSync(path.join(temporary, 'absent')), false);
    for (const target of [tmpTarget, cronTarget, jffsTarget])
        assert.equal(fs.readFileSync(target, 'utf8'), `sentinel:${target}`);

    const fifo = path.join(media, '.__fifo_var.txt');
    childProcess.execFileSync('mkfifo', [fifo]);
    assert.throws(() => safeOpen(fifo, 'a+'), /not a regular file/);

    const regular = path.join(media, '.___var.txt');
    fs.unlinkSync(regular);
    const descriptor = safeOpen(regular, 'w');
    fs.writeSync(descriptor, '*=331\n');
    fs.closeSync(descriptor);
    assert.equal(fs.readFileSync(regular, 'utf8'), '*=331\n');

    const safeShareName = name => name.length > 0 && name !== '.' && name !== '..' && !name.includes('/') &&
        !/[\x00-\x1f\x7f%\[\];#=]/.test(name);
    const safeSharePath = (mount, name) => {
        if (!safeShareName(name)) return false;
        const candidate = path.join(mount, name);
        let stat;
        let mountRoot;
        let resolved;
        try {
            stat = fs.lstatSync(candidate);
            if (!stat.isDirectory()) return false;
            mountRoot = fs.realpathSync(mount);
            resolved = fs.realpathSync(candidate);
        } catch {
            return false;
        }
        const prefix = mountRoot.endsWith(path.sep) ? mountRoot : `${mountRoot}${path.sep}`;
        return resolved !== mountRoot && resolved.startsWith(prefix);
    };
    const payload = 'x]\navailable = yes\nguest ok = yes\nroot preexec = blocked\n[y]';
    fs.mkdirSync(path.join(media, 'normal folder'));
    fs.mkdirSync(path.join(media, '%m'));
    fs.mkdirSync(path.join(media, '%L'));
    fs.mkdirSync(path.join(media, payload));
    fs.symlinkSync(path.dirname(tmpTarget), path.join(media, 'x'));
    const names = fs.readdirSync(media).filter(name => name[0] !== '.' && safeSharePath(media, name));
    assert.deepEqual(names, ['normal folder']);
    assert.equal(safeSharePath(media, 'x'), false, 'symlink to an outside directory is rejected');
    assert.equal(safeSharePath(media, '..'), false, 'parent traversal is rejected');
    assert.equal(safeSharePath(media, 'normal folder/child'), false, 'multi-component names are rejected');
    for (const name of ['%m', '%L', 'semi;colon', 'hash#mark', 'equals=name', '[section]', 'line\rbreak'])
        assert.equal(safeShareName(name), false);
    const generated = names.map(name => `[${name}]\npath = /media/${name}\n`).join('');
    assert.equal(generated.includes('[y]'), false);
    assert.equal(generated.includes('available = yes'), false);
    assert.equal(generated.includes('guest ok = yes'), false);
    assert.equal(generated.includes('root preexec ='), false);
    console.log('PASS: libdisk metadata symlink/FIFO guards and unsafe SMB share-name filtering (source contracts plus host filesystem model; not compiled C/router tests)');
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}