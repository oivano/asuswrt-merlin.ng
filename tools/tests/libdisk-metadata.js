const assert = require('node:assert/strict');
const childProcess = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/libdisk/disk_share.c'), 'utf8');
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
assert.match(folders, /metadata_name_is_safe\(dp->d_name\)/);
assert.match(source, /\*p < 0x20 \|\| \*p == 0x7f/);

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

    const safeName = name => name.length > 0 && !/[\x00-\x1f\x7f]/.test(name);
    const names = ['normal folder', 'semi; dollar$ parens()'];
    const newlineName = 'first\n* * * * * command #';
    for (const name of names) assert.equal(safeName(name), true);
    assert.equal(safeName(newlineName), false);
    const records = names.filter(safeName).map(name => `sh_name=${name}\n`);
    assert.equal(records.length, 2);
    assert.ok(records.every(record => record.split('\n').length === 2));
    console.log('PASS: libdisk metadata symlink/FIFO guards and newline-name serialization checks (source contracts plus host filesystem model; not compiled C/router tests)');
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}