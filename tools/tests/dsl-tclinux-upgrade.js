const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const api = read('release/src/router/shared/sysdeps/api-tclinux.c');
const web = read('release/src/router/httpd/web.c');
const services = read('release/src/router/rc/services.c');

function functionBody(source, name) {
    const start = source.search(new RegExp(`\\b${name}\\s*\\([^;]*?\\)\\s*\\{`));
    assert.notEqual(start, -1, `missing ${name}`);
    const open = source.indexOf('{', start);
    let depth = 1;
    for (let index = open + 1; index < source.length; index++) {
        if (source[index] === '{') depth++;
        if (source[index] === '}' && --depth === 0) return source.slice(open + 1, index);
    }
    assert.fail(`unterminated ${name}`);
}

function crc32NoComplement(bytes) {
    let crc = 0xffffffff;
    for (const byte of bytes) {
        crc = (crc ^ byte) >>> 0;
        for (let bit = 0; bit < 8; bit++)
            crc = (crc & 1) ? ((crc >>> 1) ^ 0xedb88320) >>> 0 : crc >>> 1;
    }
    return crc >>> 0;
}

function modemImage(payload) {
    const image = Buffer.alloc(0x100 + payload.length);
    image.write('2RDH', 0, 'ascii');
    image.writeUInt32BE(payload.length, 8);
    image.writeUInt32BE(crc32NoComplement(payload), 12);
    payload.copy(image, 0x100);
    return image;
}

function validImage(image) {
    if (image.length <= 0x100 || image.toString('ascii', 0, 4) !== '2RDH') return false;
    const payloadLength = image.readUInt32BE(8);
    return payloadLength > 0 && payloadLength === image.length - 0x100 &&
        image.readUInt32BE(12) === crc32NoComplement(image.subarray(0x100));
}

const stageDirOpen = functionBody(api, 'tc_stage_directory_open');
const stageFileOpen = functionBody(api, 'tc_stage_file_open');
const firmwareCheck = functionBody(api, 'tc_firmware_fd_valid');
const separate = functionBody(api, 'stage_tc_firmware_from_trx');
const checkStage = functionBody(api, 'check_tc_firmware_stage');
const checkOnly = functionBody(api, 'check_tc_firmware_image');
const published = functionBody(api, 'tc_upgrade_spool_published');
const backup = functionBody(api, 'tc_backup_firmware');
const updater = functionBody(api, 'do_upgrade_adsldrv');
const webUpload = functionBody(web.replace(/#ifdef RTAC68A\s+static void\s+do_upgrade_post[^}]+}\s+#else/, ''), 'do_upgrade_post');
const webClear = functionBody(web, 'httpd_upgrade_spool_clear');
const firmwareCheckMain = functionBody(services, 'firmware_check_main');
const activeApi = api.replace(/#ifdef RTCONFIG_RALINK[\s\S]*?#define TC_FW_HTTPD_DIRECTORY/,
    '#define TC_FW_HTTPD_DIRECTORY');

assert(stageDirOpen.includes('O_DIRECTORY | O_NOFOLLOW'));
assert(stageDirOpen.includes('st_uid != 0'));
assert(stageDirOpen.includes('(st.st_mode & 0777) != 0700'));
assert(stageFileOpen.includes('O_CREAT | O_EXCL'));
assert(stageFileOpen.includes('O_NOFOLLOW'));
assert(stageFileOpen.includes('st_nlink != 1'));
assert(stageFileOpen.includes('(st.st_mode & 0777) != 0600'));
assert(firmwareCheck.includes('memcmp(header, "2RDH", 4)'));
assert(firmwareCheck.includes('identity->st_size <= TC_HDR_LEN'));
assert(firmwareCheck.includes('payload_len == 0'));
assert(firmwareCheck.includes('payload_len != (unsigned long)(identity->st_size - TC_HDR_LEN)'));
assert(firmwareCheck.includes('calculated_crc != expected_crc'));
assert(separate.includes('source.st_size < sizeof(trx_header)'));
assert(separate.includes('trx_size < 0x1c || trx_size > file_size'));
assert(separate.includes('remaining <= TC_HDR_LEN'));
assert(separate.includes('O_NOFOLLOW | O_NONBLOCK'));
assert(checkStage.includes('tc_firmware_fd_valid'));
assert(checkStage.includes('unlinkat(dirfd, TC_FW_PART_NAME, 0)'));
assert(checkOnly.includes('mkdtemp(stage_dir)'));
assert(checkOnly.includes('check_tc_firmware_stage(stage_dir, 0)'));
assert(checkOnly.includes('unlinkat(dirfd, TC_FW_PART_NAME, 0)'));
assert(checkOnly.includes('unlinkat(dirfd, TC_FW_IMAGE_NAME, 0)'));
assert.doesNotMatch(checkOnly, /stage_dir\s+"\/"/);
assert(checkOnly.includes('rmdir(stage_dir)'));
assert(published.includes('"linux.trx"'));
assert(published.includes('"identity"'));
assert(published.includes('image.st_ino'));
assert(backup.includes('O_CREAT | O_EXCL | O_NOFOLLOW'));
assert(backup.includes('renameat(jffsfd, temporary, jffsfd, "tclinux.bin")'));
assert.doesNotMatch(backup, /\beval\s*\(/);
assert(updater.indexOf('tc_upgrade_spool_published(dirfd)') < updater.indexOf('tc_stage_file_open(dirfd, TC_FW_IMAGE_NAME, 0)'));
assert(updater.indexOf('tc_firmware_fd_valid(fwfd') < updater.indexOf('"-I", "INPUT"'));
assert(updater.indexOf('tc_firmware_fd_valid(fwfd') < updater.indexOf('tc_backup_firmware(dirfd)'));
assert(updater.includes('TC_FW_HTTPD_DIRECTORY "/" TC_FW_IMAGE_NAME'));
assert.doesNotMatch(updater, /\/tmp\/tclinux\.bin/);
const sameFirmware = updater.match(/if \((old_crc && new_crc && new_crc == old_crc)\) \{([\s\S]*?)\n\t\}/);
assert(sameFirmware, 'matching modem payloads must skip only the modem flash');
assert(sameFirmware[2].includes('goto done;'));
assert.doesNotMatch(sameFirmware[2], /\beval\(|upgrade_err|return\s+-1/);
const skipModem = new Function('old_crc', 'new_crc', `return Boolean(${sameFirmware[1]});`);
assert(skipModem(0x12345678, 0x12345678));
assert(!skipModem(0x12345678, 0x87654321));
assert(!skipModem(0, 0x12345678));
assert(updater.indexOf(sameFirmware[0]) < updater.indexOf('"tftp"'));
assert.match(api, /void do_upgrade_adsldrv\(void\)/);
assert.match(services, /do_upgrade_adsldrv\(\);\s*#endif\s*#endif\s*limit_page_cache_ratio\(90\);/,
    'base upgrade continues after the void modem updater returns');
assert(web.includes('stage_tc_firmware_from_trx(upload_fifo, upload_len'));
assert(web.includes('check_tc_firmware_stage(HTTPD_UPGRADE_DIRECTORY, 1)'));
assert(web.includes('ret_val_sep < 0'));
assert(webClear.includes('/tmp/httpd-upgrade/tclinux.bin'));
assert(firmwareCheckMain.includes('check_tc_firmware_image(argv[1])'));
assert.doesNotMatch(firmwareCheckMain, /separate_tc_fw_from_trx\(argv\[1\]\)/);
assert.doesNotMatch(activeApi, /\/tmp\/(?:tcfw|tclinux)\.bin/);

const payload = Buffer.from('validated modem payload');
const valid = modemImage(payload);
assert(validImage(valid));
assert(!validImage(valid.subarray(0, 0xff)));
assert(!validImage(Buffer.from('XXXX' + valid.subarray(4).toString('binary'), 'binary')));
const shortLength = Buffer.from(valid);
shortLength.writeUInt32BE(0, 8);
assert(!validImage(shortLength));
const overlong = Buffer.from(valid);
overlong.writeUInt32BE(payload.length + 1, 8);
assert(!validImage(overlong));
const truncated = Buffer.from(valid.subarray(0, valid.length - 1));
assert(!validImage(truncated));
const badCrc = Buffer.from(valid);
badCrc[badCrc.length - 1] ^= 0x80;
assert(!validImage(badCrc));
assert(!validImage(Buffer.concat([valid, Buffer.from([0])])));

const trimStart = webUpload.indexOf('size_t boundary_len, trailer_len;');
const trimEnd = webUpload.indexOf('upload_len = image_len;', trimStart);
assert(trimStart >= 0 && trimEnd > trimStart);
const trim = webUpload.slice(trimStart, trimEnd);
assert(trim.includes('boundary_len > sizeof(buf) - 8'));
assert(trim.includes('trailer_len = boundary_len + 8'));
assert(trim.includes('fread(buf, 1, trailer_len, fifo) != trailer_len'));
assert(trim.includes('memcmp(buf, "\\r\\n--", 4) != 0'));
assert(trim.includes('memcmp(buf + 4, boundary, boundary_len) != 0'));
assert(trim.includes('memcmp(buf + 4 + boundary_len, "--\\r\\n", 4) != 0'));
assert(trim.includes('ftruncate(fileno(fifo), image_len) != 0'));
assert(trimEnd < webUpload.indexOf('stage_tc_firmware_from_trx'));

function trimMultipart(upload, boundary) {
    const capacity = 4096;
    if (!boundary || boundary.length > capacity - 8) return null;
    const trailerLength = boundary.length + 8;
    if (upload.length <= trailerLength) return null;
    const imageLength = upload.length - trailerLength;
    const trailer = upload.subarray(imageLength);
    if (!trailer.subarray(0, 4).equals(Buffer.from('\r\n--')) ||
        !trailer.subarray(4, 4 + boundary.length).equals(Buffer.from(boundary)) ||
        !trailer.subarray(4 + boundary.length).equals(Buffer.from('--\r\n')))
        return null;
    return upload.subarray(0, imageLength);
}

const boundary = '----WebKitFormBoundaryFirmware';
const trailer = Buffer.from(`\r\n--${boundary}--\r\n`);
const routerImage = Buffer.alloc(0x1000);
routerImage.write('HDR0');
routerImage.writeUInt32LE(routerImage.length, 4);
for (const modem of [Buffer.alloc(0), valid]) {
    const image = Buffer.concat([routerImage, modem]);
    const upload = Buffer.concat([image, trailer]);
    const trimmed = trimMultipart(upload, boundary);
    assert(trimmed && trimmed.equals(image), 'only multipart framing is removed');
    const remainder = trimmed.subarray(trimmed.readUInt32LE(4));
    assert(modem.length ? validImage(remainder) : remainder.length === 0);
    assert(!validImage(upload.subarray(routerImage.length)),
        'untrimmed upload reproduces the staged-image rejection');
    assert.equal(trimMultipart(upload, boundary + 'wrong'), null);
    assert.equal(trimMultipart(upload.subarray(0, upload.length - 1), boundary), null);
    const corruptTrailer = Buffer.from(upload);
    corruptTrailer[corruptTrailer.length - 4] ^= 1;
    assert.equal(trimMultipart(corruptTrailer, boundary), null);
}
assert.equal(trimMultipart(trailer, boundary), null);
assert.equal(trimMultipart(valid, ''), null);
assert.equal(trimMultipart(valid, 'x'.repeat(4096)), null);
const trimmedBadCrc = trimMultipart(Buffer.concat([routerImage, badCrc, trailer]), boundary);
assert(!validImage(trimmedBadCrc.subarray(routerImage.length)), 'CRC rejection remains intact');

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'dsl-tclinux-test-'));
try {
    const privateDir = path.join(temp, 'stage');
    fs.mkdirSync(privateDir, { mode: 0o700 });
    fs.chmodSync(privateDir, 0o700);
    const outside = path.join(temp, 'outside');
    fs.writeFileSync(outside, 'untouched');
    fs.symlinkSync(outside, path.join(privateDir, 'tclinux.bin'));
    assert.throws(() => fs.openSync(path.join(privateDir, 'tclinux.bin'),
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL |
        fs.constants.O_NOFOLLOW, 0o600));
    assert.equal(fs.readFileSync(outside, 'utf8'), 'untouched');
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}

console.log('PASS: private modem staging, fail-closed image validation, upload identity gate, and no stale /tmp transfer');