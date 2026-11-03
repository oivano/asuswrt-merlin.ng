const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const splitter = fs.readFileSync(path.join(root,
    'release/src/router/httpd/sysdeps/web-dsl-upg.c'), 'utf8');
const service = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const rcDsl = fs.readFileSync(path.join(root, 'release/src/router/rc/sysdeps/dsl-upg.c'), 'utf8');
const header = fs.readFileSync(path.join(root, 'release/src/router/shared/sysdeps/api-broadcom.c'), 'utf8');

assert.match(web, /httpd_upgrade_spool_create\(&upgrade_spool\)/);
assert.match(web, /open\(spool->path, O_RDWR \| O_CREAT \| O_EXCL \| O_NOFOLLOW, 0600\)/);
assert.match(web, /mkdir\(HTTPD_UPGRADE_DIRECTORY, 0700\)/);
assert.match(web, /httpd_upgrade_spool_publish\(&upgrade_spool\)/);
assert.match(web, /image\.st_dev, \(unsigned long long\)image\.st_ino,[\s\S]*?image\.st_size/);
assert.match(web, /fstat\(fileno\(fifo\), &upload_stat\)[\s\S]*?upload_stat\.st_size != upload_len/);
// DSL_TCLINUX check_imageheader() widens filelen to trx+0x790000, so the spool
// legitimately holds the multipart trailer; size must equal bytes actually written.
assert.match(header, /\*filelen\+=0x790000/);
assert.doesNotMatch(web, /upload_len = len - strlen\(boundary\)/);
assert.match(web, /upload_len = 0;\s*wait_rc_misc\(\);/);
assert.match(web, /if \(fwrite\(buf, 1, count, fifo\) != \(size_t\)count\)\s*goto err;\s*upload_len \+= count;/);
assert.match(web, /if \(fputc\(ch, fifo\) == EOF\)\s*goto err;\s*upload_len\+\+;/);
assert.match(web, /separate_tc_fw_from_trx\(upload_fifo, upload_len\)/);
assert.match(web, /if \(fifo\) \{\s*if \(fifo == upgrade_spool\.file\)\s*upgrade_spool\.file = NULL;\s*fclose\(fifo\);/,
    'err path must not leave a closed FILE in the spool (double fclose crashes httpd)');
assert.match(web, /if \(stop_upgrade_once\) \{\s*websApply\(stream, "UpdateError_reboot\.asp"\);\s*sys_reboot\(\);/,
    'post-stop rejection must reboot, services cannot be restarted in place');
assert.doesNotMatch(web, /start_upgrade_recover/);
assert.doesNotMatch(service, /upgrade_recover|upgrade_stop_commit/);
assert.match(splitter, /separate_tc_fw_from_trx\(char \*trxpath, long uploaded_len\)/);
assert.match(splitter, /source_len != uploaded_len/);
assert.match(splitter, /TrxSize > filelen/);
assert.match(splitter, /if \(TrxSize && TrxSize < filelen && truncate\(trxpath, TrxSize\) != 0\)/);

// Model the DSL spool write loop: trx + tc fw + multipart trailer all fit in filelen.
{
    const boundary = '----WebKitFormBoundaryabc';
    const trxLen = 0x1000, tcLen = 0x2000;
    const body = trxLen + tcLen + boundary.length + 8;
    let len = body, filelen = trxLen + 0x790000, written = 0;
    while (len > 0 && filelen > 0) {
        let count = Math.min(len, 4096);
        len -= count;
        if (count > filelen) count = filelen;
        filelen -= count;
        written += count;
    }
    assert.equal(written, body, 'spooled size includes trailer');
    assert.notEqual(written, body - boundary.length - 8, 'old boundary arithmetic always mismatched');
}
assert.match(service, /httpd_upgrade_spool_valid\(\)/);
assert.match(service, /opened\.st_ino != expected_inode/);
assert.match(service, /opened\.st_size != expected_size/);
assert.match(service, /while \(identity_len < \(size_t\)identity_file\.st_size\)/);
assert.match(service, /count < 0 && errno == EINTR/);
assert.match(service, /identity\[identity_len\] = '\\0'/);
const abortSpool = service.match(/static void\s+upgrade_abort_invalid_spool\(int stop_commit\)\s*\{([\s\S]*?)\n\}/);
assert(abortSpool, 'invalid private spool must have a recovery path');
assert.match(abortSpool[1], /nvram_unset\(ASUS_STOP_COMMIT\)/);
assert.match(abortSpool[1], /nvram_set\("sys_reboot_reason", "rc_upg_spool"\)/);
assert.match(abortSpool[1], /kill\(1, SIGTERM\)/);
assert.equal((service.match(/upgrade_abort_invalid_spool\(stop_commit\);/g) || []).length, 4,
    'every post-stop spool rejection must trigger recovery');
assert.match(rcDsl, /HTTPD_UPGRADE_DIRECTORY "\/tcfw\.bin"/);
assert.match(rcDsl, /HTTPD_UPGRADE_DIRECTORY "\/ras\.bin"/);

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'httpd-upgrade-spool-'));
try {
    for (const kind of ['regular', 'symlink']) {
        const legacyImage = path.join(temp, `linux-${kind}.trx`);
        const outside = path.join(temp, `outside-${kind}`);
        fs.writeFileSync(outside, 'attacker image');
        if (kind === 'regular') fs.writeFileSync(legacyImage, 'attacker image');
        else fs.symlinkSync(outside, legacyImage);

        const privateDirectory = path.join(temp, `private-${kind}`);
        fs.mkdirSync(privateDirectory, 0o700);
        const uploadImage = path.join(privateDirectory, 'linux.trx');
        const descriptor = fs.openSync(uploadImage,
            fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL |
            fs.constants.O_NOFOLLOW, 0o600);
        fs.writeSync(descriptor, 'administrator image');
        const imageStat = fs.fstatSync(descriptor);
        const pathStat = fs.lstatSync(uploadImage);
        assert.equal(pathStat.ino, imageStat.ino);
        assert.equal(pathStat.nlink, 1);
        assert.equal(pathStat.mode & 0o777, 0o600);
        assert.equal(fs.readFileSync(legacyImage, 'utf8'), 'attacker image');
        assert.equal(fs.readFileSync(outside, 'utf8'), 'attacker image');
        fs.closeSync(descriptor);
        fs.rmSync(privateDirectory, { recursive: true, force: true });
    }

    for (const kind of ['regular', 'symlink']) {
        const privateDirectory = path.join(temp, `preseed-${kind}`);
        fs.mkdirSync(privateDirectory, 0o700);
        const uploadImage = path.join(privateDirectory, 'linux.trx');
        if (kind === 'regular') fs.writeFileSync(uploadImage, 'attacker image');
        else fs.symlinkSync(path.join(temp, 'outside-regular'), uploadImage);
        assert.throws(() => fs.openSync(uploadImage,
            fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL |
            fs.constants.O_NOFOLLOW, 0o600));
        fs.rmSync(privateDirectory, { recursive: true, force: true });
    }

    const outsideDirectory = path.join(temp, 'outside-directory');
    const plantedDirectory = path.join(temp, 'planted-directory');
    fs.mkdirSync(outsideDirectory, 0o700);
    fs.symlinkSync(outsideDirectory, plantedDirectory);
    assert.throws(() => fs.mkdirSync(plantedDirectory, 0o700));
    assert.deepEqual(fs.readdirSync(outsideDirectory), []);
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}

console.log('HTTPD firmware upload spool contracts and filesystem cases passed');