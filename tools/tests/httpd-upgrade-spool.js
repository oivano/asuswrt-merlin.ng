const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const splitter = fs.readFileSync(path.join(root,
    'release/src/router/httpd/sysdeps/web-dsl-upg.c'), 'utf8');
const service = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const init = fs.readFileSync(path.join(root, 'release/src/router/rc/init.c'), 'utf8');
const rcDsl = fs.readFileSync(path.join(root, 'release/src/router/rc/sysdeps/dsl-upg.c'), 'utf8');
const header = fs.readFileSync(path.join(root, 'release/src/router/shared/sysdeps/api-broadcom.c'), 'utf8');
const romMakefile = fs.readFileSync(path.join(root, 'release/src/router/rom/Makefile'), 'utf8');

assert.match(web, /httpd_upgrade_spool_create\(&upgrade_spool\)/);
assert.match(web, /open\(spool->path, O_RDWR \| O_CREAT \| O_EXCL \| O_NOFOLLOW, 0600\)/);
assert.match(init, /mkdir\(HTTPD_UPGRADE_DIRECTORY, 0700\)/);
assert.match(init, /fchmod\(fd, 0700\).*?st\.st_mode & 07777\) == 0700/s);
assert.match(web, /open\(HTTPD_UPGRADE_DIRECTORY, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.doesNotMatch(web, /mkdir\(HTTPD_UPGRADE_DIRECTORY/);
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
assert.match(service, /lstat\(HTTPD_UPGRADE_IMAGE, &st\)/);
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
const ateStart = service.slice(service.indexOf('else if(strcmp(script, "upgrade_ate") == 0)'),
    service.indexOf('else if(strcmp(script, "upgrade") == 0)'));
assert.match(ateStart, /if \(action & RC_SERVICE_START\) \{\s*#if defined\(RTCONFIG_DSL_REMOTE\)[\s\S]*?if \(!httpd_upgrade_spool_present\(\) \|\| !httpd_upgrade_spool_valid\(\)\)[\s\S]*?goto skip;/);
assert(ateStart.indexOf('httpd_upgrade_spool_valid()') < ateStart.indexOf('if(action & RC_SERVICE_STOP)'),
    'ATE start must reject absent or invalid spool before stopping services');
assert(ateStart.indexOf('Only support under ATE test mode') < ateStart.indexOf('strlcpy(upgrade_file, HTTPD_UPGRADE_IMAGE') &&
    ateStart.indexOf('strlcpy(upgrade_file, HTTPD_UPGRADE_IMAGE') < ateStart.indexOf('if(action & RC_SERVICE_STOP)'),
    'ATE mode must be established before selecting the private image or stopping services');
assert.match(ateStart, /unlink\(HTTPD_UPGRADE_IDENTITY\);/,
    'ATE flash must clean the spool identity after use');
assert.doesNotMatch(service, /rmdir\(HTTPD_UPGRADE_DIRECTORY\)/,
    'the boot-reserved private parent must remain in place');
const upgradeStart = service.slice(service.indexOf('else if(strcmp(script, "upgrade") == 0)'),
    service.indexOf('else if(strcmp(script, "mfgmode") == 0)'));
const preflight = upgradeStart.indexOf('if ((action & RC_SERVICE_START) &&');
assert(preflight >= 0 && preflight < upgradeStart.indexOf('restore_config_before_firmware_downgrade()') &&
    preflight < upgradeStart.indexOf('if(action&RC_SERVICE_STOP)'),
    'normal upgrade must reject an invalid spool before changing settings or stopping services');
const preflightCode = upgradeStart.slice(preflight, upgradeStart.indexOf('if(action&RC_SERVICE_STOP)'));
assert.match(preflightCode,
    /httpd_upgrade_spool_present\(\)[\s\S]*?httpd_upgrade_spool_valid\(\)[\s\S]*?goto skip;/);
assert.doesNotMatch(preflightCode, /upgrade_abort_invalid_spool|kill\(1,/,
    'invalid spool preflight must not trigger the reboot recovery path');
const upgradeGuard = upgradeStart.indexOf('if (!secure_upgrade)');
assert(upgradeGuard >= 0 && upgradeGuard < upgradeStart.indexOf('do_upgrade_adsldrv();') &&
    upgradeGuard < upgradeStart.indexOf('if (!f_exists(upgrade_file)'),
    'normal upgrade must refuse missing/invalid spool before legacy image selection');
const secureExpression = upgradeStart.match(/int secure_upgrade = ([^;]+);/);
assert(secureExpression, 'normal upgrade must derive its trust decision from spool validation');
const sourceGuard = secureExpression[1]
    .replace(/httpd_upgrade_spool_present\(\)/g, 'present')
    .replace(/httpd_upgrade_spool_valid\(\)/g, 'valid');
const mayFlash = new Function('present', 'valid', `return ${sourceGuard};`);
for (const [present, valid] of [[false, true], [true, false]]) {
    let mtdCalls = 0;
    if (mayFlash(present, valid)) mtdCalls++;
    assert.equal(mtdCalls, 0, 'a planted legacy /tmp image must not reach an mtd writer');
}
assert.match(romMakefile, /ifeq \(\$\(RTAC68U\),y\)\s*ifneq \(\$\(BUILD_NAME\),DSL-AC68U\)\s*cp -f webs_scripts\/ssl_webs_upgrade_enc\.sh[\s\S]*?cp -f webs_scripts\/ssl_webs_update_enc\.sh[\s\S]*?endif\s*endif/,
    'encoded firmware scripts must not be installed in the DSL-AC68U image');
assert.match(rcDsl, /HTTPD_UPGRADE_DIRECTORY "\/tcfw\.bin"/);
assert.match(rcDsl, /HTTPD_UPGRADE_DIRECTORY "\/ras\.bin"/);

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'httpd-upgrade-spool-'));
try {
    for (const kind of ['directory', 'regular', 'dangling-symlink']) {
        const planted = path.join(temp, `planted-${kind}`);
        if (kind === 'directory') {
            fs.mkdirSync(planted, 0o755);
        } else if (kind === 'regular') {
            fs.writeFileSync(planted, 'attacker entry');
        } else {
            fs.symlinkSync(path.join(temp, 'missing-target'), planted);
        }
        const stat = fs.lstatSync(planted);
        const trusted = stat.isDirectory() && stat.uid === 0 && (stat.mode & 0o777) === 0o700;
        assert.equal(trusted, false, `${kind} cannot satisfy the root-private directory contract`);
        assert.throws(() => fs.mkdirSync(planted, 0o700), { code: 'EEXIST' });
        fs.rmSync(planted, { recursive: true, force: true });
    }

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