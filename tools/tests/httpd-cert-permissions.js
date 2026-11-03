const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const misc = fs.readFileSync(path.join(root, 'release/src/router/shared/misc.c'), 'utf8');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const gencert = fs.readFileSync(path.join(root, 'release/src/router/httpd/gencert.sh'), 'utf8');
const shared = fs.readFileSync(path.join(root, 'release/src/router/shared/shared.h'), 'utf8');
const usb = fs.readFileSync(path.join(root, 'release/src/router/rc/usb.c'), 'utf8');
const functionBody = (source, signature, ending) => {
    const start = source.indexOf(signature);
    assert.notEqual(start, -1, signature);
    const end = source.indexOf(ending, start);
    assert.notEqual(end, -1, ending);
    return source.slice(start, end);
};

const secureKey = functionBody(misc, 'static int secure_cert_private_file(', '\n}\n');
assert.match(secureKey, /O_RDONLY\s*\|\s*O_NOFOLLOW\s*\|\s*O_NONBLOCK/);
assert.match(secureKey, /S_ISREG\(st\.st_mode\)/);
assert.match(secureKey, /fchown\(fd, 0, 0\)/);
assert.match(secureKey, /fchmod\(fd, 0600\)/);

const restore = functionBody(misc, 'int restore_cert(void)', '\n}\n\n/* Used to backup cert.');
assert.match(restore, /secure_cert_private_file\(\*p\)/);
assert.match(restore, /HTTPD_KEY, HTTPD_GEN_KEY, LIGHTTPD_CERTKEY/);
assert.match(restore, /O_CREAT\s*\|\s*O_EXCL\s*\|\s*O_NOFOLLOW, 0600/);
assert.match(restore, /system\("cat " HTTPD_KEY " " HTTPD_CERT " > " LIGHTTPD_CERTKEY\)/);

const save = functionBody(misc, 'void save_cert(void)', '\n}\n\nvoid erase_cert');
assert.match(save, /secure_cert_private_file\(\*p\)/);
assert.match(save, /HTTPD_KEY, HTTPD_GEN_KEY, LIGHTTPD_CERTKEY/);
assert.match(save, /open\(HTTPS_CA_JFFS, O_WRONLY \| O_CREAT \| O_NOFOLLOW \| O_NONBLOCK, 0600\)/);
assert.match(save, /fchown\(fd, 0, 0\)/);
assert.match(save, /fchmod\(fd, 0600\)/);
assert(save.indexOf('fchmod(fd, 0600)') < save.indexOf('_eval(argv'));
assert.match(save, /st\.st_nlink != 1/);

const exportKey = functionBody(web, 'do_download_cert_key_cgi(char *url, FILE *stream)', '\n}\n\nstatic void\ndo_download_cert_cgi');
assert.match(exportKey, /httpd_spool_create\(&cert_spool\)/);
assert(exportKey.indexOf('argv[2] = cert_spool.path') < exportKey.indexOf('for (i = 0'));
assert.match(exportKey, /fclose\(cert_spool\.file\)/);
assert.match(exportKey, /ret = _eval\(argv, NULL, 0, NULL\)/);
assert.match(exportKey, /if \(!ret\)\s*do_file\(cert_spool\.path, stream\)/);
assert.match(exportKey, /httpd_spool_clear\(&cert_spool\)/);
assert.doesNotMatch(exportKey, /\/tmp\/cert_key\.tar/);

assert.match(gencert, /^umask 077$/m);
assert.match(gencert, /exec 9>>\/var\/run\/gencert\.lock/);
assert.match(gencert, /flock -n 9/);
assert.doesNotMatch(gencert, /\/var\/lock\/gencert\.lock|cat \/var\/lock\/gencert\.lock|sleep 1/);
assert.match(shared, /#define GENCERT_TIMEOUT\s+120/);
for (const name of [
    'GENCERT_SH',
    'GENCERT_SH_AND_RELOAD',
    'GENCERT_SH_AND_BACKUP',
    'GENCERT_SH_AND_BACKUP_RELOAD',
    'GENCERT_SH_AND_BACKUP_RELOAD_AFTER_LOGOUT',
]) {
    const macro = shared.slice(shared.indexOf(`#define ${name}(`), shared.indexOf('\n', shared.indexOf(`#define ${name}(`)));
    assert.match(macro, /_eval\(argv, NULL, GENCERT_TIMEOUT, NULL\)/, name);
}
const webdavPem = functionBody(usb, 'void write_webdav_server_pem()', '\n}\n');
assert.match(webdavPem, /_eval\(gencert_argv, NULL, GENCERT_TIMEOUT, NULL\)/);
assert.match(gencert, /chmod 600 \$\{HTTPD_ROOTCA_KEY\} \$\{HTTPD_ROOTCA_GEN_KEY\} \$\{HTTPD_GEN_KEY\} \$\{HTTPD_KEY\}/);
assert.match(gencert, /rm -f server\.pem[\s\S]*?cat \$\{HTTPD_KEY\} \$\{HTTPD_CERT\} > server\.pem[\s\S]*?chmod 600 server\.pem/);
assert.match(gencert, /chown 0:0 \/jffs\/cert\.tgz && chmod 600 \/jffs\/cert\.tgz/);
assert.match(gencert, /tar czvf \/jffs\/cert\.tgz/);

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'gencert-lock-'));
const privateDir = path.join(temp, 'private');
const sharedDir = path.join(temp, 'shared');
fs.mkdirSync(privateDir, { mode: 0o700 });
fs.mkdirSync(sharedDir, { mode: 0o777 });
fs.chmodSync(sharedDir, 0o1777);
const protectedTarget = path.join(temp, 'root-file');
fs.writeFileSync(protectedTarget, 'preserve\n');
const plantedLock = path.join(sharedDir, 'gencert.lock');
const productionLock = path.join(privateDir, 'gencert.lock');
const lockStart = gencert.indexOf('exec 9>>/var/run/gencert.lock');
const lockEnd = gencert.indexOf('\ncp -L openssl.cnf', lockStart);
assert(lockStart >= 0 && lockEnd > lockStart, 'lock block boundaries');
const lockBlock = gencert.slice(lockStart, lockEnd)
    .replace('/var/run/gencert.lock', productionLock);
const runLock = () => spawnSync('/bin/sh', ['-c', `${lockBlock}\nprintf 'lock-acquired\\n'`], {
    encoding: 'utf8',
    timeout: 1000,
});

try {
    for (const kind of ['symlink', 'fifo', 'pid-file']) {
        fs.rmSync(plantedLock, { force: true });
        if (kind === 'symlink')
            fs.symlinkSync(protectedTarget, plantedLock);
        else if (kind === 'fifo') {
            const result = spawnSync('mkfifo', [plantedLock]);
            assert.equal(result.status, 0, 'mkfifo is required for this regression');
        } else {
            fs.writeFileSync(plantedLock, '1\n');
        }

        const result = runLock();
        assert.equal(result.error, undefined, `${kind} lock must not block`);
        assert.equal(result.status, 0, `${kind} legacy lock entry is ignored`);
        assert.match(result.stdout, /lock-acquired/);
        assert.equal(fs.readFileSync(protectedTarget, 'utf8'), 'preserve\n');
    }

    const contended = spawnSync('/bin/sh', ['-c', `exec 8>>'${productionLock}'; flock -n 8; sleep 1 & holder=$!; ${lockBlock}\nprintf 'lock-acquired\\n'; wait $holder`], {
        encoding: 'utf8',
        timeout: 2000,
    });
    assert.equal(contended.error, undefined, 'contended lock must not block');
    assert.equal(contended.status, 0);
    assert.doesNotMatch(contended.stdout, /lock-acquired/);
} finally {
    fs.rmSync(temp, { recursive: true, force: true });
}

console.log('HTTPS certificate permissions and lock contracts passed');