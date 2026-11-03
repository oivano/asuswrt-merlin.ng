const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const misc = fs.readFileSync(path.join(root, 'release/src/router/shared/misc.c'), 'utf8');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const gencert = fs.readFileSync(path.join(root, 'release/src/router/httpd/gencert.sh'), 'utf8');
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
assert.match(gencert, /chmod 600 \$\{HTTPD_ROOTCA_KEY\} \$\{HTTPD_ROOTCA_GEN_KEY\} \$\{HTTPD_GEN_KEY\} \$\{HTTPD_KEY\}/);
assert.match(gencert, /rm -f server\.pem[\s\S]*?cat \$\{HTTPD_KEY\} \$\{HTTPD_CERT\} > server\.pem[\s\S]*?chmod 600 server\.pem/);
assert.match(gencert, /chown 0:0 \/jffs\/cert\.tgz && chmod 600 \/jffs\/cert\.tgz/);
assert.match(gencert, /tar czvf \/jffs\/cert\.tgz/);

console.log('HTTPS private-key file permission contracts passed');