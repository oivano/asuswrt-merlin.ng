const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const files = read('release/src/router/shared/files.c');
const services = read('release/src/router/rc/services.c');
const httpdWriterSource = read('release/src/router/httpd/aspbw.c');
const init = read('release/src/router/rc/init.c');
const discover = read('release/src/router/shared/discover.c');
const discoverHeader = read('release/src/router/shared/discover.h');
const watchdog = read('release/src/router/rc/watchdog.c');
const discoverLogStart = discover.indexOf('void discover_log(');
const strDupStart = discover.indexOf('char *\nstrDup(');
const fWrite = files.slice(files.indexOf('int f_write('), files.indexOf('\nint f_read_string('));
const httpdWriter = httpdWriterSource.slice(
    httpdWriterSource.indexOf('int f_write('),
    httpdWriterSource.indexOf('\nconst char *resmsg_get(')
);
const checkedAppend = services.slice(
    services.indexOf('static void append_jffs_config_checked('),
    services.indexOf('\nvoid create_passwd(')
);
const createPasswd = services.slice(services.indexOf('void create_passwd('), services.indexOf('\nvoid get_dhcp_pool('));
const generalWriter = fWrite.slice(fWrite.indexOf('f = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW'));

assert.match(fWrite, /cmode == 0\) cmode = root_writer \? 0600 : 0666/);
assert.match(fWrite, /cmode &= ~0022/);
assert.match(generalWriter, /O_NOFOLLOW \| O_NONBLOCK/);
assert.doesNotMatch(generalWriter, /O_TRUNC/);
assert(generalWriter.indexOf('fstat(f, &st)') < generalWriter.indexOf('ftruncate(f, 0)'));
assert.match(generalWriter, /st\.st_uid != 0/);
assert.match(generalWriter, /st\.st_nlink != 1/);
assert.match(generalWriter, /st\.st_mode & 0022/);
assert.match(generalWriter, /pseudo_file/);
assert.match(httpdWriter, /O_NOFOLLOW \| O_NONBLOCK/);
assert.match(httpdWriter, /st\.st_uid != 0/);
assert.match(httpdWriter, /st\.st_nlink != 1/);
assert.match(httpdWriter, /st\.st_mode & 0022/);
assert(httpdWriter.indexOf('fstat(f, &st)') < httpdWriter.indexOf('ftruncate(f, 0)'));
assert.match(init, /f_write\("\/tmp\/detect_wrong\.log", NULL, 0, 0, 0600\)/);
assert.match(init, /f_write\("\/tmp\/usb\.log", NULL, 0, 0, 0600\)/);
assert.match(discoverHeader, /#define eprintf\(fmt, args\.\.\.\) discover_log/);
assert.match(discover, /f_write\(DETECT_LOG, buffer, len, FW_APPEND, 0600\)/);
assert.match(discover, /f_write\(DETECT_LOG, NULL, 0, 0, 0600\)/);
assert.doesNotMatch(discover, /unlink\(DETECT_LOG\)/);
assert(discoverLogStart >= 0 && discoverLogStart < strDupStart);
const discoverLog = discover.slice(discoverLogStart, strDupStart);
assert.match(discoverLog, /va_start\(args, fmt\)/);
assert.match(discoverLog, /f_write\(DETECT_LOG, buffer, len, FW_APPEND, 0600\)/);
const strDup = discover.slice(strDupStart, discover.indexOf('\nint\nopenInterface', strDupStart));
assert.match(strDup, /len = strlen\(str\)\s*\+\s*1/);
assert.match(strDup, /return copy;/);
assert.doesNotMatch(strDup, /va_start|DETECT_LOG/);
assert.match(watchdog, /#define MODEMLOG_TEMP "\/tmp\/ppp\/usb\.log-1"/);

assert.match(checkedAppend, /nvram_match\("jffs2_scripts", "0"\)/);
assert.match(checkedAppend, /O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK/);
assert.match(checkedAppend, /fstat\(fd, &st\)/);
assert.match(checkedAppend, /!S_ISREG\(st\.st_mode\)/);
assert.match(checkedAppend, /st\.st_uid != 0/);
assert.match(checkedAppend, /st\.st_nlink != 1/);
assert.match(checkedAppend, /st\.st_mode & 0022/);
for (const name of ['passwd', 'gshadow', 'group'])
    assert.match(createPasswd, new RegExp(`append_jffs_config_checked\\(fp, "${name}"\\)`));
assert.doesNotMatch(createPasswd, /fappend\(fp, "\/jffs\/configs\/(?:passwd|gshadow|group)\.add"\)/);

const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'upgrade-passwd-symlink-'));
try {
    const target = path.join(sandbox, 'passwd.add');
    const link = path.join(sandbox, 'detect_wrong.log');
    fs.writeFileSync(target, 'preserve-target\n');
    fs.symlinkSync(target, link);
    assert.throws(() => fs.openSync(link,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK,
        0o600));
    assert.strictEqual(fs.readFileSync(target, 'utf8'), 'preserve-target\n');
} finally {
    fs.rmSync(sandbox, { recursive: true, force: true });
}

console.log('upgrade log and passwd fragment symlink contracts passed');