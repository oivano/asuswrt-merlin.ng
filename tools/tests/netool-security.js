const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/rc/netool.c'), 'utf8');
const header = fs.readFileSync(path.join(root, 'release/src/router/rc/netool.h'), 'utf8');
const webSource = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const usbSource = fs.readFileSync(path.join(root, 'release/src/router/rc/usb.c'), 'utf8');
const servicesSource = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const diskToolsSource = fs.readFileSync(path.join(root, 'release/src/router/libdisk/disk_io_tools.c'), 'utf8');
const listSource = fs.readFileSync(path.join(root, 'release/src/router/rc/linklist.c'), 'utf8');
const defaults = fs.readFileSync(path.join(root, 'release/src/router/shared/defaults.c'), 'utf8');

function body(name) {
    const start = source.indexOf('{', source.indexOf(name + '('));
    assert(start >= 0, name);
    let depth = 1;
    let end = start + 1;
    while (depth && end < source.length) {
        if (source[end] === '{') depth++;
        if (source[end] === '}') depth--;
        end++;
    }
    assert.equal(depth, 0, name);
    return source.slice(start + 1, end - 1);
}

function sourceBody(text, name) {
    const start = text.indexOf('{', text.indexOf(name + '('));
    assert(start >= 0, name);
    let depth = 1;
    let end = start + 1;
    while (depth && end < text.length) {
        if (text[end] === '{') depth++;
        if (text[end] === '}') depth--;
        end++;
    }
    assert.equal(depth, 0, name);
    return text.slice(start + 1, end - 1);
}

const receive = body('rcv_socket');
assert.match(receive, /getsockopt\(newsockfd, SOL_SOCKET, SO_PEERCRED/);
assert.match(receive, /peer_len != sizeof\(peer\) \|\| peer.uid != 0\)\s*return;/);
assert(receive.indexOf('peer.uid != 0') < receive.indexOf('recv('));
assert.match(receive, /SO_RCVTIMEO/);
assert.match(receive, /recv\(newsockfd, &req_t, sizeof\(req_t\), MSG_WAITALL\)/);
assert.match(receive, /n != sizeof\(req_t\) \|\| !valid_request\(&req_t\)\)\s*{/);
assert(receive.indexOf('!valid_request') < receive.indexOf('StampToDate'));
assert.match(source, /old_umask = umask\(077\);\s*bind_result = bind\([^;]+;\s*umask\(old_umask\);/);
assert.match(source, /bind_result == -1 \|\| chmod\(NETOOL_SOCKET_PATH, 0600\) == -1/);
assert.doesNotMatch(source, /\b(system|popen|execl|execlp)\s*\(|\/bin\/sh|sh -c/);
assert.match(source, /execvp\(argv\[0\], argv\)/);
assert.match(source, /waitpid\(child, &status, 0\)/);
assert.match(source, /task_listcreate\(\*\(REQUEST_INFO_T \*\)rInfo\)/);
assert.match(source, /pthread_create\(&thread, &attr, request_worker, request\)/);
assert.match(body('request_worker'), /free\(req\);\s*return NULL;/);
assert.match(body('log_tool'), /if \(always_marker \|\| status == 0\)\s*fputs\("XU6J03M6\\n", output\)/);
assert.match(body('do_ping_normal'), /log_tool\(argv, NETOOL_RESULT_PING_NORMAL_LOG, 1\)/);
for (const worker of ['do_nslookup', 'do_traceroute_normal', 'do_netstat', 'do_netstat_nat']) {
    assert.match(body(worker), /log_tool\(argv, NETOOL_RESULT_\w+, 0\)/);
}
for (const worker of ['do_ping', 'do_traceroute']) {
    assert.match(body(worker), /vpopen\(argv, &child\)/);
    assert.match(body(worker), /vpclose\(fp, child\)/);
    assert.match(body(worker), /netool_result_file_open\(req->target\)/);
}
const resultDirOpen = body('netool_result_dir_open');
assert.match(resultDirOpen, /mkdir\(NETOOL_RESULT_DIR, 0700\)/);
assert.match(resultDirOpen, /open\(NETOOL_RESULT_DIR, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(resultDirOpen, /S_ISDIR\(st\.st_mode\) && st\.st_uid == 0/);
assert.match(resultDirOpen, /fchmod\(fd, 0700\)/);
assert.match(resultDirOpen, /!\(st\.st_mode & 0077\)/);
const resultFileOpen = body('netool_result_file_open');
assert.match(resultFileOpen, /strchr\(name, '\/'\)/);
assert.match(resultFileOpen, /unlinkat\(dirfd, name, 0\)/);
assert.match(resultFileOpen, /openat\(dirfd, name, O_WRONLY \| O_CREAT \| O_EXCL \| O_NOFOLLOW/);
assert.match(resultFileOpen, /S_ISREG\(st\.st_mode\).*st\.st_uid != 0/);
assert.match(resultFileOpen, /st\.st_nlink != 1/);
assert.match(resultFileOpen, /fdopen\(fd, "w"\)/);
assert.doesNotMatch(source, /fopen\(result_path,\s*"w"\)/);
assert.match(source.slice(source.indexOf('int netool_main (')), /netool_result_dir_open\(\)/);
assert.doesNotMatch(source.slice(source.indexOf('int netool_main (')), /mkdir_if_none\(NETOOL_RESULT_DIR\)/);
const resultRead = sourceBody(webSource, 'netool');
assert.match(resultRead, /open\(NETOOL_RESULT_DIR, O_RDONLY \| O_DIRECTORY \| O_NOFOLLOW\)/);
assert.match(resultRead, /openat\(dirfd, req_t\.target, O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK\)/);
assert.match(resultRead, /S_ISREG\(st\.st_mode\)[\s\S]*?st\.st_uid == 0/);
assert.match(resultRead, /st\.st_nlink == 1/);
const nfsStart = sourceBody(usbSource, 'void start_nfsd');
assert.match(nfsStart, /secure_root_config_dir\("\/var\/lib\/nfs"\)/);
assert.match(nfsStart, /secure_root_config_dir\("\/var\/lib\/nfs\/sm"\)/);
assert.match(nfsStart, /open_root_config_file\("\/var\/lib\/nfs", "etab", 0644\)/);
assert.doesNotMatch(nfsStart, /creat\("\/var\/lib\/nfs\//);
assert.match(sourceBody(diskToolsSource, 'mkdir_if_none_mode'), /mode & 0777/);
assert.match(diskToolsSource, /mkdir_if_none\(const char \*path\)\s*\{\s*return mkdir_if_none_mode\(path, 0755\);/);
const fallbackStart = servicesSource.indexOf('#else\nint mkdir_if_none_mode');
const fallbackEnd = servicesSource.indexOf('#endif\t/* RTCONFIG_USB */', fallbackStart);
assert(fallbackStart >= 0 && fallbackEnd > fallbackStart);
const fallback = servicesSource.slice(fallbackStart, fallbackEnd);
assert.match(fallback, /return mkdir_if_none_mode\(path, 0755\);/);
assert.equal((fallback.match(/return mkdir_if_none_mode/g) || []).length, 1);

const fixture = fs.mkdtempSync(path.join(os.tmpdir(), 'netool-security-'));
try {
    const outputDir = path.join(fixture, 'netool');
    const victim = path.join(fixture, 'victim');
    fs.mkdirSync(outputDir, { mode: 0o700 });
    fs.writeFileSync(victim, 'sentinel');
    fs.symlinkSync(victim, path.join(outputDir, '192.0.2.1'));
    fs.unlinkSync(path.join(outputDir, '192.0.2.1'));
    const resultFd = fs.openSync(path.join(outputDir, '192.0.2.1'),
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
        0o600);
    fs.writeSync(resultFd, 'probe result');
    fs.closeSync(resultFd);
    assert.equal(fs.readFileSync(victim, 'utf8'), 'sentinel');
    assert.equal(fs.lstatSync(path.join(outputDir, '192.0.2.1')).isFile(), true);
    const readLink = path.join(outputDir, 'read-link');
    fs.symlinkSync(victim, readLink);
    assert.throws(() => fs.openSync(readLink,
        fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK),
        error => error.code === 'ELOOP');
    assert.equal(fs.readFileSync(victim, 'utf8'), 'sentinel');
} finally {
    fs.rmSync(fixture, { recursive: true, force: true });
}
const traceroute = body('do_traceroute');
assert.match(traceroute, /listnode_delete\(task_list, req_task\)/);
assert.doesNotMatch(traceroute, /free\(req_task\)/);
const deleteStart = listSource.indexOf('void listnode_delete(');
assert(deleteStart >= 0);
const deleteEnd = listSource.indexOf('\n}', deleteStart);
assert(deleteEnd > deleteStart);
assert.match(listSource.slice(deleteStart, deleteEnd), /free\(node->data\)/);
assert.doesNotMatch(`${source}\n${header}`, /NETOOL_QUEUE|\/tmp\/NETOOL_QUEUE/);
assert.match(receive, /nvram_get_int\("netool_queue"\) == 1/);
const mainStart = source.indexOf('int netool_main (');
assert(mainStart >= 0);
assert.match(source.slice(mainStart), /nvram_get_int\("netool_queue"\) == 1/);
assert.match(defaults, /\{\s*"netool_queue",\s*"0"/);

const sizes = Object.fromEntries([...header.matchAll(/char\s+(\w+)\[(\d+)\]/g)]
    .map(match => [match[1], Number(match[2])]));
const enumText = header.match(/typedef enum\s*{([\s\S]*?)}REQ_TYPE;/)[1];
const modes = Object.fromEntries(enumText.split(',').map((entry, index) =>
    [entry.trim().split(/\s*=/)[0], index]));
const tokenBody = body('valid_token');
assert.match(tokenBody, /!memchr\(value, '\\0', size\)/);
assert.match(tokenBody, /\*value == '-'/);
assert.match(tokenBody, /!strcmp\(value, "\."\) \|\| !strcmp\(value, "\.\."\)/);
for (const [lower, upper] of [['a', 'z'], ['A', 'Z'], ['0', '9']]) {
    assert(tokenBody.includes(`*cursor >= '${lower}' && *cursor <= '${upper}'`));
}
assert(tokenBody.includes('strchr(extra, *cursor)'));

function valid_token(value, size, extra) {
    if (Buffer.byteLength(value) >= size || value.startsWith('-') || value === '.' || value === '..') return false;
    return [...value].every(character => /^[a-zA-Z0-9]$/.test(character) || extra.includes(character));
}

const validation = body('valid_request')
    .replace(/req->/g, 'req.')
    .replace(/sizeof\(req\.(\w+)\)/g, (_, field) => String(sizes[field]))
    .replace(/\*req\.(\w+)/g, 'req.$1.length');
const valid = vm.runInNewContext(`(function(req) { ${validation} })`, {
    ...modes, valid_token, strcmp: (left, right) => left === right ? 0 : 1
});
function request(type = modes.REQ_NSLOOKUP_MODE) {
    return {
        type, ping_cnt: 5, hops: 30, response: 3, exec_cnt: 1, netst: 0,
        ver: 'v4', sort: '', proto: '', srchost: '', dsthost: '', interface: '', target: 'example.com'
    };
}

for (let type = 1; type < modes.REQ_MODE_TOTAL; type++) assert.equal(valid(request(type)), 1);
for (const target of ['example.com', 'router-name.lan', '192.0.2.1', '2001:db8::1', 'fe80::1%br0']) {
    assert.equal(valid({ ...request(), target }), 1, target);
}
for (const field of Object.keys(sizes)) {
    assert.equal(valid({ ...request(), [field]: 'a'.repeat(sizes[field]) }), 0, `unterminated ${field}`);
    for (const payload of ['x;id', 'x$(id)', 'x`id`', 'x\nid', 'x id', 'x\tid', 'x|id', 'x&id',
        'x>file', 'x<file', 'x"id', "x'id", 'x\\id', '../file', '/tmp/file', '-option', '.', '..']) {
        assert.equal(valid({ ...request(), [field]: payload }), 0, `${field}: ${payload}`);
    }
}
for (const sort of ['', 'src', 'dst', 'src-port', 'dst-port', 'state']) {
    assert.equal(valid({ ...request(modes.REQ_NETSTAT_NAT_MODE), sort }), 1);
}
for (const proto of ['', 'tcp', 'udp', 'icmp', 'igmp']) {
    assert.equal(valid({ ...request(modes.REQ_NETSTAT_NAT_MODE), proto }), 1);
}
for (const [field, value] of [['sort', 'unknown'], ['proto', 'unknown'], ['ver', 'v5'],
['type', -1], ['type', 0], ['type', modes.REQ_MODE_TOTAL], ['target', '']]) {
    assert.equal(valid({ ...request(), [field]: value }), 0);
}
for (const type of [modes.REQ_PING_MODE, modes.REQ_PING_NORMAL_MODE]) {
    assert.equal(valid({ ...request(type), ping_cnt: 0 }), 0);
    assert.equal(valid({ ...request(type), response: 0 }), 0);
}
for (const type of [modes.REQ_TRACEROUTE_MODE, modes.REQ_TRACEROUTE_NORMAL_MODE]) {
    for (const hops of [-1, 0, 65]) assert.equal(valid({ ...request(type), hops }), 0);
}
assert.equal(valid({ ...request(modes.REQ_PING_MODE), exec_cnt: 0 }), 0);
assert.equal(valid({ ...request(modes.REQ_NETSTAT_MODE), netst: 256 }), 0);
assert.equal(valid({ ...request(modes.REQ_NETSTAT_NAT_MODE), netst: -1 }), 0);

const probe = body('probe_argv')
    .replace(/#ifdef RTCONFIG_TRACEROUTE([\s\S]*?)#else[\s\S]*?#endif/g, '$1')
    .replace(/req->/g, 'req.')
    .replace(/\bint ([^;]+);/g, 'let $1;')
    .replace(/snprintf\(numbers\[(\d)\], 16, "%d", ([^;]+)\);/g, 'numbers[$1] = String($2);')
    .replace(/\*req.interface/g, 'req.interface.length')
    .replace(/\bNULL\b/g, 'null');
const probeArgs = vm.runInNewContext(`(function(req, argv, numbers, normal) { ${probe} })`, {
    ...modes, TRACEROUTE: '/usr/sbin/traceroute', strcmp: (left, right) => left === right ? 0 : 1
});
for (const ver of ['v4', 'v6']) {
    for (const iface of ['', 'br0', 'vlan3880']) {
        for (const normal of [0, 1]) {
            for (const ping of [false, true]) {
                const type = ping
                    ? (normal ? modes.REQ_PING_NORMAL_MODE : modes.REQ_PING_MODE)
                    : (normal ? modes.REQ_TRACEROUTE_NORMAL_MODE : modes.REQ_TRACEROUTE_MODE);
                const req = { ...request(type), ver, interface: iface };
                const argv = [];
                probeArgs(req, argv, [], normal);
                const expected = ping ? [ver === 'v6' ? 'ping6' : 'ping']
                    : ['/usr/sbin/traceroute', ver === 'v6' ? '-6' : '-4'];
                if (iface) expected.push(ping ? '-I' : '-i', iface);
                expected.push(ping ? '-c' : '-m', ping ? '5' : '30', ping && normal ? '-W' : '-w', '3');
                if (!normal) expected.push(ping ? '-q' : '-n');
                expected.push('example.com', null);
                assert.deepEqual(argv, expected);
            }
        }
    }
}
console.log('PASS: netool socket, shell-free worker, symlink-safe result I/O, NFS setup and validation contracts');
console.log('Not a C compile or on-router socket/diagnostic test.');