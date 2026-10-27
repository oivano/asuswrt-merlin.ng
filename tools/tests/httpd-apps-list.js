const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const apps = fs.readFileSync(path.join(root, 'release/src/router/httpd/apps.c'), 'utf8');
const stanza = apps.match(/static int read_apps_stanza\([^]*?\n\}/)[0];
assert.equal((apps.match(/if\(!read_apps_stanza\(fp, line, sizeof\(line\), buf, sizeof\(buf\)\)\)/g) || []).length, 2);
assert.doesNotMatch(apps, /pkg_tail/);
assert.match(stanza, /if\(length >= buf_size - used\)\s+oversized = 1;/);
assert.match(stanza, /if\(!oversized\)\{\s+memcpy\(buf \+ used, line, length \+ 1\);\s+used \+= length;/);

// Execute the source-derived append and drain control flow with checked memory writes.
const body = stanza.slice(stanza.indexOf('buf[0]'), stanza.lastIndexOf('}'))
    .replace("buf[0] = '\\0';", 'buf.fill(0);')
    .replace('strlen(line)', 'Buffer.byteLength(line)')
    .replace('memcpy(buf + used, line, length + 1);', 'copy(used, line, length + 1);')
    .replace('fgets(line, line_size, fp) != NULL', '(line = next()) !== null')
    .replace('strcmp(line, "\\n") && strcmp(line, "\\r\\n")', 'line !== "\\n" && line !== "\\r\\n"');
const read = new Function('line', 'next', 'buf', 'buf_size', 'copy',
    `let used = 0, length, oversized = 0; ${body}`);

function parse(input) {
    let offset = 0;
    function next() {
        if (offset === input.length) return null;
        let end = input.indexOf('\n', offset);
        end = end < 0 ? input.length : end + 1;
        end = Math.min(end, offset + 127);
        const line = input.slice(offset, end);
        offset = end;
        return line;
    }
    const records = [];
    let line;
    while ((line = next()) !== null) {
        if (!line.includes('Package: ')) continue;
        const memory = Buffer.alloc(4096 + 32, 0xa5);
        const buffer = memory.subarray(0, 4096);
        const result = read(line, next, buffer, buffer.length, (used, text, count) => {
            assert(used + count <= buffer.length, 'copy stays inside stanza buffer');
            memory.write(text, used, 'latin1');
            memory[used + count - 1] = 0;
        });
        assert(memory.subarray(4096).every(byte => byte === 0xa5), 'outside sentinel unchanged');
        if (result) records.push(buffer.subarray(0, buffer.indexOf(0)).toString('latin1'));
    }
    return records;
}

const valid = 'Package: good\nVersion: 1\nStatus: install ok installed\n';
for (const length of [4095, 4096, 10000, 20000]) {
    const record = 'Package: x\n' + 'a'.repeat(length - 11);
    assert.equal(parse(record).length, length < 4096 ? 1 : 0);
    assert.deepEqual(parse(record + '\n\n' + valid), length < 4095 ? [record + '\n', valid] : [valid]);
}
assert.deepEqual(parse(valid + '\r\n' + valid), [valid, valid]);
assert.deepEqual(parse('Package: bad\n' + 'Description: data\n'.repeat(1000) + '\n' + valid), [valid]);
assert.deepEqual(parse('Package: x\n' + 'a'.repeat(127 * 100) + '\n\n' + valid), [valid]);
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
assert.match(web, /\{ "update_applist\.asp",[^\n]*do_ej, do_auth \}/);
const hook = web.match(/int ej_apps_info\([^]*?\n\}/)[0];
assert.match(hook, /#if defined\(RTCONFIG_APP_PREINSTALLED\) \|\| defined\(RTCONFIG_APP_NETINSTALLED\) \|\| defined\(RTCONFIG_APP_FILEFLEX\)/);
assert.match(hook, /#else\s+websWrite\(wp, "\[\]"\);\s+#endif/);
assert.equal(hook.split('#else')[1].includes('get_apps_list'), false);

const opener = apps.match(/static FILE \*open_apps_file\([^]*?\n\}/)[0];
assert.match(opener, /open\("\/opt", O_RDONLY \| O_DIRECTORY \| O_NONBLOCK\)/);
assert.match(opener, /openat\(dir_fd, component, O_RDONLY \| O_NOFOLLOW \| O_NONBLOCK \|/);
assert.match(opener, /fstat\(dir_fd, &st\)[^]*?st\.st_uid != 0[^]*?S_IWGRP \| S_IWOTH/);
assert.match(opener, /fstat\(fd, &st\) == 0 && S_ISREG\(st.st_mode\) &&\s+st.st_uid == 0 && st.st_nlink == 1 &&\s+!\(st.st_mode & \(S_IWGRP \| S_IWOTH\)\)/);
assert.match(opener, /!strcmp\(component, "\.\."\)/);
assert.equal((apps.match(/fp = open_apps_file\(/g) || []).length, 3, 'lists, status and control use trusted opens');
assert.doesNotMatch(apps, /fopen\(|read_whole_file\(/);
assert.match(apps, /info_size = fread\(buf, 1, sizeof\(buf\) - 1, fp\)/);

const constants = fs.constants;
const directory = { mode: 0o40755, uid: 0, nlink: 2 };
const regular = { mode: 0o100644, uid: 0, nlink: 1 };
const trusted = {
    '/opt': directory,
    '/opt/lib': directory,
    '/opt/lib/ipkg': directory,
    '/opt/lib/ipkg/lists': directory,
    '/opt/lib/ipkg/lists/optware.asus': regular,
    '/opt/lib/ipkg/status': regular,
    '/opt/lib/ipkg/info': directory,
    '/opt/lib/ipkg/info/good.control': regular,
};
const openBody = opener.slice(opener.indexOf('\tif(strncmp'), opener.lastIndexOf('}'))
    .replace('strdup(path + 5)', 'strdup(path.slice(5))')
    .replace('(component = strsep(&cursor, "/")) != NULL', '(component = takeComponent()) !== null')
    .replace(/fstat\((dir_fd|fd), &st\)/g, 'fstat($1, st)')
    .replace(/\bNULL\b/g, 'null')
    .replace(/\*component/g, 'component.length');
const trustedOpen = new Function('path', 'io', `
    const {open, openat, fstat, fdopen, close, free, strdup, strncmp, strcmp,
        O_RDONLY, O_DIRECTORY, O_NONBLOCK, O_NOFOLLOW, S_IWGRP, S_IWOTH, S_ISDIR, S_ISREG} = io;
    let relative, cursor, component, dir_fd, fd = -1, fp = null;
    const st = {};
    function takeComponent() {
        if (cursor === null) return null;
        const split = cursor.indexOf('/');
        if (split < 0) { const result = cursor; cursor = null; return result; }
        const result = cursor.slice(0, split); cursor = cursor.slice(split + 1); return result;
    }
    ${openBody}
`);

function checkOpen(filename, overrides = {}, failStream = false, failStat = false) {
    const tree = { ...trusted, ...overrides };
    const live = new Map();
    let serial = 0;
    const type = mode => mode & 0o170000;
    function open(name, flags) {
        const node = tree[name];
        if (!node || (node.symlink && (flags & constants.O_NOFOLLOW)) ||
            ((flags & constants.O_DIRECTORY) && type(node.mode) !== 0o40000)) return -1;
        assert(flags & constants.O_NONBLOCK, 'untrusted FIFO cannot block open');
        live.set(++serial, name);
        return serial;
    }
    const io = {
        ...constants, S_IWGRP: 0o20, S_IWOTH: 0o2,
        S_ISDIR: mode => type(mode) === 0o40000,
        S_ISREG: mode => type(mode) === 0o100000,
        strdup: text => text, free: () => {},
        strncmp: (left, right, count) => left.slice(0, count) === right ? 0 : 1,
        strcmp: (left, right) => left === right ? 0 : 1,
        open,
        openat: (parent, name, flags) => {
            assert(live.has(parent), 'parent descriptor is pinned');
            return open(live.get(parent) + '/' + name, flags);
        },
        fstat: (fd, stat) => {
            assert(live.has(fd));
            const node = tree[live.get(fd)];
            Object.assign(stat, { st_mode: node.mode, st_uid: node.uid, st_nlink: node.nlink });
            return failStat ? -1 : 0;
        },
        fdopen: fd => failStream ? null : { fd },
        close: fd => { assert(live.delete(fd), 'descriptor closed once'); },
    };
    const stream = trustedOpen(filename, io);
    if (stream) io.close(stream.fd);
    assert.equal(live.size, 0, 'all directory and rejected-file descriptors closed');
    return stream !== null;
}

for (const filename of ['/opt/lib/ipkg/lists/optware.asus', '/opt/lib/ipkg/status', '/opt/lib/ipkg/info/good.control']) {
    assert(checkOpen(filename));
    const ancestors = filename.split('/').slice(1);
    for (let count = 1; count <= ancestors.length; count++) {
        const name = '/' + ancestors.slice(0, count).join('/');
        const original = trusted[name];
        assert.equal(checkOpen(filename, { [name]: { ...original, uid: 65534 } }), false, `nobody-owned ${name}`);
        for (const write of [0o20, 0o2])
            assert.equal(checkOpen(filename, { [name]: { ...original, mode: original.mode | write } }), false);
        if (name !== '/opt')
            assert.equal(checkOpen(filename, { [name]: { ...original, symlink: true } }), false);
    }
    for (const mode of [0o10600, 0o40755])
        assert.equal(checkOpen(filename, { [filename]: { ...regular, mode } }), false, 'FIFO or directory is not package data');
    assert.equal(checkOpen(filename, { [filename]: { ...regular, nlink: 2 } }), false);
    assert.equal(checkOpen(filename, { [filename]: null }), false);
    assert.equal(checkOpen(filename, {}, true), false, 'fdopen failure closes file');
    assert.equal(checkOpen(filename, {}, false, true), false, 'fstat failure closes directory');
}
for (const filename of ['/tmp/status', '/opt/lib/../status', '/opt/lib/./status', '/opt//status', '/opt/lib/ipkg/'])
    assert.equal(checkOpen(filename), false);
console.log('httpd apps list: bounds, recovery, trusted-open and auth contracts passed (source-derived JS, not native C)');