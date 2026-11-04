const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const util = require('node:util');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const usbSource = fs.readFileSync(path.join(root, 'release/src/router/rc/usb.c'), 'utf8');
const helper = source.match(/static void aidisk_write_folder_string\([^]*?\n\}/)[0];
const handler = source.match(/int ej_get_AiDisk_status\([^]*?\n\}/)[0];
assert.match(handler, /aidisk_write_folder_string\(wp, folder_list\[i\]\);/);
assert.doesNotMatch(handler, /websWrite\([^;]*folder_list|folder_name|string_to_htmlencode/);

// Execute the encoder's C control flow with byte-oriented input and mocked websWrite.
const translated = helper.slice(helper.indexOf('{') + 1, helper.lastIndexOf('}'))
    .replace(/const unsigned char \*cursor = \(const unsigned char \*\)name;/, 'let cursor = 0;')
    .replace(/\(unsigned int\)\*cursor/g, 'name[cursor]')
    .replace(/cursor\[(\d+)\]/g, 'name[cursor + $1]')
    .replace(/\*cursor/g, 'name[cursor]')
    .replace(/'(?:\\.|[^'\\])'/g, literal => String(vm.runInNewContext(literal).charCodeAt(0)));
const encode = input => {
    const bytes = Buffer.concat([Buffer.isBuffer(input) ? input : Buffer.from(input), Buffer.from([0])]);
    const chunks = [];
    const websWrite = (wp, format, ...args) => {
        const output = format === '%c' ? Buffer.from([args[0]])
            : Buffer.from(format === '\\u%04x' ? '\\u' + args[0].toString(16).padStart(4, '0')
                : util.format(format.replace('%u', '%d'), ...args));
        chunks.push(output);
        return output.length;
    };
    vm.runInNewContext(translated, { name: bytes, wp: null, websWrite });
    return Buffer.concat(chunks).toString('utf8');
};

const payload = 'x"]}}alert(1);function q(){{return["';
const names = ['', 'photos', payload, 'a\\', "'\"\\<>&", '\\u2028', '\\x22',
    '\r\n\t', '\u2028\u2029', 'caf\u00e9-\u65e5\u672c-\ud83d\udcc1',
    'a'.repeat(255), '"'.repeat(255), '\\'.repeat(255)];
for (let byte = 1; byte < 128; byte++) names.push('a' + String.fromCharCode(byte) + 'b');

for (const name of names) {
    const literal = encode(name);
    assert.equal(vm.runInNewContext(literal), name);
    assert.doesNotMatch(literal.slice(1, -1), /["'<>&\x00-\x1f\x7f\u2028\u2029]/);
}
for (const byte of ['\\', '"', "'", '<', '>', '&', '\n', '\x7f'])
    assert.match(encode(byte), /^"\\u[0-9a-f]{4}"$/);
assert.equal(encode('\u2028\u2029'), '"\\u2028\\u2029"');
for (const bytes of [[0xe2], [0xe2, 0x80], [0xe2, 0x80, 0xa8], [0xff, 0x22]])
    assert.doesNotThrow(() => new vm.Script(encode(Buffer.from(bytes))));

// Use the handler's actual framing for a pool containing all regression names.
const writes = [...handler.matchAll(/websWrite\(wp, ("(?:\\.|[^"\\])*")/g)]
    .map(match => JSON.parse(match[1]));
const start = writes.find(text => text === 'function get_sharedfolder_in_pool(poolName){\n');
const branch = writes.find(text => text.startsWith('if(poolName == "%s")'));
const array = writes.find(text => text.includes('return [""'));
assert(start && branch && array);
const makeScript = literals => start + branch.replace('%s', 'sda1') + array + ', ' +
    literals.join(', ') + '];\n    }\n}\n';
let executions = 0;
const context = { alert: () => executions++ };
vm.createContext(context);
vm.runInContext(makeScript(names.map(encode)), context);
assert.equal(executions, 0);
assert.deepEqual(Array.from(context.get_sharedfolder_in_pool('sda1')), ['', ...names]);
assert.equal(context.get_sharedfolder_in_pool('missing'), undefined);
assert.doesNotMatch(makeScript(names.map(encode)), /<\/script/i);
vm.runInContext(makeScript(['"' + payload + '"']), context);
assert.equal(executions, 1, 'negative control must execute the original raw-name injection');

for (const file of ['device-map/disk.asp', 'Advanced_AiDisk_samba.asp', 'Advanced_AiDisk_ftp.asp',
    'Advanced_AiDisk_NFS.asp', 'aidisk/popCreateFolder.asp']) {
    const page = fs.readFileSync(path.join(root, 'release/src/router/www', file), 'utf8');
    assert.match(page, /<%\s*get_AiDisk_status\(\);\s*%>/);
}

const folderTree = source.slice(source.indexOf('int ej_get_folder_tree('), source.indexOf('int ej_get_share_tree('));
const shareTree = source.slice(source.indexOf('int ej_get_share_tree('), source.indexOf('int ej_set_share_mode('));
for (const hook of [folderTree, shareTree]) {
    assert.match(hook, /snprintf\(tree_item, sizeof\(tree_item\), "%s#%u#%u", follow_disk->tag, disk_count, partition_count\);/);
    assert.match(hook, /aidisk_write_folder_string\(wp, tree_item\);/);
    assert.doesNotMatch(hook, /websWrite\(wp, .*follow_disk->tag/);
}

const readPage = file => fs.readFileSync(path.join(root, 'release/src/router/www', file), 'utf8');
const diskFunctions = readPage('disk_functions.js');
const diskPage = readPage('device-map/disk.asp');
const appPage = readPage('APP_Installation.asp');
const help = readPage('help.js');
const state = readPage('state.js');
const otherSettings = readPage('Tools_OtherSettings.asp');
const nfsPage = readPage('Advanced_AiDisk_NFS.asp');
assert.match(diskFunctions, /showhtmlspace\(htmlEnDeCode\.htmlEncode\(short_ItemText\)\)/);
assert.match(diskFunctions, /var encoded_ItemText = htmlEnDeCode\.htmlEncode\(ItemText\)/);
assert.equal((diskFunctions.match(/title="'\+encoded_ItemText/g) || []).length, 3);
for (const treePage of [otherSettings, nfsPage]) {
    assert.match(treePage, /showhtmlspace\(htmlEnDeCode\.htmlEncode\(short_ItemText\)\)/);
    assert.match(treePage, /var encoded_ItemText = htmlEnDeCode\.htmlEncode\(ItemText\)/);
    assert.equal((treePage.match(/title="'\+encoded_ItemText/g) || []).length, 3);
}
assert.match(diskPage, /disk_model_name"\)\.textContent = device\.deviceName/);
assert.match(appPage, /htmlEnDeCode\.htmlEncode\(usbDevicesList\[i\]\.deviceName\)/);
assert.equal((appPage.match(/htmlEnDeCode\.htmlEncode\(usbDevicesList\[i\]\.partition\[j\]\.partName\)/g) || []).length, 2);
assert.equal((help.match(/htmlEnDeCode\.htmlEncode\(usbDevicesList\[i\]\.deviceName\)/g) || []).length, 3);

const htmlCodecSource = state.match(/var htmlEnDeCode = \(function \(\) \{[\s\S]*?\}\)\(\);/);
assert(htmlCodecSource);
const htmlCodec = vm.runInNewContext(`${htmlCodecSource[0]}; htmlEnDeCode`);
for (const name of names) {
    const encoded = htmlCodec.htmlEncode(name);
    assert(!/[<>"']/.test(encoded));
    assert.equal(htmlCodec.htmlDecode(encoded), name);
}

const diskShareSource = fs.readFileSync(path.join(root, 'release/src/router/libdisk/disk_share.c'), 'utf8');
const diskInitialSource = fs.readFileSync(path.join(root, 'release/src/router/libdisk/disk_initial.c'), 'utf8');
const httpdSource = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.c'), 'utf8');
const functionBody = (text, signature) => {
    const start = text.indexOf(signature);
    assert(start >= 0, `missing function ${signature}`);
    const open = text.indexOf('{', start);
    let depth = 1;
    for (let cursor = open + 1; cursor < text.length; cursor++) {
        if (text[cursor] === '{') depth++;
        if (text[cursor] === '}' && --depth === 0) return text.slice(open + 1, cursor);
    }
    assert.fail(`unterminated function ${signature}`);
};

const componentValidator = functionBody(diskShareSource, 'static int folder_component_is_safe(');
assert.match(componentValidator, /folder == NULL/);
assert.match(componentValidator, /!strcmp\(folder, "\."\)/);
assert.match(componentValidator, /!strcmp\(folder, "\.\."\)/);
assert.match(componentValidator, /strlen\(folder\) > NAME_MAX/);
assert.match(componentValidator, /\*p == '\/'/);
assert.match(componentValidator, /\*p == '\\\\'/);
assert.match(componentValidator, /\*p < 0x20/);
assert.match(componentValidator, /\*p == 0x7f/);
const componentSafe = folder => typeof folder === 'string' && folder.length > 0 &&
    folder !== '.' && folder !== '..' && Buffer.byteLength(folder) <= 255 &&
    !/[\\/\x00-\x1f\x7f]/.test(folder);
const componentCases = [
    ['shares', true], ['folder with spaces', true], ['café', true], ['.', false], ['..', false],
    ['../jffs', false], ['x/../../tmp', false], ['x\\\\..\\\\tmp', false],
    ['line\nfeed', false], ['tab\tname', false], ['delete\x7f', false],
    ['x'.repeat(255), true], ['x'.repeat(256), false]
];
for (const [folder, expected] of componentCases)
    assert.equal(componentSafe(folder), expected, JSON.stringify(folder));

for (const [signature, operation] of [
    ['extern int add_folder(', 'mkdir('],
    ['extern int del_folder(', 'delete_file_or_dir('],
    ['extern int mod_folder(', 'rename(']
]) {
    const body = functionBody(diskShareSource, signature);
    assert.match(body, /mount_path_is_safe\(mount_path\)/);
    assert.match(body, /folder_component_is_safe\(folder\)/);
    assert(body.indexOf('mount_path_is_safe(mount_path)') < body.indexOf(operation));
    assert(body.indexOf('folder_component_is_safe(folder)') < body.indexOf(operation));
    if (signature.includes('mod_folder')) {
        assert.match(body, /folder_component_is_safe\(new_folder\)/);
        assert(body.indexOf('folder_component_is_safe(new_folder)') < body.indexOf('rename('));
    }
}
const mountGuard = functionBody(diskShareSource, 'static int mount_path_is_safe(');
assert.match(mountGuard, /realpath\(mount_path, resolved\)/);
assert.match(mountGuard, /strncmp\(resolved, "\/tmp\/mnt\/", 9\)/);
assert.match(mountGuard, /strcmp\(target, resolved\)/);
assert.match(mountGuard, /is_partition_name\(source \+ 5, NULL\)/);
const mountReader = functionBody(diskInitialSource, 'int read_mount_data(');
assert.match(mountReader, /snprintf\(expected_source, sizeof\(expected_source\), "\/dev\/%s", device_name\)/);
assert.match(mountReader, /strcmp\(source, expected_source\)/);
assert.match(mountReader, /if \(!found\)/);
const mountPath = functionBody(diskInitialSource, 'int get_mount_path(');
assert.match(mountPath, /is_partition_name\(pool, NULL\)/);
assert.match(mountPath, /realpath\(mount_path, resolved\)/);
assert.match(mountPath, /strcmp\(mount_path, resolved\)/);
assert.match(mountPath, /strncmp\(resolved, "\/tmp\/mnt\/", 9\)/);

for (const hookName of ['ej_modify_sharedfolder', 'ej_delete_sharedfolder', 'ej_create_sharedfolder'])
    assert.match(functionBody(source, `int ${hookName}(`), /get_mount_path\(pool, mount_path, PATH_MAX\) != 1/);
assert.equal((source.match(/get_mount_path\(pool, mount_path, PATH_MAX\) < 0/g) || []).length, 0);
for (const [page, endpoint] of [
    ['popCreateFolder.asp', 'create_sharedfolder.asp'],
    ['popDeleteFolder.asp', 'delete_sharedfolder.asp'],
    ['popModifyFolder.asp', 'modify_sharedfolder.asp']
]) {
    const dialog = readPage(`aidisk/${page}`);
    assert.match(dialog, new RegExp(`<form[^>]+method="post"[^>]+action="${endpoint}"`, 'i'));
}
assert.match(source, /\{ "\*\*\.asp\*", "text\/html", no_cache_IE7, do_html_post_and_get, do_ej, do_auth \}/);
const request = httpdSource.slice(httpdSource.indexOf('handle_request(void)\n{'));
const requestGuard = request.match(/if \(\(handler->input \|\| \(do_referer & CHECK_REFERER\) \|\| strstr\(url, "\.cgi"\)\) &&\s*!httpd_check_request_origin\(\) && !httpd_check_csrf_token\(csrf_token\)\)/);
assert(requestGuard);
assert(request.indexOf(requestGuard[0]) < request.indexOf('handler->input(file, conn_fp, cl, boundary)'));

const accountCleanup = functionBody(source, 'static void remove_initial_account_files(');
const accountHandler = functionBody(source, 'int ej_initial_account(');
assert.match(accountCleanup, /opendir\(mount_point\)/);
assert.match(accountCleanup, /dirfd\(dir\)/);
assert.match(accountCleanup, /strncmp\(entry->d_name, "\.__", 3\) == 0/);
assert.match(accountCleanup, /unlinkat\(mount_fd, entry->d_name, 0\)/);
assert.doesNotMatch(accountCleanup, /\bsystem\s*\(/);
assert.match(accountHandler, /remove_initial_account_files\(follow_partition->mount_point\)/);
assert.doesNotMatch(accountHandler, /\bsystem\s*\(/);

const labelSanitizer = functionBody(usbSource, 'static void sanitize_mount_label(');
const mountPartition = functionBody(usbSource, 'int mount_partition(');
for (const allowedRange of [
    /label_char >= 'A' && label_char <= 'Z'/,
    /label_char >= 'a' && label_char <= 'z'/,
    /label_char >= '0' && label_char <= '9'/,
    /label_char == '-' \|\| label_char == '_' \|\| label_char == '\.'/
]) assert.match(labelSanitizer, allowedRange);
assert.match(mountPartition, /sanitize_mount_label\(the_label\)/);
assert.match(mountPartition, /"%s\/%s_%d"/);
assert.doesNotMatch(mountPartition, /"%s\/%s\(%d\)"/);

const isSafeMountByte = labelByte =>
    (labelByte >= 0x41 && labelByte <= 0x5a) ||
    (labelByte >= 0x61 && labelByte <= 0x7a) ||
    (labelByte >= 0x30 && labelByte <= 0x39) ||
    labelByte === 0x2d || labelByte === 0x5f || labelByte === 0x2e;
const sanitizeLabel = bytes => Buffer.from(bytes).map(labelByte =>
    isSafeMountByte(labelByte) ? labelByte : 0x5f).toString('ascii');
assert.equal(sanitizeLabel(Buffer.from('&reboot&')), '_reboot_');
assert.equal(sanitizeLabel(Buffer.from('disk(1)')), 'disk_1_');
assert.equal(sanitizeLabel(Buffer.from('A-z_9.')), 'A-z_9.');
for (let labelByte = 1; labelByte <= 0xff; labelByte++) {
    const sanitized = sanitizeLabel([labelByte]);
    assert.equal(sanitized, isSafeMountByte(labelByte) ? String.fromCharCode(labelByte) : '_');
}

console.log(`PASS: AiDisk rendering plus ${names.length} name round trips, ${componentCases.length} shared-folder name cases, mount containment, mutator and pre-hook CSRF contracts (source/model only; not compiled C or hardware)`);