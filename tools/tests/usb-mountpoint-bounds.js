const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const common = fs.readFileSync(path.join(root, 'release/src/router/rc/common.c'), 'utf8');
const timeMachine = fs.readFileSync(path.join(root, 'release/src/router/rc/timemachine.c'), 'utf8');
const usb = fs.readFileSync(path.join(root, 'release/src/router/rc/usb.c'), 'utf8');

function functionBody(source, signature) {
    const start = source.indexOf(signature);
    assert.notEqual(start, -1, `missing ${signature}`);
    const end = source.indexOf('\n}', start);
    assert.notEqual(end, -1, `missing end of ${signature}`);
    return source.slice(start, end + 2);
}

const mountCount = functionBody(web, '\ncount_sddev_mountpoint()\n{');
assert.match(mountCount, /setmntent\(MOUNT_FILE, "r"\)/);
assert.match(mountCount, /getmntent\(procpt\)/);
assert.match(mountCount, /mnt->mnt_fsname, "\/dev\/sd"/);
assert.match(mountCount, /endmntent\(procpt\)/);
assert.doesNotMatch(mountCount, /sscanf\s*\(/);

const mountCheck = functionBody(common, 'int check_mountpoint(char *mountpoint)');
assert.match(mountCheck, /getmntent\(procpt\)/);
assert.match(mountCheck, /mnt->mnt_dir, mountpoint/);
assert.match(mountCheck, /endmntent\(procpt\)/);
assert.doesNotMatch(mountCheck, /sscanf\s*\(/);

for (const signature of [
    'char *find_mountpoint(char *device_name)',
    'char *find_exchange_mountpoint(char *device_name)',
    'void find_tokenfile_partition()',
]) {
    const body = functionBody(timeMachine, signature);
    assert.match(body, /getmntent\(procpt\)/, `${signature} uses getmntent`);
    assert.match(body, /endmntent\(procpt\)/, `${signature} closes the mount table`);
    assert.doesNotMatch(body, /sscanf\s*\(/, `${signature} has no width-less mount parser`);
}

assert.match(timeMachine, /static char mount_point_name\[128\]/);
assert.match(timeMachine, /char token_path\[PATH_MAX\]/);
assert.match(timeMachine, /char cnid_path\[128 \+ sizeof\(CNID_DIR_NAME\)\]/);

const mountPartition = functionBody(usb, 'int mount_partition(');
assert.match(mountPartition, /char the_label\[128\], mountpoint\[128\]/);
assert.match(mountPartition, /snprintf\(mountpoint, sizeof\(mountpoint\), "%s\/%s", POOL_MOUNT_ROOT, the_label\)/);

const label = 'L'.repeat(64);
const mountpoint = `/tmp/mnt/${label}`;
assert(mountpoint.length < 128);
assert(`${mountpoint}/CNID`.length < 128 + 'CNID'.length + 1);
assert(`${mountpoint}/.tm_tokenfile.txt`.length < 4096);

console.log('USB mountpoint bounds: ok');