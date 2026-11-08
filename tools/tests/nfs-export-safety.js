const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const usb = fs.readFileSync(path.join(root, 'release/src/router/rc/usb.c'), 'utf8');
const page = fs.readFileSync(path.join(root, 'release/src/router/www/Advanced_AiDisk_NFS.asp'), 'utf8');
const nfsExports = fs.readFileSync(path.join(root,
    'release/src/router/nfs-utils-1.3.4/support/nfs/exports.c'), 'utf8');
const start = usb.indexOf('void start_nfsd(void)');
const end = usb.indexOf('void restart_nfsd(void)', start);
assert.ok(start >= 0 && end > start);
const startup = usb.slice(start, end);

assert.match(startup, /fprintf\(fp, " %s\(root_squash%s%s\)"/);
assert.ok(startup.indexOf('run_postconf("exports"') < startup.indexOf('nfs_filter_private_exports()'));
assert.ok(startup.indexOf('nfs_filter_private_exports()') < startup.indexOf('exportfs", "-r'));
assert.match(startup, /nfs_filter_private_exports\(\) != 0[\s\S]*?exportfs", "-au"[\s\S]*?return;/);
assert.match(nfsExports, /strcmp\(opt, "root_squash"\) == 0[\s\S]*?setflags\(NFSEXP_ROOTSQUASH/);
assert.match(nfsExports, /!strcmp\(opt, "no_root_squash"\)[\s\S]*?clearflags\(NFSEXP_ROOTSQUASH/);

function effectiveRootSquash(options) {
    let rootSquash = true;
    for (const option of options.split(',').filter(Boolean)) {
        if (option === 'root_squash') rootSquash = true;
        if (option === 'no_root_squash') rootSquash = false;
    }
    return rootSquash;
}

assert.equal(effectiveRootSquash(''), true);
assert.equal(effectiveRootSquash('rw'), true);
assert.equal(effectiveRootSquash('rw,no_root_squash'), false);
assert.equal(effectiveRootSquash('no_root_squash,root_squash'), true);

function within(candidate, base) {
    return candidate === base || candidate.startsWith(base.endsWith('/') ? base : base + '/');
}
function overlaps(candidate, privatePath) {
    return within(candidate, privatePath) || within(privatePath, candidate);
}

const privateSwap = '/tmp/mnt/disk1/.asus-swap';
assert.equal(overlaps('/tmp/mnt/disk1', privateSwap), true);
assert.equal(overlaps('/tmp/mnt/disk1/.asus-swap/.swap', privateSwap), true);
assert.equal(overlaps('/tmp/mnt/disk1/shared', privateSwap), false);
assert.equal(overlaps('/tmp/mnt/disk10', privateSwap), false);
assert.equal(overlaps('/', privateSwap), true);

assert.match(usb, /static int nfs_private_usb_name\([\s\S]*?"\.asus-swap"[\s\S]*?"\.swap"[\s\S]*?"asus_lighttpdpasswd"[\s\S]*?"asusware"[\s\S]*?"\.txt"/);
assert.match(usb, /swap_enabled = nvram_match\("apps_swap_enable", "1"\)/);
assert.match(usb, /swap_enabled \|\| lstat\(private_path, &st\) == 0/);
assert.match(usb, /setmntent\("\/proc\/mounts", "r"\)/);
assert.match(usb, /opendir\(entry->mnt_dir\)[\s\S]*?nfs_private_usb_name\(item->d_name\)/);
assert.match(usb, /nfs_export_overlaps_private_path\(path, private_path\)/);
assert.match(usb, /rename\(temp_path, NFS_EXPORT\)/);
assert.match(usb, /p\[1\] >= '0' && p\[1\] <= '7'[\s\S]*?p\[3\] >= '0' && p\[3\] <= '7'/);

assert.match(page, /cell_value = "root_squash"[\s\S]*?cell_value\.length > 0/);
assert.match(page, /Effective options/);
assert.match(page, /root_squash[\s\S]*?no_root_squash/);
assert.match(page, /router-private USB data[\s\S]*?\.asus-swap/);

console.log('NFS export safety checks passed');
