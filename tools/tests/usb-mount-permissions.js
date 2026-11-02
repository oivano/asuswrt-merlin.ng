const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const usb = fs.readFileSync(path.join(root, 'release/src/router/rc/usb.c'), 'utf8');
const mount = usb.match(/int mount_r\([\s\S]*?(?=\nstruct mntent \*mount_fstab)/);
assert.ok(mount, 'mount_r definition exists');
const source = mount[0];

assert.match(source, /unsigned long flags = MS_NOATIME \| MS_NODEV \| MS_NOSUID;/);
assert.match(source, /unsigned long flags = MS_NODEV \| MS_NOSUID;/);
assert.match(source, /strlcat\(options, options\[0\] \? ",nosuid,nodev" : "nosuid,nodev", sizeof\(options\)\)/);
assert.match(source, /mount\(mnt_dev, mnt_dir, type, flags, options\[0\] \? options : ""\)/);
assert.match(source, /eval\("mount", "-t", "vfat", "-o", options, mnt_dev, mnt_dir\)/);
assert.match(source, /eval\("mount", "-t", "tfat", "-o", options, mnt_dev, mnt_dir\)/);
assert.match(source, /eval\("ntfs-3g", "-o", options, mnt_dev, mnt_dir\)/);
assert.match(source, /eval\("mount", "-t", "tntfs", "-o", options, mnt_dev, mnt_dir\)/);
assert.match(source, /eval\("mount", "-t", "ufsd", "-o", options/);
assert.match(source, /eval\("mount", "-t", "hfsplus", "-o", options, mnt_dev, mnt_dir\)/);
assert.match(source, /eval\("mount", "-t", "thfsplus", "-o", options, mnt_dev, mnt_dir\)/);
assert.match(source, /eval\("mount", "-t", "udf", "-o", options, mnt_dev, mnt_dir\)/);
assert.match(source, /eval\("mount", "-t", "iso9660", "-o", options, mnt_dev, mnt_dir\)/);
assert.match(source, /eval\("tapfs-u", "-o", "nosuid,nodev", mnt_dev, mnt_dir\)/);
assert.match(source, /"noatime,nodev,nosuid"/);
assert.match(source, /"nodev,nosuid"/);

assert.match(usb, /snprintf\(command, PATH_MAX, "%s\/\.asusrouter", nvram_safe_get\("apps_local_space"\)\);[\s\S]*?system\(command\);/);
assert.match(usb, /snprintf\(command, PATH_MAX, "ln -sf %s\/%s \/tmp\/opt", mountpoint, apps_folder\);/);

console.log('USB mount permission contracts passed');