const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const usb = fs.readFileSync(path.join(root, 'release/src/router/rc/usb.c'), 'utf8');
const validMountpoint = usb.match(/static int usb_mountpoint_path_is_valid\([\s\S]*?\n\}/);
const safeMountpoint = usb.match(/static int usb_mountpoint_is_safe\([\s\S]*?\n\}/);
const prepareMountpoint = usb.match(/static int usb_mountpoint_prepare\([\s\S]*?\n\}/);
assert.ok(validMountpoint, 'mountpoint path validation exists');
assert.ok(safeMountpoint, 'safe mountpoint check exists');
assert.ok(prepareMountpoint, 'mountpoint preparation exists');
assert.match(validMountpoint[0], /POOL_MOUNT_ROOT[\s\S]*?path\[root_len\] != '\/'/);
assert.match(validMountpoint[0], /!strchr\(name, '\/'\)[\s\S]*?strcmp\(name, "\.\."\) != 0/);
assert.match(safeMountpoint[0], /lstat\(path, &st\)[\s\S]*?S_ISDIR\(st\.st_mode\)/);
assert.match(safeMountpoint[0], /st\.st_uid == 0.*st\.st_mode & 0022/);
assert.match(prepareMountpoint[0], /lstat\(path, &st\).*S_ISDIR\(st\.st_mode\).*st\.st_uid != 0/);
assert.match(prepareMountpoint[0], /chmod\(path, 0755\)/);
const mount = usb.match(/int mount_r\([\s\S]*?(?=\nstruct mntent \*mount_fstab)/);
assert.ok(mount, 'mount_r definition exists');
const source = mount[0];
assert.match(source, /usb_mountpoint_prepare\(mnt_dir, &dir_made\)/);
assert.match(source, /if \(!usb_mountpoint_is_safe\(mnt_dir\)\)[\s\S]*?if\(!strncmp\(type, "ext", 3\)\)/);

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

const mountPartition = usb.match(/int mount_partition\([\s\S]*?(?=\nint umount_disk|\nstatic )/);
assert.ok(mountPartition, 'mount_partition definition exists');
assert.match(mountPartition[0], /struct stat st;[\s\S]*?lstat\(mountpoint, &st\) == 0 && S_ISDIR\(st\.st_mode\)[\s\S]*?chmod\(mountpoint, 0777\)/);
assert.doesNotMatch(mountPartition[0], /chmod\(mountpoint, 0777\)[\s\S]*?lstat\(/);

assert.match(usb, /snprintf\(command, PATH_MAX, "%s\/\.asusrouter", nvram_safe_get\("apps_local_space"\)\);[\s\S]*?system\(command\);/);
assert.match(usb, /snprintf\(command, PATH_MAX, "ln -sf %s\/%s \/tmp\/opt", mountpoint, apps_folder\);/);

console.log('USB mount permission contracts passed');