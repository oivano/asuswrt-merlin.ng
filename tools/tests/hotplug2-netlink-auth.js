const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const hotplug = read('release/src/router/hotplug2/hotplug2.c');
const rules = read('release/src/router/hotplug2/rules.c');
const rc = read('release/src/router/rc/rc.c');
const usb = read('release/src/router/rc/usb.c');

assert.match(hotplug, /size = recvmsg\(netlink_socket, &msg, 0\)/);
assert.match(hotplug, /sender\.nl_family != AF_NETLINK \|\| sender\.nl_pid != 0/);
assert.match(hotplug, /msg\.msg_flags & MSG_TRUNC/);
assert.match(hotplug, /msg\.msg_namelen < sizeof\(sender\)/);

const allowlist = rules.match(/static int event_env_allowed\(const char \*key\)\s*\{([\s\S]*?)\n\}/);
assert(allowlist, 'event environment allowlist exists');
for (const key of ['ACTION', 'DEVPATH', 'DEVICENAME', 'SUBSYSTEM', 'MAJOR', 'MINOR', 'MODALIAS', 'FIRMWARE']) {
    assert(allowlist[1].includes(`"${key}"`), `allowlist retains ${key}`);
}
for (const key of ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'PATH', 'IFS']) {
    assert(!allowlist[1].includes(`"${key}"`), `allowlist excludes ${key}`);
}
assert.match(rules, /if \(!event_env_allowed\(event->env_vars\[i\]\.key\)\)/);
assert.match(rules, /strchr\(devicename, '\/'\)/);
assert.match(rules, /!strcmp\(devicename, "\."\) \|\| !strcmp\(devicename, "\.\."\)/);

const validator = rc.match(/static int hotplug_device_name_valid\(const char \*applet, const char \*name\)\s*\{([\s\S]*?)\n\}/);
assert(validator, 'rc applet device-name validator exists');
for (const applet of ['asus_sd', 'asus_mmc', 'asus_lp', 'asus_sg', 'asus_sr', 'asus_tty', 'asus_usb_interface', 'asus_usbbcm']) {
    assert(validator[1].includes(`"${applet}"`), `validator covers ${applet}`);
    assert(rc.includes(`hotplug_device_name_valid(base, argv[1])`), `${applet} applets validate argv`);
}
assert.match(rc, /hotplug_action_valid\(argv\[2\]\)/);

assert.match(usb, /hotplug_sysfs_block_numbers\(device, &major, &minor\)/);
assert.match(usb, /\/sys\/block\/%s\/%s\/dev/);
assert.match(usb, /\/sys\/block\/%s\/dev/);
assert.match(usb, /hotplug_block_name_valid\(device\)/);
assert.match(usb, /strlen\(device\) >= sizeof\(parent\)/);
assert.doesNotMatch(usb, /\/sys\/class\/block\/%s\/dev/);
assert.match(usb, /else if \(!strncmp\(device, "sr", 2\)\) \{\s*#ifdef RTCONFIG_USB_CDROM\s*major = USB_CDROM_MAJOR;\s*#endif\s*\}\s*else \{\s*major = USB_DISK_MAJOR;/);
assert.doesNotMatch(usb, /safe_atoi\(getenv\("MAJOR"\)/);
assert.doesNotMatch(usb, /safe_atoi\(getenv\("MINOR"\)/);

console.log('hotplug2 netlink authentication and rc input contracts passed');