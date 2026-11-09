import assert from 'node:assert/strict';
import {
    mkdirSync,
    mkdtempSync,
    readFileSync,
    rmSync,
    statSync,
    symlinkSync,
    unlinkSync,
    utimesSync,
    writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const read = (path) => readFileSync(new URL(`../../release/src/router/${path}`, import.meta.url), 'utf8');
const header = read('rc/rc.h');
const init = read('rc/init.c');
const watchdog = read('rc/watchdog.c');
const monitor = read('rc/check_watchdog.c');

assert.match(header, /#define WATCHDOG_HEARTBEAT_DIRECTORY "\/tmp\/watchdog"/);
assert.match(header, /#define WATCHDOG_HEARTBEAT_FILE WATCHDOG_HEARTBEAT_DIRECTORY "\/heartbeat"/);
const prepare = init.match(/static int watchdog_heartbeat_dir_prepare\(void\)([\s\S]*?)\n\}/)?.[1];
assert.ok(prepare, 'startup directory preparation exists');
assert.match(prepare, /geteuid\(\) != 0/);
assert.match(prepare, /O_DIRECTORY \| O_NOFOLLOW/);
assert.match(prepare, /st\.st_uid == 0/);
assert.match(prepare, /fchmod\(fd, 0700\)/);
assert.match(prepare, /path\.st_ino == st\.st_ino/);
assert.ok(init.indexOf('watchdog_heartbeat_dir_prepare()') > init.indexOf('chmod("/tmp", 01777)'),
    'private directory is prepared during early runtime setup');

const secureDir = watchdog.match(/int watchdog_heartbeat_dir_is_secure\(void\)([\s\S]*?)\n\}/)?.[1];
assert.ok(secureDir, 'writer and monitor share parent validation');
assert.match(secureDir, /O_DIRECTORY \| O_NOFOLLOW/);
assert.match(secureDir, /st\.st_uid == 0/);
assert.match(secureDir, /\(st\.st_mode & 07777\) == 0700/);
const buttonCheck = watchdog.match(/void btn_check\(void\)([\s\S]*?)\n\}/)?.[1];
assert.match(buttonCheck, /watchdog_heartbeat_dir_is_secure\(\)[\s\S]*?eval\("touch", WATCHDOG_HEARTBEAT_FILE\)/);
assert.doesNotMatch(buttonCheck, /\/tmp\/watchdog_heartbeat/);
assert.match(monitor, /watchdog_heartbeat_dir_is_secure\(\)/);
assert.match(monitor, /lstat\(WATCHDOG_HEARTBEAT_FILE, &sb\)/);
assert.match(monitor, /S_ISREG\(sb\.st_mode\) && sb\.st_uid == 0 && sb\.st_nlink == 1/);

const sandbox = mkdtempSync(join(tmpdir(), 'watchdog-heartbeat-'));
try {
    const privateDir = join(sandbox, 'watchdog');
    const missingTarget = join(sandbox, 'missing-target');
    const oldPath = join(sandbox, 'watchdog_heartbeat');
    mkdirSync(privateDir, { mode: 0o700 });
    symlinkSync(missingTarget, oldPath);
    const heartbeat = join(privateDir, 'heartbeat');
    writeFileSync(heartbeat, '');
    assert.equal(statSync(heartbeat).isFile(), true,
        'monitor has a regular heartbeat at the private path');
    assert.throws(() => statSync(missingTarget), { code: 'ENOENT' },
        'legacy planted symlink target is not created');

    unlinkSync(oldPath);
    const existingTarget = join(sandbox, 'existing-target');
    writeFileSync(existingTarget, 'existing');
    const oldTime = new Date(Date.now() - 120000);
    utimesSync(existingTarget, oldTime, oldTime);
    const oldMtime = statSync(existingTarget).mtimeMs;
    symlinkSync(existingTarget, oldPath);
    utimesSync(heartbeat, new Date(), new Date());
    assert.equal(statSync(existingTarget).mtimeMs, oldMtime,
        'legacy planted symlink target is not re-timestamped');
} finally {
    rmSync(sandbox, { recursive: true, force: true });
}