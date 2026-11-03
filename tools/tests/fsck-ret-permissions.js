const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/rom/apps_scripts/app_fsck.sh'), 'utf8');
const guard = source.match(/_ensure_fsck_ret_dir\(\)\s*\{([\s\S]*?)\n\}/);
assert.ok(guard, 'result directory validation exists');
assert.match(guard[1], /ls -ldn/);
assert.match(guard[1], /\$3 == 0/);
assert.match(guard[1], /substr\(\$1, 6, 1\) != "w"/);
assert.match(guard[1], /substr\(\$1, 9, 1\) != "w"/);
assert.ok(source.indexOf('elif ! _ensure_fsck_ret_dir; then') < source.indexOf('[ "$1" == "vfat" ]'),
    'directory validation precedes the FAT fast path');
assert.doesNotMatch(source, /rm -rf\s+\$ret_dir/);

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'fsck-ret-permissions-'));
try {
    for (const [type, plantedName] of [['ntfs', 'sda1.log'], ['vfat', 'sda1.3']]) {
        const directory = path.join(temporary, type);
        const target = path.join(temporary, `${type}-target`);
        const plantedLink = path.join(directory, plantedName);
        fs.mkdirSync(directory, { mode: 0o777 });
        fs.chmodSync(directory, 0o777);
        fs.writeFileSync(target, 'sensitive sentinel\n');
        fs.symlinkSync(target, plantedLink);
        if (process.getuid() === 0) fs.chownSync(directory, 65534, 65534);

        const script = source.replace(/^ret_dir=\/tmp\/fsck_ret$/m, `ret_dir="${directory}"`);
        assert.notEqual(script, source, 'test directory replaces the fixed result path');
        const prelude = `
            nvram() {
                case "$2" in
                    usb_ntfs_mod) printf tuxera ;;
                    *) printf 0 ;;
                esac
            }
            free_caches() { :; }
            ntfsck() { printf 'NTFS_MARKER'; return 0; }
        `;
        const result = spawnSync('/bin/bash', ['-c', prelude + script, 'app_fsck.sh', type, '/dev/sda1'], {
            encoding: 'utf8'
        });
        assert.ifError(result.error);
        assert.equal(result.status, 1, `${type} scan rejects an untrusted directory: ${result.stderr}`);
        assert.match(result.stderr, /refusing unsafe result directory/);
        assert.equal(fs.readFileSync(target, 'utf8'), 'sensitive sentinel\n', `${type} target remains unchanged`);
        assert.equal(fs.lstatSync(plantedLink).isSymbolicLink(), true, `${type} planted symlink remains untouched`);
    }
    console.log('PASS: fsck refuses attacker-owned result directories before NTFS/FAT file operations');
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}