const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const releaseUrl = 'https://github.com/oivano/asuswrt-merlin.ng/releases';
const scriptPath = 'release/src/router/rom/webs_scripts/ssl_webs_upgrade.sh';
const script = read(scriptPath);
const updaterPath = 'release/src/router/rom/webs_scripts/merlin_webs_update.sh';
const updater = read(updaterPath);
const rom = read('release/src/router/rom/Makefile');
const firmwarePage = read('release/src/router/www/Advanced_FirmwareUpgrade_Content.asp');
const qis = read('release/src/router/www/sysdep/DSL-AC68U/www/qis/QIS_finish.htm');

for (const file of [scriptPath, updaterPath]) {
    assert.equal(spawnSync('sh', ['-n', path.join(root, file)]).status, 0);
}

assert(script.includes(releaseUrl));
assert.doesNotMatch(script, /wget|curl|restart_upgrade|stop_upgrade|reboot|firmware_check|rsasign_check|nvram commit|dlcdn|update_url|webs_state_url/);
assert.doesNotMatch(script, /\brm\b|\bmount\b|\bejusb\b/);

for (const trigger of ['', '1', 'https://attacker.invalid/old.trx']) {
    const result = spawnSync('sh', ['-c', `
logger() { printf 'LOG %s\n' "$*"; }
nvram() { printf 'NVRAM %s\n' "$*"; }
rc() { printf 'UNEXPECTED rc %s\n' "$*"; }
wget() { printf 'UNEXPECTED wget %s\n' "$*"; }
reboot() { printf 'UNEXPECTED reboot\n'; }
${script}`, 'test', trigger], {
        encoding: 'utf8',
        env: { ...process.env, update_url: 'http://attacker.invalid', webs_state_url: 'http://attacker.invalid' }
    });
    assert.equal(result.status, 1);
    assert.doesNotMatch(result.stdout, /UNEXPECTED/);
    assert(result.stdout.includes(releaseUrl));
    const settings = result.stdout.split('\n').filter(line => line.startsWith('NVRAM '));
    assert.deepEqual(settings, [
        'NVRAM set webs_state_error=3',
        'NVRAM set webs_state_dl_error=3',
        'NVRAM set webs_state_flag=0',
        'NVRAM set webs_state_upgrade=1',
        'NVRAM set auto_upgrade=0',
        'NVRAM set webs_state_dl=0'
    ]);
}

const install = 'install -m 0755 webs_scripts/ssl_webs_upgrade.sh $(INSTALLDIR)/usr/sbin/webs_upgrade.sh';
assert(rom.includes(`ifeq ($(BUILD_NAME),DSL-AC68U)\n\t${install}\nendif`));
assert(rom.indexOf(install) > rom.indexOf('endif\t#merlinupdate'));
assert(!rom.slice(rom.indexOf(install) + install.length).includes('/usr/sbin/webs_upgrade.sh'));

const action = qis.match(/function doLiveUpdate\(_do\)\{[\s\S]*?\n\}/)[0];
assert.doesNotMatch(action, /submit|start_webs_upgrade|stop_upgrade|progressBar/);
for (const accepted of [true, false]) {
    const context = { parent: { location: {} }, setTimeout() {} };
    vm.runInNewContext(`${action}; doLiveUpdate(${accepted});`, context);
    assert.equal(context.parent.location.href, accepted ? releaseUrl : undefined);
}
assert(firmwarePage.includes(`var download_url = "${releaseUrl}";`));
assert(firmwarePage.includes(`href="${releaseUrl}"`));
assert.doesNotMatch(firmwarePage, /download_srv|releases" \+ event\.data\.model_name/);
assert(updater.includes('fwsite="https://oivano.github.io/asuswrt-merlin.ng/updates"'));
assert.doesNotMatch(updater, /gnuton|--no-check-certificate/);
assert(updater.includes('--check-certificate --ca-certificate=/etc/ssl/certs/ca-certificates.crt --max-redirect=0'));

console.log('PASS: executed live-flash refusal and QIS actions; DSL install, GitHub source, and metadata TLS contracts');