const assert = require('assert');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '../..');
const checker = fs.readFileSync(path.join(root, 'release/src/router/rc/github_fw_check.c'), 'utf8');
const target = fs.readFileSync(path.join(root, 'release/src-rt/target.mak'), 'utf8');
const rcMakefile = fs.readFileSync(path.join(root, 'release/src/router/rc/Makefile'), 'utf8');
const rcSource = fs.readFileSync(path.join(root, 'release/src/router/rc/rc.c'), 'utf8');
const services = fs.readFileSync(path.join(root, 'release/src/router/rc/services.c'), 'utf8');
const watchdog = fs.readFileSync(path.join(root, 'release/src/router/rc/watchdog.c'), 'utf8');
const config = fs.readFileSync(path.join(root, 'release/src/router/config/config.in'), 'utf8');
const defaults = fs.readFileSync(path.join(root, 'release/src/router/shared/defaults.c'), 'utf8');
const profileMakefile = fs.readFileSync(path.join(root, 'release/src-rt/Makefile'), 'utf8');
const firmwarePage = fs.readFileSync(path.join(root, 'release/src/router/www/Advanced_FirmwareUpgrade_Content.asp'), 'utf8');
const notifications = fs.readFileSync(path.join(root, 'release/src/router/www/notification.js'), 'utf8');

function expectedAssetPrefix(tag) {
    const separator = tag.indexOf('_');
    assert(separator > 0);
    return `DSL-AC68U_${tag.slice(0, separator)}-${tag.slice(separator + 1)}_DSL_`;
}

function releaseIsNewer(available, current) {
    if (available.major !== current.major) return available.major > current.major;
    if (available.minor !== current.minor) return available.minor > current.minor;
    if (available.revision !== current.revision) return available.revision > current.revision;
    return available.suffix > current.suffix;
}

function selectAsset(release) {
    const prefix = expectedAssetPrefix(release.tag_name);
    return release.assets.find(asset =>
        asset.state === 'uploaded' &&
        asset.name.startsWith(prefix) &&
        asset.name.endsWith('.trx') &&
        asset.browser_download_url.startsWith('https://github.com/oivano/asuswrt-merlin.ng/releases/download/'));
}

function makeAsset(tag, name, state = 'uploaded') {
    return {
        state,
        name,
        browser_download_url: `https://github.com/oivano/asuswrt-merlin.ng/releases/download/${tag}/${encodeURIComponent(name)}`
    };
}

const releases = [
    {
        tag_name: '386.15_4-ion',
        assets: [
            makeAsset('386.15_4-ion', 'DSL-AC68U_386.15-4-ion_NO-DSL-FIRMWARE.trx'),
            makeAsset('386.15_4-ion', 'DSL-AC68U_386.15-4-ion_DSL_1.0.5.3.md5'),
            makeAsset('386.15_4-ion', 'DSL-AC68U_386.15-4-ion_DSL_1.0.5.3.trx'),
            makeAsset('386.15_4-ion', 'RT-AC68U_386.15-4-ion_DSL_1.0.5.3.trx')
        ]
    },
    {
        tag_name: '386.16_2',
        assets: [
            makeAsset('386.16_2', 'DSL-AC68U_386.16-2_NO-DSL-FIRMWARE.trx'),
            makeAsset('386.16_2', 'DSL-AC68U_386.16-2_DSL_1.0.5.4.md5'),
            makeAsset('386.16_2', 'DSL-AC68U_386.16-2_DSL_1.0.5.4.trx', 'new')
        ]
    }
];

assert.strictEqual(selectAsset(releases[0]).name, 'DSL-AC68U_386.15-4-ion_DSL_1.0.5.3.trx');
assert.strictEqual(selectAsset(releases[1]), undefined);
releases[1].assets[2].state = 'uploaded';
assert.strictEqual(selectAsset(releases[1]).name, 'DSL-AC68U_386.16-2_DSL_1.0.5.4.trx');
assert.strictEqual(selectAsset({ ...releases[0], assets: releases[0].assets.slice(0, 2) }), undefined);
assert.strictEqual(releaseIsNewer(
    { major: 386, minor: 15, revision: 4, suffix: '-ion' },
    { major: 386, minor: 15, revision: Number.MAX_SAFE_INTEGER, suffix: 'DEV-experimental-20261117' }), false);
assert.strictEqual(releaseIsNewer(
    { major: 386, minor: 16, revision: 1, suffix: '-ion' },
    { major: 386, minor: 15, revision: Number.MAX_SAFE_INTEGER, suffix: 'DEV-experimental-20261117' }), true);
assert(checker.includes('https://api.github.com/repos/oivano/asuswrt-merlin.ng/releases/latest'));
assert(checker.includes('version->revision = ULONG_MAX'));
assert(checker.includes('isdigit((unsigned char)*extension)'));
assert(checker.includes('CURLOPT_SSL_VERIFYPEER, 1L'));
assert(checker.includes('CURLOPT_SSL_VERIFYHOST, 2L'));
assert(checker.includes('GITHUB_RESPONSE_MAX'));
assert(checker.includes('ion_fw_check_status'));
assert(checker.includes('ion_fw_download_url'));
assert(checker.includes('GITHUB_RELEASE_PAGE_PREFIX'));
assert(checker.includes('ion_fw_release_url'));
assert(checker.includes('json_string_member(release, "body")'));
assert(checker.includes('publish_release_notes(release_notes)'));
assert(checker.includes('/tmp/release_note0.txt'));
assert(checker.includes('rename(temporary_path, note_path)'));
assert(checker.includes('nvram_set("webs_state_info_am", newer ? tag : "")'));
assert(checker.includes('nvram_set("webs_state_flag", newer ? "1" : "0")'));
assert(checker.includes('release_is_newer'));
assert(!checker.includes('webs_state_url'));
assert(target.includes('MERLINUPDATE=n IONUPDATE=y'));
assert(config.includes('config RTCONFIG_IONUPDATE'));
assert(profileMakefile.includes('if [ "$(IONUPDATE)" = "y" ]'));
assert(profileMakefile.includes('echo "RTCONFIG_IONUPDATE=y"'));
assert(profileMakefile.includes('echo "# RTCONFIG_IONUPDATE is not set"'));
assert(defaults.includes('"firmware_check_enable", "1"'));
assert(defaults.includes('"ion_fw_check_status", "idle"'));
assert(defaults.includes('"ion_fw_check_run", "0"'));
assert(defaults.includes('"ion_fw_release_url", ""'));
assert(rcMakefile.includes('OBJS += github_fw_check.o'));
assert(rcMakefile.includes('ln -sf rc ion_firmware_check'));
assert(rcSource.includes('firmware_release_check_main'));
assert(services.includes('strcmp(script, "ion_firmware_check")'));
assert(services.includes('char *check_argv[] = { "/sbin/ion_firmware_check", NULL }'));
assert(!services.includes('char *check_argv[] = { "/usr/sbin/ion_firmware_check", NULL }'));
assert(services.includes('nvram_set_int("ion_fw_check_run"'));
assert(watchdog.includes('auto_ion_firmware_check'));
assert(firmwarePage.includes('ionupdate_support = (based_modelid == "DSL-AC68U")'));
assert(firmwarePage.includes('Visit download site'));
assert(firmwarePage.includes('Release notes'));
assert(firmwarePage.includes('Development build; no newer stable release than '));
assert(firmwarePage.includes('if(/^\\d+$/.test(extendno))'));
assert(firmwarePage.includes('function show_ion_release_notes(tag, url)'));
assert(firmwarePage.includes('iframe: "get_release_note0.asp"'));
assert(firmwarePage.includes('show_ion_release_notes(tag, url);'));
assert(!firmwarePage.includes('.attr({"href": releaseUrl'));
assert(firmwarePage.includes('ion_fw_release_url'));
assert(firmwarePage.includes('poll_ion_firmware_check(previousRun, 40)'));
assert(firmwarePage.includes('start_ion_firmware_check'));
assert(!firmwarePage.includes('"ion_fw_check_status": "checking"'));
assert(notifications.includes('var ionupdate_support = (based_modelid == "DSL-AC68U")'));
assert(notifications.includes("notification.desc[1] = 'A new firmware version (' + webs_state_info + ') is now available.'"));
assert(notifications.includes('if(ionupdate_support){'));
assert(notifications.includes("location.href = 'Advanced_FirmwareUpgrade_Content.asp?confirm_show=0'"));

console.log('IONUPDATE wiring, release selection, and native notification contracts passed');