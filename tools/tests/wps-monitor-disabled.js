const assert = require("assert");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../..");
const services = fs.readFileSync(path.join(root, "release/src/router/rc/services.c"), "utf8");
const defaults = fs.readFileSync(path.join(root, "release/src/router/shared/defaults.c"), "utf8");
const configDefaults = fs.readFileSync(path.join(root, "release/src/router/cfg_mnt/cfg_param.h"), "utf8");

function functionBody(startMarker, endMarker) {
	const start = services.indexOf(startMarker);
	const end = services.indexOf(endMarker, start);
	assert(start >= 0 && end > start, `Could not locate ${startMarker}`);
	return services.slice(start, end);
}

const checkWps = functionBody("\ncheck_wps_enable()\n{", "\nint\nstart_wps_pbc");
assert.match(checkWps, /#ifdef RTCONFIG_DSL[\s\S]*?nvram_set\("wps_enable_x", "0"\);[\s\S]*?nvram_set\("wps_enable", "0"\);[\s\S]*?nvram_set\("wl_wps_mode", "disabled"\);[\s\S]*?#else/);

const startWps = functionBody("\nstart_wps(void)\n{", "\nint\nstop_wps(void)");
const dslGuard = startWps.indexOf("#ifdef RTCONFIG_DSL");
const guardReturn = startWps.indexOf("return 0;", dslGuard);
const monitorLaunch = startWps.indexOf("_eval(wps_argv");
assert(dslGuard >= 0 && guardReturn > dslGuard && guardReturn < monitorLaunch,
	"DSL start_wps must return before the monitor launch path");
for (const required of [
	'nvram_set("wps_enable_x", "0")',
	'nvram_set("wps_enable", "0")',
	'nvram_set("wl_wps_mode", "disabled")',
	'killall_tk("wps_monitor")',
	'unlink("/tmp/wps_monitor.pid")'
]) {
	assert(startWps.indexOf(required) < guardReturn, `DSL guard is missing ${required}`);
}

assert.match(defaults, /\{ "wps_enable", "0"/);
assert.match(defaults, /\{ "wps_enable_x", "0"/);
assert.match(configDefaults, /\{ "wps_enable", FT_WIRELESS, SUBFT_WPS,\s+"0"\}/);

console.log("DSL WPS monitor disablement checks passed");
