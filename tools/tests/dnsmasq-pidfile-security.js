"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const repo = path.resolve(__dirname, "../..");
const source = (file) => fs.readFileSync(path.join(repo, file), "utf8");

const dnsmasq = source("release/src/router/dnsmasq/src/dnsmasq.c");
const services = source("release/src/router/rc/services.c");
const ntp = source("release/src/router/rc/ntp.c");
const ntpd = source("release/src/router/rc/ntpd.c");
const process = source("release/src/router/shared/process.c");

assert.doesNotMatch(dnsmasq, /chown_warn|fchown\(fd, ent_pw/);
assert.match(dnsmasq, /open\(daemon->runfile, O_WRONLY\|O_CREAT\|O_TRUNC\|O_EXCL, S_IWUSR\|S_IRUSR\|S_IRGRP\|S_IROTH\)/);

assert.match(services, /void reload_dnsmasq\(void\)\s*\{[^}]*killall\("dnsmasq", SIGHUP\);/s);
assert.match(ntp, /killall\("dnsmasq", SIGINT\);/);
assert.match(ntpd, /killall\("dnsmasq", SIGINT\);/);
for (const file of [services, ntp, ntpd])
    assert.doesNotMatch(file, /kill_pidfile_s\("\/var\/run\/dnsmasq\.pid"/);

assert.match(process, /strcmp\(name, psname\(i, buf, sizeof\(buf\)\)\) == 0/);
assert.match(process, /kill\(pids\[--i\], sig\)/);

console.log("dnsmasq pidfile security checks passed");