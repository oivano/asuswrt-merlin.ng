"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../..");
const common = fs.readFileSync(path.join(root, "release/src/router/httpd/common.h"), "utf8");
const httpd = fs.readFileSync(path.join(root, "release/src/router/httpd/httpd.c"), "utf8");
const web = fs.readFileSync(path.join(root, "release/src/router/httpd/web.c"), "utf8");

assert.match(common, /#define HTTPD_DEBUG_FILE\s+"\/tmp\/httpd\/HTTPD_DEBUG\.log"/);
assert.match(common, /if \(httpd_debug_log_enabled\(\)\)/);
assert.doesNotMatch(common, /f_exists\(HTTPD_DEBUG\)/);
assert.match(httpd, /int httpd_debug_log_enabled\(void\)[\s\S]*?return httpd_debug_log_ready && nvram_get_int\("HTTPD_DBG"\) > 0;/);
assert.match(httpd, /int httpd_ensure_temp_dir\(void\)[\s\S]*?geteuid\(\)/);
assert.match(httpd, /int httpd_ensure_temp_dir\(void\)[\s\S]*?st_uid != 0[\s\S]*?\(st\.st_mode & 0777\) != 0700/);
assert.match(httpd, /static void httpd_debug_log_init\(void\)[\s\S]*?httpd_ensure_temp_dir\(\)[\s\S]*?unlink\(HTTPD_DEBUG_LEGACY_FILE\)[\s\S]*?unlink\(HTTPD_DEBUG_LEGACY_FILE "-1"\)/);
assert.match(httpd, /httpd_debug_log_init\(\);/);
assert.doesNotMatch(httpd, /eval\("touch", HTTPD_DEBUG\)/);
assert.doesNotMatch(web, /HTTPD_DBG\([^;]*(?:post_buf|authorization_t)/);
assert.match(web, /POST request received; payload omitted/);
assert.match(web, /login request received; authorization omitted/);

console.log("httpd debug logging privacy checks passed");