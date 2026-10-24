#!/usr/bin/env node
"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../..");
const read = (name) => fs.readFileSync(path.join(root, name), "utf8");
const httpd = read("release/src/router/httpd/httpd.c");
const header = read("release/src/router/httpd/httpd.h");
const arrays = read("release/src/router/httpd/data_arrays.c");
const sysinfo = read("release/src/router/httpd/sysinfo.c");
const web = read("release/src/router/httpd/web.c");

assert.match(header, /httpd_create_tempfile\(char \*path, size_t path_size\)/);
assert.match(httpd, /mkdir\(directory, 0700\)/);
assert.match(httpd, /lstat\(directory, &st\)/);
assert.match(httpd, /S_ISDIR\(st\.st_mode\).*st\.st_uid != 0/s);
assert.match(httpd, /\(st\.st_mode & 0777\) != 0700/);
assert.match(httpd, /mkstemp\(path\)/);
assert.match(httpd, /fchmod\(fd, 0600\)/);

for (const oldPath of [
  "/tmp/pinhole.log",
  "/tmp/vserver.log",
  "/tmp/connect.log",
  "/tmp/tcclass.txt",
  "/tmp/output.txt",
  "/tmp/conntrack.tmp",
  "/tmp/upnp.leases",
]) {
  assert(!arrays.includes(oldPath), `legacy data-array path remains: ${oldPath}`);
  assert(!sysinfo.includes(oldPath), `legacy sysinfo path remains: ${oldPath}`);
}

assert.match(arrays, /fopen\("\/etc\/upnp\/upnp\.leases", "r"\)/);
assert.match(arrays, /case '<': ret \+= websWrite\(wp, "\\\\u003c"\)/);
assert.match(arrays, /case '>': ret \+= websWrite\(wp, "\\\\u003e"\)/);
assert.match(arrays, /case '\/': ret \+= websWrite\(wp, "\\\\\/"\)/);
assert.match(arrays, /case '"': ret \+= websWrite\(wp, "\\\\\\\""\)/);
assert.match(arrays, /websWriteJsonString\(wp, desc\)/);
assert.match(arrays, /websWriteJsonString\(wp, state\)/);
assert.match(arrays, /websWriteJsonString\(wp, name\)/);
assert.match(arrays, /websWriteJsonString\(wp, ratebps\)/);
assert.match(arrays, /websWriteJsonString\(wp, hostname\)/);
assert.match(arrays, /websWriteJsonString\(wp, ipaddrs\)/);
assert.match(arrays, /websWriteJsonString\(wp, addrbuf\)/);
assert.match(arrays, /int ej_connlist_array[\s\S]*?char output_path\[64\], redirect\[128\]/);
assert.match(sysinfo, /fopen\("\/proc\/net\/nf_conntrack", "r"\)/);
assert.match(web, /httpd_create_tempfile\(filename, sizeof\(filename\)\)/);

function encodeScriptString(value) {
  return `"${Array.from(value, (char) => {
    const code = char.charCodeAt(0);
    const escaped = {
      '"': '\\"',
      "\\": "\\\\",
      "/": "\\/",
      "<": "\\u003c",
      ">": "\\u003e",
      "&": "\\u0026",
      "\n": "\\n",
      "\r": "\\r",
      "\t": "\\t",
    }[char];
    if (escaped) return escaped;
    return code < 0x20 ? `\\u${code.toString(16).padStart(4, "0")}` : char;
  }).join("")}"`;
}

const payload = '</script><svg/onload=alert(1)>"\\\n';
const encoded = encodeScriptString(payload);
assert(!encoded.includes("</script>"));
assert(!encoded.includes("<svg"));
assert.doesNotThrow(() => JSON.parse(`[${encoded}]`));

console.log("httpd command-output security contracts passed");