"use strict";

const assert = require("assert");
const fs = require("fs");
const path = require("path");

const sourcePath = path.join(__dirname, "../../release/src-rt-6.x.4708/linux/linux-2.6.36/fs/cifs/cifssmb.c");
const source = fs.readFileSync(sourcePath, "utf8");
const functionBody = source.match(/int CIFSFindNext\([\s\S]*?\n\{([\s\S]*?)\n\}/);

assert(functionBody, "CIFSFindNext definition must exist");
assert.match(functionBody[1], /unsigned int name_len;/);
assert.match(functionBody[1], /if \(name_len < PATH_MAX\) \{[\s\S]*?memcpy\(pSMB->ResumeFileName, psrch_inf->presume_name, name_len\);[\s\S]*?\} else \{\s*rc = -EINVAL;/);

const pathMax = 4096;
for (const length of [0x80000000, 0x80000010, 0xffffffff]) {
    assert((length | 0) < pathMax, "signed 32-bit conversion reproduces the vulnerable comparison");
    assert(!((length >>> 0) < pathMax), "unsigned 32-bit length must fail the PATH_MAX check");
}

for (const length of [0, 1, pathMax - 1]) {
    assert((length >>> 0) < pathMax, "valid bounded lengths remain accepted");
}

console.log("CIFS resume-name length signedness regression checks passed");