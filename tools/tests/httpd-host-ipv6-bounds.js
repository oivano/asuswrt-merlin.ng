'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/shared/misc.c'), 'utf8');
const start = source.indexOf('static unsigned int _parseDecimal (');
const end = source.indexOf('//simple version if we want', start);
assert.ok(start >= 0 && end > start, 'could not locate the address parser source');

const harness = String.raw`
#include <stddef.h>
#include <string.h>

${source.slice(start, end)}

static int rejected(const char *text)
{
	const char *cursor = text;
	unsigned char address[16] = {0};
	int is_ipv6 = 0;
	return ParseIPv4OrIPv6(&cursor, address, NULL, &is_ipv6) == 0;
}

int main(void)
{
	const char *text = "::ffff:1.2.3.4";
	const char *cursor = text;
	unsigned char address[16] = {0};
	int is_ipv6 = 0;
	if (!rejected("1:2:3:4:5:6:7:1.2.3.4"))
		return 1;
	if (!rejected("0:0:0:0:0:ffff:0:1.2.3.4"))
		return 2;
	if (!ParseIPv4OrIPv6(&cursor, address, NULL, &is_ipv6) || !is_ipv6 || *cursor)
		return 3;
	for (int i = 0; i < 10; ++i)
		if (address[i] != 0)
			return 4;
	if (address[10] != 0xff || address[11] != 0xff ||
		address[12] != 1 || address[13] != 2 || address[14] != 3 || address[15] != 4)
		return 5;
	return 0;
}
`;

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'httpd-host-ipv6-'));
const cFile = path.join(directory, 'parser.c');
const binary = path.join(directory, 'parser');
try {
    fs.writeFileSync(cFile, harness);
    const compile = spawnSync('cc', [
        '-std=gnu99', '-O1', '-g', '-fsanitize=address', '-fno-omit-frame-pointer',
        cFile, '-o', binary,
    ], { encoding: 'utf8' });
    assert.equal(compile.status, 0, `AddressSanitizer harness compilation failed:\n${compile.stderr}`);
    const run = spawnSync(binary, [], {
        encoding: 'utf8',
        env: { ...process.env, ASAN_OPTIONS: 'detect_leaks=0:abort_on_error=1' },
    });
    assert.equal(run.status, 0, `AddressSanitizer parser regression failed:\n${run.stderr}`);
} finally {
    fs.rmSync(directory, { recursive: true, force: true });
}

console.log('httpd Host IPv6 embedded-IPv4 bounds passed under AddressSanitizer');
