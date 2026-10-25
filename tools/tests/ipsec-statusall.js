const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const web = fs.readFileSync(path.join(root, 'release/src/router/httpd/web.c'), 'utf8');
const parserStart = web.indexOf('get_ipsec_conn_info(struct json_object *ipsec_conn_obj');
const parserEnd = web.indexOf('\nstatic int\n', parserStart + 1);
const parser = web.slice(parserStart, parserEnd);

assert.match(parser, /ipsec_status_read_line\(p_fp, line, sizeof\(line\)\)/);
assert.match(parser, /ipsec_status_parse_peer\(line, ipaddr, sizeof\(ipaddr\), peer_identity, sizeof\(peer_identity\)\)/);
assert.doesNotMatch(parser, /fgets\(line, sizeof\(line\), p_fp\)|strncpy\(/);

const extractFunction = name => {
    const namePosition = web.indexOf(`${name}(`);
    const start = web.lastIndexOf('\n', namePosition) + 1;
    assert.notEqual(start, -1, `missing ${name}`);
    const open = web.indexOf('{', start);
    let depth = 0;
    for (let index = open; index < web.length; index++) {
        if (web[index] === '{') depth++;
        if (web[index] === '}' && --depth === 0) return web.slice(start, index + 1);
    }
    assert.fail(`unterminated ${name}`);
};

const helpers = ['ipsec_status_copy_span', 'ipsec_status_parse_peer', 'ipsec_status_read_line', 'ipsec_status_copy_value']
    .map(extractFunction).join('\n');
const harness = `
#include <assert.h>
#include <stdio.h>
#include <string.h>
${helpers}
int main(void)
{
    char address[16] = {0}, identity[33] = {0}, line[1024] = {0};
    char long_identity[401], oversized[601];
    FILE *stream;
    const char *valid = "Host-to-Netv2[1]: ESTABLISHED, 2 hours, 192.0.2.1[local]...198.51.100.7[peer]\\n";

    assert(ipsec_status_parse_peer(valid, address, sizeof(address), identity, sizeof(identity)));
    assert(strcmp(address, "198.51.100.7") == 0);
    assert(strcmp(identity, "peer") == 0);

    memset(long_identity, 'A', sizeof(long_identity) - 1);
    long_identity[sizeof(long_identity) - 1] = '\\0';
    snprintf(line, sizeof(line), "Host-to-Netv2[1]: CONNECTING, 1 second, 192.0.2.1[local]...198.51.100.7[%s]\\n", long_identity);
    assert(ipsec_status_parse_peer(line, address, sizeof(address), identity, sizeof(identity)));
    assert(strlen(identity) == sizeof(identity) - 1);

    snprintf(line, sizeof(line), "Host-to-Netv2[1]: CONNECTING, 1 second, 192.0.2.1[local]...198.51.100.7[%s[,]]\\n", long_identity);
    assert(!ipsec_status_parse_peer(line, address, sizeof(address), identity, sizeof(identity)));
    assert(!ipsec_status_parse_peer("Host-to-Netv2[1]: CONNECTING, x]", address, sizeof(address), identity, sizeof(identity)));
    assert(!ipsec_status_parse_peer("  Remote EAP identity: [1]: CONNECTING, 1 second, 192.0.2.1[local]...198.51.100.7[peer]\\n", address, sizeof(address), identity, sizeof(identity)));
    memset(line, 'B', 400);
    memcpy(line, "Remote XAuth identity: ", 23);
    line[400] = '\\n';
    line[401] = '\\0';
    ipsec_status_copy_value(identity, sizeof(identity), line, "Remote XAuth identity:");
    assert(strlen(identity) == sizeof(identity) - 1);

    memset(oversized, 'X', sizeof(oversized) - 1);
    memcpy(oversized + sizeof(oversized) - 1 - 10, "CONNECTING", 10);
    oversized[sizeof(oversized) - 1] = '\\n';
    stream = tmpfile();
    assert(stream != NULL);
    assert(fwrite(oversized, 1, sizeof(oversized), stream) == sizeof(oversized));
    assert(fwrite(valid, 1, strlen(valid), stream) == strlen(valid));
    rewind(stream);
    assert(ipsec_status_read_line(stream, line, 512) == -1);
    assert(line[0] == '\\0');
    assert(ipsec_status_read_line(stream, line, 512) == 1);
    assert(strcmp(line, valid) == 0);
    assert(ipsec_status_read_line(stream, line, 512) == 0);
    fclose(stream);
    return 0;
}
`;

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ipsec-statusall-'));
try {
    const sourcePath = path.join(tempDir, 'test.c');
    const binaryPath = path.join(tempDir, 'test');
    fs.writeFileSync(sourcePath, harness);
    const compile = spawnSync('cc', [
        '-std=c99', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined',
        '-fno-omit-frame-pointer', sourcePath, '-o', binaryPath
    ], { encoding: 'utf8' });
    assert.equal(compile.status, 0, compile.stderr || compile.stdout);
    const run = spawnSync(binaryPath, [], { encoding: 'utf8' });
    assert.equal(run.status, 0, run.stderr || run.stdout);
} finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
}

console.log('PASS: statusall peer parsing and overlong-line handling under ASan/UBSan');