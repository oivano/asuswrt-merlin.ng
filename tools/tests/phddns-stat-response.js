const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = name => fs.readFileSync(path.join(root, 'release/src/router/phddns/src', name), 'latin1');
const update = source('phupdate.c');
const socket = source('phsocket.c');
const storage = fs.readFileSync(path.join(root, 'release/src/router/infosvr/storage.c'), 'utf8');
const hostnameCopy = storage.match(/snprintf\(st->u\.wt\.HostName,[^;]+;/)[0];
assert.match(hostnameCopy, /, "%s", nvram_safe_get\("ddns_hostname_x"\)\)/);

function func(text, signature) {
    const begin = text.indexOf(signature);
    assert(begin >= 0, `missing ${signature}`);
    let end = text.indexOf('{', begin) + 1;
    for (let depth = 1; depth; end++) {
        if (text[end] === '{') depth++;
        if (text[end] === '}') depth--;
        assert(end < text.length, 'balanced function body');
    }
    return text.slice(begin, end);
}

const executeBody = func(update, 'int ExecuteUpdate(');
assert.doesNotMatch(executeBody, /strncat\(xmldata/);
assert.doesNotMatch(executeBody, /buflen \+= MAX_PATH/);
assert.equal(executeBody.match(/xmldata = ReadStatResponse\(phglobal\);\s*if \(xmldata == NULL\)/g).length, 2);
const cap = Number(update.match(/#define PH_STAT_RESPONSE_MAX_LEN \((\d+) \* 1024\)/)[1]) * 1024;

const harness = `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#define MAX_PATH 260
#define PH_STAT_RESPONSE_MAX_LEN ${cap}
typedef struct { int m_tcpsocket; } PHGlobal;
${func(update, 'static int ValidRedirectHost(')}
${func(update, 'static int ValidDdnsHostname(')}
static const char *hostname;
static const char *nvram_safe_get(const char *key) { (void)key; return hostname; }
static int test_hostname(void)
{
	struct { struct { struct { char HostName[64]; } wt; } u; } status, *st = &status;
	const char *valid[] = { "router.example", "DDNS-1.Oray.NET", "router.example." };
	const char *invalid[] = { "", ".", "%n%n%s%s%x%x", "router%.net", "router\\\".net",
		"router'.net", "-router.net", "router-.net", "router..net", "router_net", "router net", "router\\xff.net" };
	char boundary[65];
	size_t index;
	for (index = 0; index < sizeof(valid) / sizeof(valid[0]); index++)
		if (!ValidDdnsHostname(valid[index])) return 20;
	for (index = 0; index < sizeof(invalid) / sizeof(invalid[0]); index++)
		if (ValidDdnsHostname(invalid[index])) return 21;
	memset(boundary, 'a', 63); boundary[63] = 0;
	if (!ValidDdnsHostname(boundary)) return 22;
	boundary[63] = 'a'; boundary[64] = 0;
	if (ValidDdnsHostname(boundary)) return 23;
	hostname = "%n%n%s%s%x%x";
	${hostnameCopy}
	if (strcmp(st->u.wt.HostName, hostname)) return 24;
	hostname = boundary;
	memset(&status, 0xa5, sizeof(status));
	${hostnameCopy}
	if (strlen(st->u.wt.HostName) != 63 || st->u.wt.HostName[63] != 0 ||
		memcmp(st->u.wt.HostName, boundary, 63)) return 25;
	return 0;
}
static int fail_realloc;
static void *test_realloc(void *p, size_t n) { return fail_realloc ? NULL : realloc(p, n); }
${func(socket, 'int phDataReadable(')}
${func(socket, 'int phReadOneLine(')}
#define realloc test_realloc
${func(update, 'static char *ReadStatResponse(')}
#undef realloc

static char *run(const char *data, size_t n)
{
	int sv[2];
	PHGlobal g;
	char *out;
	pid_t pid;
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) exit(2);
	pid = fork();
	if (pid == 0) {
		close(sv[0]);
		while (n) { ssize_t w = write(sv[1], data, n); if (w <= 0) _exit(0); data += w; n -= w; }
		_exit(0);
	}
	close(sv[1]);
	g.m_tcpsocket = sv[0];
	out = ReadStatResponse(&g);
	close(sv[0]);
	waitpid(pid, NULL, 0);
	return out;
}

static char *lines(int count, int width, const char *tail, size_t *n)
{
	size_t t = strlen(tail), i;
	char *p = malloc((size_t)count * (width + 1) + t), *q = p;
	for (i = 0; i < (size_t)count; i++) { memset(q, 'A' + i % 26, width); q[width] = '\\n'; q += width + 1; }
	memcpy(q, tail, t);
	*n = (size_t)count * (width + 1) + t;
	return p;
}

int main(void)
{
	char *in, *out;
	size_t n;
	int result = test_hostname();
	if (result) return result;

	in = lines(1, 1024, "", &n);
	n -= 1;
	out = run(in, n);
	if (!out || strlen(out) != 1024) return 10;
	free(out); free(in);

	in = lines(3, 1024, "tail\\r\\n.\\r\\n", &n);
	out = run(in, n);
	if (!out || strlen(out) != 3 * 1024 + 4 || strcmp(out + 3 * 1024, "tail")) return 11;
	free(out); free(in);

	n = (${cap} - 1) / 1023;
	in = lines((int)n, 1023, ".\\n", &n);
	out = run(in, n);
	if (!out || strlen(out) != ((${cap} - 1) / 1023) * 1023) return 12;
	free(out); free(in);

	in = lines(${cap} / 1023 + 1, 1023, ".\\n", &n);
	if (run(in, n)) return 13;
	free(in);

	out = run("ab\\0cd\\nef\\r\\n.\\r\\nignored\\n", 21);
	if (!out || strcmp(out, "abef")) return 14;
	free(out);

	out = run(".\\r\\n", 3);
	if (!out || out[0]) return 15;
	free(out);

	fail_realloc = 1;
	in = lines(2, 1000, ".\\n", &n);
	if (run(in, n)) return 16;
	free(in);
	return 0;
}
`;

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'phddns-stat-'));
try {
    const c = path.join(dir, 'harness.c');
    const bin = path.join(dir, 'harness');
    fs.writeFileSync(c, harness);
	execFileSync('cc', ['-std=gnu99', '-Wall', '-Wformat=2', '-Werror', '-g', '-fsanitize=address,undefined',
        '-fno-sanitize-recover=all', '-o', bin, c], { stdio: 'inherit' });
    execFileSync(bin, { stdio: 'inherit', env: { ...process.env, ASAN_OPTIONS: 'detect_leaks=1' } });
} finally {
    fs.rmSync(dir, { recursive: true, force: true });
}

console.log('phddns/infosvr: extracted hostname validators/copy and ReadStatResponse/phReadOneLine passed host ASan/UBSan and format-security checks');
console.log('Not a cross-compiled build, real Oray session, or hardware validation.');
