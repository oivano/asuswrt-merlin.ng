const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const srcDir = path.resolve(__dirname, '../../release/src/router/6relayd/src');
const iaSource = process.env.DHCPV6_IA_SOURCE || path.join(srcDir, 'dhcpv6-ia.c');
const iaText = fs.readFileSync(iaSource, 'utf8');
const dhcpText = fs.readFileSync(path.join(srcDir, 'dhcpv6.c'), 'utf8');

assert.match(dhcpText, /static bool is_configured_slave\([\s\S]*?iface == &config->slaves\[i\]/);
assert.match(dhcpText, /static void handle_client_request\([\s\S]*?\n\tif \(!is_configured_slave\(iface\) \|\| len < sizeof\(\*hdr\)\)/);
assert.match(iaText, /static bool ia_interface_ready\([\s\S]*?iface->pd_assignments\.next \|\| !iface->pd_assignments\.prev \|\|\s*list_empty\(&iface->pd_assignments\)/);
assert.match(iaText, /list_for_each_entry\(a, &iface->pd_assignments, head\)\s*if \(!a->clid_len && a->length == 64\)/);
assert.match(iaText, /static void update\(struct relayd_interface \*iface\)\n\{\n\tif \(!ia_interface_ready\(iface\)\)\n\t\treturn;/);
assert.match(iaText, /size_t dhcpv6_handle_ia\([\s\S]*?\n\tif \(!ia_interface_ready\(iface\)\)\n\t\treturn 0;/);

if (process.env.DHCPV6_IA_SOURCE_ONLY === '1') {
    console.log('6relayd DHCPv6 IA source guards: ok');
    process.exit(0);
}

const harness = String.raw`
#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/uio.h>
#include ${JSON.stringify(iaSource)}

int fflags(int sock, int flags) { (void)flags; return sock; }
int relayd_register_event(struct relayd_event *e) { (void)e; return 0; }
ssize_t relayd_forward_packet(int s, struct sockaddr_in6 *d, struct iovec *iov, size_t n,
		const struct relayd_interface *i) { (void)s; (void)d; (void)iov; (void)i; return n; }
void relayd_urandom(void *data, size_t len) { memset(data, 0x5a, len); }
void relayd_setup_route(const struct in6_addr *a, int l, const struct relayd_interface *i,
		const struct in6_addr *gw, int m, bool add) { (void)a; (void)l; (void)i; (void)gw; (void)m; (void)add; }
time_t relayd_monotonic_time(void) { return 1000; }
ssize_t relayd_get_interface_addresses(int ifindex, struct relayd_ipaddr *addrs, size_t cnt)
{
	(void)ifindex; (void)cnt;
	memset(addrs, 0, sizeof(*addrs));
	inet_pton(AF_INET6, "2001:db8:1:2::1", &addrs[0].addr);
	addrs[0].prefix = 64;
	addrs[0].preferred = 3600;
	addrs[0].valid = 7200;
	return 1;
}

static uint8_t *opt(uint8_t *p, uint16_t type, const void *data, uint16_t len)
{
	p[0] = type >> 8; p[1] = type; p[2] = len >> 8; p[3] = len;
	memcpy(p + 4, data, len);
	return p + 4 + len;
}

static size_t run(uint8_t msg_type, int pd_count, int na_count, struct relayd_interface *iface)
{
	static uint8_t pkt[4096];
	uint8_t *p = pkt;
	*p++ = msg_type; *p++ = 1; *p++ = 2; *p++ = 3;
	const uint8_t duid[10] = {0, 3, 0, 1, 2, 4, 6, 8, 10, msg_type};
	p = opt(p, DHCPV6_OPT_CLIENTID, duid, sizeof(duid));
	for (int i = 0; i < pd_count + na_count; ++i) {
		uint32_t ia[3] = {htonl(0x1000 + i), 0, 0};
		p = opt(p, i < pd_count ? DHCPV6_OPT_IA_PD : DHCPV6_OPT_IA_NA, ia, sizeof(ia));
	}

	uint8_t *buf = malloc(512);
	struct sockaddr_in6 peer = {.sin6_family = AF_INET6};
	size_t len = dhcpv6_handle_ia(buf, 512, iface, &peer, pkt, p);
	free(buf);
	return len;
}

int main(void)
{
	static struct relayd_config cfg;
	static struct relayd_interface slave = {.ifindex = 1, .ifname = "br0"};
	cfg.slaves = &slave;
	cfg.slavecount = 1;
	if (dhcpv6_init_ia(&cfg, -1))
		return 2;

	size_t req = run(DHCPV6_MSG_REQUEST, 22, 30, &slave);
	size_t sol = run(DHCPV6_MSG_SOLICIT, 22, 30, &slave);
	size_t small = run(DHCPV6_MSG_REQUEST, 0, 1, &slave);
	size_t master = run(DHCPV6_MSG_SOLICIT, 1, 0, &cfg.master);
	update(&cfg.master);
	memset(&slave.pd_assignments, 0, sizeof(slave.pd_assignments));
	size_t uninitialized = run(DHCPV6_MSG_SOLICIT, 1, 0, &slave);
	update(&slave);
	printf("%zu %zu %zu %zu %zu\n", req, sol, small, master, uninitialized);
	return req > 512 || sol > 512 || small <= 36 || master != 0 || uninitialized != 0;
}
`;

const dir = fs.mkdtempSync(path.join(os.tmpdir(), '6relayd-ia-'));
try {
    const cFile = path.join(dir, 'harness.c');
    const exe = path.join(dir, 'harness');
    fs.writeFileSync(cFile, harness);
    execFileSync('cc', ['-std=gnu99', '-g', '-O0', '-fsanitize=address', '-fno-omit-frame-pointer',
        '-w', '-I', srcDir, cFile, path.join(srcDir, 'md5.c'), '-o', exe], { stdio: 'pipe' });
    const result = spawnSync(exe, [], { encoding: 'utf8', env: { ...process.env, ASAN_OPTIONS: 'detect_leaks=0' } });
    assert.equal(result.status, 0, `harness failed:\n${result.stdout}\n${result.stderr}`);
    const [req, sol, small, master, uninitialized] = result.stdout.trim().split(/\s+/).map(Number);
    assert(req <= 512 && sol <= 512, 'reply exceeds pdbuf');
    assert(small > 36, 'normal REQUEST still carries the reconfigure handshake');
    assert.equal(master, 0, 'master interface must not receive IA processing');
    assert.equal(uninitialized, 0, 'uninitialized IA list must not receive IA processing');
} finally {
    fs.rmSync(dir, { recursive: true, force: true });
}
console.log('6relayd DHCPv6 IA reply bounds: ok');
