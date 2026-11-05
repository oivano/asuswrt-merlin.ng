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
assert.match(dhcpText, /uint8_t clientid_buf\[130\];/);
assert.match(dhcpText, /if \(otype == DHCPV6_OPT_CLIENTID && olen <= 130\) \{\n\t\t\tdest\.clientid_length = htons\(olen\);\n\t\t\tmemcpy\(dest\.clientid_buf, odata, olen\);\n\t\t\tiov\[1\]\.iov_len = sizeof\(dest\) - sizeof\(dest\.clientid_buf\) \+ olen;/);
assert.doesNotMatch(dhcpText, /iov\[1\]\.iov_len\s*\+=\s*4\s*\+\s*olen/);
const clientReplySize = 152;
const clientIdCapacity = 130;
let replyLength = clientReplySize - clientIdCapacity;
for (const clientIdLength of [...Array(500).fill(0), 1, 10, clientIdCapacity]) {
	replyLength = clientReplySize - clientIdCapacity + clientIdLength;
	assert(replyLength <= clientReplySize, `CLIENTID length ${clientIdLength} exceeds reply struct`);
}
assert.equal(replyLength, clientReplySize, 'maximum CLIENTID reply fills but does not exceed struct');
replyLength = clientReplySize - clientIdCapacity;
for (let i = 0; i < 500; i++)
	replyLength = clientReplySize - clientIdCapacity;
assert.equal(replyLength, 22, '500 zero-length CLIENTIDs leave only header and one CLIENTID option');
assert.match(iaText, /static bool ia_interface_ready\([\s\S]*?iface->pd_assignments\.next \|\| !iface->pd_assignments\.prev \|\|\s*list_empty\(&iface->pd_assignments\)/);
assert.match(iaText, /list_for_each_entry\(a, &iface->pd_assignments, head\)\s*if \(!a->clid_len && a->length == 64\)/);
assert.match(iaText, /static void update\(struct relayd_interface \*iface\)\n\{\n\tif \(!ia_interface_ready\(iface\)\)\n\t\treturn;/);
assert.match(iaText, /size_t dhcpv6_handle_ia\([\s\S]*?\n\tif \(!ia_interface_ready\(iface\)\)\n\t\treturn 0;/);
assert.match(iaText, /uint8_t clid_data\[130\];[\s\S]*?if \(assign->clid_len > sizeof\(reconf_msg\.clid_data\)\)\n\t\treturn -1;[\s\S]*?memcpy\(reconf_msg\.clid_data, assign->clid_data, assign->clid_len\);[\s\S]*?sizeof\(reconf_msg\) - sizeof\(reconf_msg\.clid_data\) \+ assign->clid_len/);

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

static int address_prefix = 64;
static int routes_added;
static int routes_removed;

int fflags(int sock, int flags) { (void)flags; return sock; }
int relayd_register_event(struct relayd_event *e) { (void)e; return 0; }
ssize_t relayd_forward_packet(int s, struct sockaddr_in6 *d, struct iovec *iov, size_t n,
		const struct relayd_interface *i) { (void)s; (void)d; (void)iov; (void)n; (void)i; return 0; }
void relayd_urandom(void *data, size_t len) { memset(data, 0x5a, len); }
void relayd_setup_route(const struct in6_addr *a, int l, const struct relayd_interface *i,
		const struct in6_addr *gw, int m, bool add)
{
	(void)a; (void)l; (void)i; (void)gw; (void)m;
	if (add) ++routes_added;
	else ++routes_removed;
}
time_t relayd_monotonic_time(void) { return 1000; }
ssize_t relayd_get_interface_addresses(int ifindex, struct relayd_ipaddr *addrs, size_t cnt)
{
	(void)ifindex; (void)cnt;
	memset(addrs, 0, sizeof(*addrs));
	inet_pton(AF_INET6, "2001:db8:1:2::1", &addrs[0].addr);
	addrs[0].prefix = address_prefix;
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

static uint16_t run_pd(uint8_t msg_type, uint8_t prefix_len,
		struct relayd_interface *iface)
{
	uint8_t pkt[256] = {0}, reply[256] = {0};
	uint8_t *p = pkt;
	*p++ = msg_type; *p++ = 4; *p++ = 5; *p++ = prefix_len;
	const uint8_t duid[10] = {0, 3, 0, 1, 2, 4, 6, 8, 10, prefix_len};
	p = opt(p, DHCPV6_OPT_CLIENTID, duid, sizeof(duid));
	uint8_t ia_data[12 + sizeof(struct dhcpv6_ia_prefix)] = {0};
	uint32_t ia_hdr[3] = {htonl(0x2000 + prefix_len), 0, 0};
	memcpy(ia_data, ia_hdr, sizeof(ia_hdr));
	struct dhcpv6_ia_prefix prefix = {
		.type = htons(DHCPV6_OPT_IA_PREFIX),
		.len = htons(sizeof(prefix) - 4),
		.preferred = htonl(3600),
		.valid = htonl(7200),
		.prefix = prefix_len
	};
	inet_pton(AF_INET6, "0:0:0:1::", &prefix.addr);
	memcpy(ia_data + sizeof(ia_hdr), &prefix, sizeof(prefix));
	p = opt(p, DHCPV6_OPT_IA_PD, ia_data, sizeof(ia_data));
	struct sockaddr_in6 peer = {.sin6_family = AF_INET6};
	size_t len = dhcpv6_handle_ia(reply, sizeof(reply), iface, &peer, pkt, p);
	size_t offset = reply[0] == 0 && reply[1] == DHCPV6_OPT_RECONF_ACCEPT ? 4 : 0;
	if (len < offset + sizeof(struct dhcpv6_ia_hdr) + 4)
		return 0;
	uint16_t option_type;
	memcpy(&option_type, reply + offset + sizeof(struct dhcpv6_ia_hdr), sizeof(option_type));
	if (ntohs(option_type) != DHCPV6_OPT_STATUS ||
			len < offset + sizeof(struct dhcpv6_ia_hdr) + 6)
		return 0;
	uint16_t status;
	memcpy(&status, reply + offset + sizeof(struct dhcpv6_ia_hdr) + 4, sizeof(status));
	return ntohs(status);
}

static void run_reconf(struct relayd_interface *iface, uint8_t clid_len)
{
	struct assignment *a = calloc(1, sizeof(*a) + clid_len);
	a->peer.sin6_family = AF_INET6;
	a->clid_len = clid_len;
	memset(a->clid_data, 0x5a, clid_len);
	if (send_reconf(iface, a))
		exit(3);
	free(a);
}

int main(void)
{
	static struct relayd_config cfg;
	static struct relayd_interface slave = {.ifindex = 1, .ifname = "br0"};
	cfg.slaves = &slave;
	cfg.slavecount = 1;
	if (dhcpv6_init_ia(&cfg, -1))
		return 2;
	run_reconf(&slave, 128);
	run_reconf(&slave, 129);
	run_reconf(&slave, 130);

	size_t req = run(DHCPV6_MSG_REQUEST, 22, 30, &slave);
	size_t sol = run(DHCPV6_MSG_SOLICIT, 22, 30, &slave);
	size_t small = run(DHCPV6_MSG_REQUEST, 0, 1, &slave);
	size_t master = run(DHCPV6_MSG_SOLICIT, 1, 0, &cfg.master);
	int initial_adds = routes_added;
	for (uint8_t prefix_len = 1; prefix_len <= 64; ++prefix_len) {
		if (run_pd(DHCPV6_MSG_SOLICIT, prefix_len, &slave) != DHCPV6_STATUS_NOPREFIXAVAIL ||
				run_pd(DHCPV6_MSG_REQUEST, prefix_len, &slave) != DHCPV6_STATUS_NOPREFIXAVAIL ||
				routes_added != initial_adds)
			return 4;
	}

	address_prefix = 63;
	update(&slave);
	if (run_pd(DHCPV6_MSG_REQUEST, 63, &slave) != DHCPV6_STATUS_NOPREFIXAVAIL ||
			routes_added != initial_adds)
		return 9;
	if (run_pd(DHCPV6_MSG_SOLICIT, 64, &slave) != 0 || routes_added != initial_adds)
		return 5;
	reconf_timer(&reconf_event);
	if (routes_removed != 1)
		return 6;

	uint16_t request_status = run_pd(DHCPV6_MSG_REQUEST, 64, &slave);
	if (request_status != 0 || routes_added != initial_adds + 1) {
		fprintf(stderr, "request status=%u route adds=%d expected=%d\n",
				request_status, routes_added, initial_adds + 1);
		return 7;
	}
	dhcpv6_deinit_ia();
	if (routes_removed != 2)
		return 8;

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
