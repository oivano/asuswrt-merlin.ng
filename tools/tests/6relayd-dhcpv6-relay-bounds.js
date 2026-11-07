const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const srcDir = path.resolve(__dirname, '../../release/src/router/6relayd/src');
const harness = String.raw`
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "dhcpv6.c"

static unsigned int forwarded;
static uint8_t forwarded_packet[16384];
static size_t forwarded_len;

int relayd_register_event(struct relayd_event *event)
{
	(void)event;
	return 0;
}

ssize_t relayd_forward_packet(int socket, struct sockaddr_in6 *dest,
		struct iovec *iov, size_t iov_len, const struct relayd_interface *iface)
{
	(void)socket;
	(void)dest;
	(void)iface;
	++forwarded;
	forwarded_len = 0;
	for (size_t i = 0; i < iov_len; ++i) {
		if (iov[i].iov_len > sizeof(forwarded_packet) - forwarded_len)
			return -1;
		memcpy(forwarded_packet + forwarded_len, iov[i].iov_base, iov[i].iov_len);
		forwarded_len += iov[i].iov_len;
	}
	return forwarded_len;
}

ssize_t relayd_get_interface_addresses(int ifindex, struct relayd_ipaddr *addrs, size_t count)
{
	(void)ifindex;
	(void)count;
	memset(addrs, 0, sizeof(*addrs));
	inet_pton(AF_INET6, "2001:db8::1", &addrs[0].addr);
	return 1;
}

struct relayd_interface *relayd_get_interface_by_index(int ifindex)
{
	(void)ifindex;
	return NULL;
}

size_t dhcpv6_handle_ia(uint8_t *buf, size_t buflen, struct relayd_interface *iface,
		const struct sockaddr_in6 *addr, const void *data, const uint8_t *end)
{
	(void)buf;
	(void)buflen;
	(void)iface;
	(void)addr;
	(void)data;
	(void)end;
	return 0;
}

static size_t wrap_relay(uint8_t *out, const uint8_t *inner, size_t inner_len)
{
	memset(out, 0, sizeof(struct dhcpv6_relay_header));
	out[0] = DHCPV6_MSG_RELAY_FORW;
	out[34] = 0;
	out[35] = DHCPV6_OPT_RELAY_MSG;
	out[36] = inner_len >> 8;
	out[37] = inner_len;
	memcpy(out + 38, inner, inner_len);
	return 38 + inner_len;
}

int main(void)
{
	static struct relayd_config cfg;
	static struct relayd_interface slave;
	struct sockaddr_in6 peer = {.sin6_family = AF_INET6};
	uint8_t packet[8192] = {0};
	cfg.slaves = &slave;
	cfg.slavecount = 1;
	config = &cfg;

	packet[0] = DHCPV6_MSG_RELAY_FORW;
	packet[34] = 0;
	packet[35] = DHCPV6_OPT_RELAY_MSG;
	packet[36] = 0;
	packet[37] = 2;
	packet[38] = DHCPV6_MSG_RELAY_FORW;
	packet[39] = 0;
	packet[72] = 0;
	packet[73] = 1;
	packet[74] = 0xea;
	packet[75] = 0x60;
	handle_client_request(&peer, packet, sizeof(packet), &slave);
	if (forwarded)
		return 1;

	memset(packet, 0, sizeof(packet));
	packet[0] = DHCPV6_MSG_RELAY_FORW;
	packet[34] = 0;
	packet[35] = DHCPV6_OPT_RELAY_MSG;
	packet[36] = 0xff;
	packet[37] = 0xff;
	handle_client_request(&peer, packet, sizeof(packet), &slave);
	if (forwarded)
		return 3;

	uint8_t client[4] = {DHCPV6_MSG_SOLICIT, 0x12, 0x34, 0x56};
	uint8_t inner[128] = {0};
	uint8_t outer[256] = {0};
	size_t inner_len = wrap_relay(inner, client, sizeof(client));
	size_t outer_len = wrap_relay(outer, inner, inner_len);
	forwarded = 0;
	handle_client_request(&peer, outer, outer_len, &slave);
	if (forwarded != 1 || forwarded_len != 114 ||
			forwarded_packet[0] != DHCPV6_MSG_RELAY_REPL ||
			forwarded_packet[38] != DHCPV6_MSG_RELAY_REPL ||
			forwarded_packet[76] != DHCPV6_MSG_ADVERTISE ||
			forwarded_packet[36] != 0 || forwarded_packet[37] != 76 ||
			forwarded_packet[74] != 0 || forwarded_packet[75] != 38)
		return 2;

	return 0;
}
`;

const dir = fs.mkdtempSync(path.join(os.tmpdir(), '6relayd-relay-bounds-'));
try {
    const cFile = path.join(dir, 'harness.c');
    const exe = path.join(dir, 'harness');
    fs.writeFileSync(cFile, harness);
    execFileSync('cc', ['-std=gnu99', '-g', '-O1', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
        '-ffunction-sections', '-fdata-sections', '-Wl,--gc-sections', '-w', '-I', srcDir,
        cFile, '-lresolv', '-o', exe], { stdio: 'pipe' });
    const result = spawnSync(exe, [], { encoding: 'utf8', env: { ...process.env, ASAN_OPTIONS: 'detect_leaks=0' } });
    assert.equal(result.status, 0, `harness failed:\n${result.stdout}\n${result.stderr}`);
} finally {
    fs.rmSync(dir, { recursive: true, force: true });
}
console.log('6relayd DHCPv6 relay bounds: ok');