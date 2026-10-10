/*
 * frr_web.c - FRR WebUI Backend Functions
 * AsusWRT-Merlin FRR Integration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include <bcmnvram.h>
#include <shutils.h>
#include <shared.h>

#include "httpd.h"
#include "frr_web.h"
#include <json.h>
#include <frr_ui_config.h>

#define FRR_RUNNING_CONFIG_CMD  "show running-config"
#define FRR_BGP_SUMMARY_CMD     "show bgp summary json"
#define FRR_BFD_PEERS_CMD       "show bfd peers json"
#define FRR_SHOW_IP_ROUTE_CMD   "show ip route json"
#define FRR_SHOW_IPV6_ROUTE_CMD "show ipv6 route json"
#define FRR_MAX_CAPTURE_SIZE 524288
#define FRR_DAEMON_RETRY_DELAY_SEC 5
#define FRR_DAEMON_TIMEOUT_SEC 2

enum frr_vty_daemon {
	FRR_VTY_ZEBRA,
	FRR_VTY_BGPD,
	FRR_VTY_BFDD,
	FRR_VTY_COUNT
};

static const char *const frr_vty_sockets[FRR_VTY_COUNT] = {
	"/var/run/frr/zebra.vty",
	"/var/run/frr/bgpd.vty",
	"/var/run/frr/bfdd.vty"
};

struct frr_bgp_cache {
	char neighbors[512];
	char neighbor_as[512];
	char neighbor_desc[768];
	char neighbor_src[512];
	time_t ts;
	int valid;
};

static time_t frr_daemon_backoff_until[FRR_VTY_COUNT] = {0};
static struct frr_bgp_cache frr_bgp_cache = {{0}, {0}, {0}, {0}, 0, 0};

struct frr_command_output {
	char *data;
	size_t len;
};

static int frr_socket_wait(int fd, int writing, time_t deadline)
{
	fd_set fds;
	struct timeval tv;
	int result;
	time_t now;

	for (;;) {
		now = time(NULL);
		if (now >= deadline)
			return 0;
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		tv.tv_sec = deadline - now;
		tv.tv_usec = 0;
		result = select(fd + 1, writing ? NULL : &fds,
				writing ? &fds : NULL, NULL, &tv);
		if (result < 0 && errno == EINTR)
			continue;
		return result > 0;
	}
}

static int frr_daemon_capture(enum frr_vty_daemon daemon, const char *cmd,
			      struct frr_command_output *output)
{
	struct sockaddr_un address;
	time_t deadline;
	int fd = -1;
	int socket_error;
	int trailer_seen = 0;
	socklen_t error_len = sizeof(socket_error);
	size_t sent = 0;
	size_t used = 0;
	size_t capacity = 4096;
	size_t command_len;
	ssize_t count;
	char *terminator;
	char *new_data;
	const char *request;
	int enabling;

	if (!output)
		return 0;
	memset(output, 0, sizeof(*output));
	if (!cmd || (unsigned int)daemon >= FRR_VTY_COUNT)
		return 0;
	if (!((daemon == FRR_VTY_ZEBRA &&
	       (!strcmp(cmd, FRR_SHOW_IP_ROUTE_CMD) || !strcmp(cmd, FRR_SHOW_IPV6_ROUTE_CMD))) ||
	      (daemon == FRR_VTY_BGPD && !strcmp(cmd, FRR_BGP_SUMMARY_CMD)) ||
	      (daemon == FRR_VTY_BFDD && (!strcmp(cmd, FRR_RUNNING_CONFIG_CMD) || !strcmp(cmd, FRR_BFD_PEERS_CMD)))))
		return 0;
	if (time(NULL) < frr_daemon_backoff_until[daemon])
		return 0;

	deadline = time(NULL) + FRR_DAEMON_TIMEOUT_SEC;
	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		goto fail;
	if (fd >= FD_SETSIZE || fcntl(fd, F_SETFL, O_NONBLOCK) < 0 ||
	    fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
		goto fail;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strcpy(address.sun_path, frr_vty_sockets[daemon]);
	if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
		if (errno != EINPROGRESS || !frr_socket_wait(fd, 1, deadline))
			goto fail;
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_error, &error_len) < 0 ||
		    socket_error != 0)
			goto fail;
	}

	enabling = daemon == FRR_VTY_BFDD;
	request = enabling ? "enable" : cmd;
execute:
	command_len = strlen(request) + 1;
	while (sent < command_len) {
		if (!frr_socket_wait(fd, 1, deadline))
			goto fail;
		count = send(fd, request + sent, command_len - sent, MSG_NOSIGNAL);
		if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
			continue;
		if (count <= 0)
			goto fail;
		sent += count;
	}

	output->data = malloc(capacity);
	if (!output->data)
		goto fail;
	for (;;) {
		if (used == capacity) {
			if (capacity == FRR_MAX_CAPTURE_SIZE + 4)
				goto fail;
			capacity *= 2;
			if (capacity > FRR_MAX_CAPTURE_SIZE + 4)
				capacity = FRR_MAX_CAPTURE_SIZE + 4;
			new_data = realloc(output->data, capacity);
			if (!new_data)
				goto fail;
			output->data = new_data;
		}
		if (!frr_socket_wait(fd, 0, deadline))
			goto fail;
		count = recv(fd, output->data + used, capacity - used, 0);
		if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
			continue;
		if (count <= 0)
			goto fail;
		terminator = trailer_seen ? NULL : memchr(output->data + used, '\0', count);
		used += count;
		if (terminator) {
			output->len = terminator - output->data;
			trailer_seen = 1;
		}
		if (trailer_seen) {
			if (used - output->len < 4)
				continue;
			if (used - output->len != 4 || output->len >= FRR_MAX_CAPTURE_SIZE ||
			    memcmp(output->data + output->len, "\0\0\0\0", 4) != 0)
				goto fail;
			if (enabling) {
				free(output->data);
				memset(output, 0, sizeof(*output));
				sent = used = 0;
				capacity = 4096;
				trailer_seen = enabling = 0;
				request = cmd;
				goto execute;
			}
			close(fd);
			frr_daemon_backoff_until[daemon] = 0;
			return 1;
		}
	}

fail:
	if (fd >= 0)
		close(fd);
	free(output->data);
	memset(output, 0, sizeof(*output));
	frr_daemon_backoff_until[daemon] = time(NULL) + FRR_DAEMON_RETRY_DELAY_SEC;
	return 0;
}

static void frr_command_output_free(struct frr_command_output *output)
{
	if (!output)
		return;

	free(output->data);
	output->data = NULL;
	output->len = 0;
}

static int frr_route_overlay_ready(void)
{
	/*
	 * Route queries use zebra's native VTY socket. Some deployments can run
	 * zebra/bgpd without watchfrr supervision, so do not hard-require watchfrr.
	 */
	if (!frr_daemon_running("zebra"))
		return 0;

	return 1;
}

/*
 * Write a JS variable containing full FRR route origin data.
 *
 * Output: per-prefix array of route entries, one entry per nexthop.
 * Each entry carries: proto, active, nhactive, nexthop, iface,
 *                     dist, metric, age, aspath.
 *
 *   var frr_route_origin_v4 = {
 *   "0.0.0.0/0":[{"proto":"kernel","active":1,"nhactive":1,
 *                 "nexthop":"<gw>","iface":"<wan>",
 *                 "dist":0,"metric":0,"age":"HH:MM:SS","aspath":""}],
 *   "192.168.0.0/24":[{"proto":"bgp","active":1,"nhactive":1,
 *                      "nexthop":"<peer>","iface":"<lan>",
 *                      "dist":20,"metric":0,"age":"HH:MM:SS","aspath":"<ASN>"}],
 *   };
 *
 * Multiple entries per prefix represent ECMP nexthops or competing routes.
 * The JS table marks active (FIB-selected) routes with '+'.
 */
static int frr_write_route_origin_object(webs_t wp, const char *var_name, const char *cmd,
					 int *valid)
{
	struct frr_command_output output;
	json_object *root = NULL;
	int ret = 0;
	int first_prefix = 1;

	*valid = 0;
	ret += websWrite(wp, "var %s = {\n", var_name);

	if (!frr_route_overlay_ready()) {
		ret += websWrite(wp, "};\n");
		return ret;
	}

	if (!frr_daemon_capture(FRR_VTY_ZEBRA, cmd, &output)) {
		ret += websWrite(wp, "};\n");
		return ret;
	}

	root = json_tokener_parse(output.data);
	frr_command_output_free(&output);

	if (!root || !json_object_is_type(root, json_type_object)) {
		if (root) json_object_put(root);
		ret += websWrite(wp, "};\n");
		return ret;
	}

	*valid = 1;
	json_object_object_foreach(root, prefix_key, routes_arr) {
		int n, i, j;
		int wrote_entry = 0;

		if (!json_object_is_type(routes_arr, json_type_array))
			continue;

		n = json_object_array_length(routes_arr);
		if (n == 0)
			continue;

		if (!first_prefix)
			ret += websWrite(wp, ",\n");
		first_prefix = 0;

		ret += websWrite(wp, "\"%s\":[", prefix_key);

		/* Each element of the array is a route (protocol/nexthop combination) */
		for (i = 0; i < n; i++) {
			json_object *route_obj = json_object_array_get_idx(routes_arr, i);
			json_object *tmp;
			const char *proto = "kernel";
			const char *age = "";
			const char *aspath = "";
			int active = 0;
			int dist = 0;
			int metric = 0;

			if (!route_obj)
				continue;

			if (json_object_object_get_ex(route_obj, "protocol", &tmp))
				proto = json_object_get_string(tmp);
			if (json_object_object_get_ex(route_obj, "selected", &tmp))
				active = json_object_get_boolean(tmp) ? 1 : 0;
			if (json_object_object_get_ex(route_obj, "distance", &tmp))
				dist = json_object_get_int(tmp);
			if (json_object_object_get_ex(route_obj, "metric", &tmp))
				metric = json_object_get_int(tmp);
			if (json_object_object_get_ex(route_obj, "uptime", &tmp))
				age = json_object_get_string(tmp);
			if (json_object_object_get_ex(route_obj, "asPath", &tmp))
				aspath = json_object_get_string(tmp);

			/* Expand each nexthop into its own row for ECMP visibility */
			if (json_object_object_get_ex(route_obj, "nexthops", &tmp) &&
			    json_object_is_type(tmp, json_type_array)) {
				int nh_n = json_object_array_length(tmp);

				for (j = 0; j < nh_n; j++) {
					json_object *nh = json_object_array_get_idx(tmp, j);
					json_object *nh_val;
					const char *nh_ip = "";
					const char *nh_iface = "";
					int nh_active = 0;
					int direct = 0;

					if (!nh) continue;

					if (json_object_object_get_ex(nh, "ip", &nh_val))
						nh_ip = json_object_get_string(nh_val);
					if (json_object_object_get_ex(nh, "interfaceName", &nh_val))
						nh_iface = json_object_get_string(nh_val);
					if (json_object_object_get_ex(nh, "active", &nh_val))
						nh_active = json_object_get_boolean(nh_val) ? 1 : 0;
					if (json_object_object_get_ex(nh, "directlyConnected", &nh_val))
						direct = json_object_get_boolean(nh_val) ? 1 : 0;

					/* Skip recursive nexthops — the resolved FIB nexthop appears alongside */
					if (json_object_object_get_ex(nh, "recursive", &nh_val) &&
					    json_object_get_boolean(nh_val))
						continue;

					if (wrote_entry)
						ret += websWrite(wp, ",");

					ret += websWrite(wp,
						"{\"proto\":\"%s\",\"active\":%d,\"nhactive\":%d,"
						"\"nexthop\":\"%s\",\"direct\":%d,\"iface\":\"%s\","
						"\"dist\":%d,\"metric\":%d,\"age\":\"%s\",\"aspath\":\"%s\"}",
						proto, active, nh_active,
						nh_ip, direct, nh_iface,
						dist, metric, age, aspath);

					wrote_entry = 1;
				}
			}

			/* Handle routes without nexthop entries (e.g. blackhole) */
			if (!wrote_entry) {
				ret += websWrite(wp,
					"{\"proto\":\"%s\",\"active\":%d,\"nhactive\":%d,"
					"\"nexthop\":\"\",\"direct\":0,\"iface\":\"\","
					"\"dist\":%d,\"metric\":%d,\"age\":\"%s\",\"aspath\":\"%s\"}",
					proto, active, active,
					dist, metric, age, aspath);
				wrote_entry = 1;
			}
		}

		ret += websWrite(wp, "]");
	}

	if (!first_prefix)
		ret += websWrite(wp, "\n");

	json_object_put(root);
	ret += websWrite(wp, "};\n");
	return ret;
}

static void frr_append_delimited(char *dst, size_t dst_len, const char *value, int separator)
{
	size_t used;
	size_t add;

	if (!dst || dst_len == 0 || !value)
		return;

	used = strlen(dst);
	if (used >= (dst_len - 1))
		return;

	if (separator) {
		if (used + 1 >= dst_len)
			return;
		dst[used++] = '>';
		dst[used] = '\0';
	}

	add = strlen(value);
	if (used + add >= dst_len)
		add = dst_len - used - 1;

	memcpy(dst + used, value, add);
	dst[used + add] = '\0';
}

static int frr_has_list_value(const char *value)
{
	const char *p = value;

	if (!p)
		return 0;

	while (*p) {
		if (!isspace((unsigned char)*p) && *p != '>')
			return 1;
		p++;
	}

	return 0;
}

/*
 * Extract BGP peers from "show bgp summary json" via json-c.
 *
 * FRR 8.1 JSON structure:
 *   {"ipv4Unicast":{"peers":{"<peer-ip>":{"remoteAs":<ASN>,"desc":"<name>","state":"Established"}}}}
 *
 * All configured peers (including non-Established) are returned so the WebUI
 * shows the full configured neighbor list, not just active sessions.
 */
static int frr_extract_bgp_neighbors_from_conf(char *neighbors, size_t neighbors_len,
		char *neighbor_as, size_t neighbor_as_len,
		char *neighbor_desc, size_t neighbor_desc_len,
		char *neighbor_src, size_t neighbor_src_len)
{
	struct frr_command_output output;
	json_object *root = NULL;
	json_object *afi_obj = NULL;
	json_object *peers_obj = NULL;
	int found = 0;

	if (!neighbors || !neighbor_as || !neighbor_desc || !neighbor_src ||
	    neighbors_len == 0 || neighbor_as_len == 0 ||
	    neighbor_desc_len == 0 || neighbor_src_len == 0)
		return 0;

	neighbors[0] = '\0';
	neighbor_as[0] = '\0';
	neighbor_desc[0] = '\0';
	neighbor_src[0] = '\0';

	if (!frr_daemon_capture(FRR_VTY_BGPD, FRR_BGP_SUMMARY_CMD, &output))
		return 0;

	root = json_tokener_parse(output.data);
	frr_command_output_free(&output);

	if (!root || !json_object_is_type(root, json_type_object))
		goto out;

	/*
	 * FRR 8.1: top level has "ipv4Unicast" (and optionally "ipv6Unicast").
	 * We only need IPv4 for the peer list — the same peer IP appears in both
	 * address families; using only ipv4Unicast avoids duplicates.
	 */
	if (!json_object_object_get_ex(root, "ipv4Unicast", &afi_obj) ||
	    !json_object_is_type(afi_obj, json_type_object))
		goto out;

	if (!json_object_object_get_ex(afi_obj, "peers", &peers_obj) ||
	    !json_object_is_type(peers_obj, json_type_object))
		goto out;

	json_object_object_foreach(peers_obj, peer_ip, peer_obj) {
		json_object *tmp;
		char asn_buf[32];
		const char *desc = "";

		if (!json_object_is_type(peer_obj, json_type_object))
			continue;

		/* remoteAs is required */
		if (!json_object_object_get_ex(peer_obj, "remoteAs", &tmp))
			continue;
		snprintf(asn_buf, sizeof(asn_buf), "%llu",
			 (unsigned long long)json_object_get_int64(tmp));

		/* desc is optional */
		if (json_object_object_get_ex(peer_obj, "desc", &tmp))
			desc = json_object_get_string(tmp);

		frr_append_delimited(neighbors,     neighbors_len,     peer_ip, found);
		frr_append_delimited(neighbor_as,   neighbor_as_len,   asn_buf, found);
		frr_append_delimited(neighbor_desc, neighbor_desc_len, desc ? desc : "", found);
		frr_append_delimited(neighbor_src,  neighbor_src_len,  "", found);

		found = 1;
	}

out:
	if (root) json_object_put(root);
	return found;
}

static int frr_get_bgp_neighbors_cached(char *neighbors, size_t neighbors_len,
		char *neighbor_as, size_t neighbor_as_len,
		char *neighbor_desc, size_t neighbor_desc_len,
		char *neighbor_src, size_t neighbor_src_len)
{
	time_t now = time(NULL);

	if (frr_bgp_cache.valid && (now - frr_bgp_cache.ts) <= 2) {
		strlcpy(neighbors, frr_bgp_cache.neighbors, neighbors_len);
		strlcpy(neighbor_as, frr_bgp_cache.neighbor_as, neighbor_as_len);
		strlcpy(neighbor_desc, frr_bgp_cache.neighbor_desc, neighbor_desc_len);
		strlcpy(neighbor_src, frr_bgp_cache.neighbor_src, neighbor_src_len);
		return (neighbors[0] != '\0');
	}

	neighbors[0] = '\0';
	neighbor_as[0] = '\0';
	neighbor_desc[0] = '\0';
	neighbor_src[0] = '\0';

	if (!frr_extract_bgp_neighbors_from_conf(neighbors, neighbors_len,
	    neighbor_as, neighbor_as_len,
	    neighbor_desc, neighbor_desc_len,
	    neighbor_src, neighbor_src_len)) {
		frr_bgp_cache.valid = 0;
		return 0;
	}

	strlcpy(frr_bgp_cache.neighbors, neighbors, sizeof(frr_bgp_cache.neighbors));
	strlcpy(frr_bgp_cache.neighbor_as, neighbor_as, sizeof(frr_bgp_cache.neighbor_as));
	strlcpy(frr_bgp_cache.neighbor_desc, neighbor_desc, sizeof(frr_bgp_cache.neighbor_desc));
	strlcpy(frr_bgp_cache.neighbor_src, neighbor_src, sizeof(frr_bgp_cache.neighbor_src));
	frr_bgp_cache.ts = now;
	frr_bgp_cache.valid = 1;

	return 1;
}

static int frr_write_bgp_neighbor_status_map(webs_t wp)
{
	struct frr_command_output output;
	json_object *root = NULL;
	json_object *afi_obj = NULL;
	json_object *peers_obj = NULL;
	int ret = 0;
	int first = 1;

	ret += websWrite(wp, "{");

	if (!frr_daemon_running("bgpd")) {
		ret += websWrite(wp, "}");
		return ret;
	}

	if (!frr_daemon_capture(FRR_VTY_BGPD, FRR_BGP_SUMMARY_CMD, &output)) {
		ret += websWrite(wp, "}");
		return ret;
	}

	root = json_tokener_parse(output.data);
	frr_command_output_free(&output);

	if (!root || !json_object_is_type(root, json_type_object)) {
		if (root)
			json_object_put(root);
		ret += websWrite(wp, "}");
		return ret;
	}

	if (!json_object_object_get_ex(root, "ipv4Unicast", &afi_obj) ||
	    !json_object_is_type(afi_obj, json_type_object))
		goto out;

	if (!json_object_object_get_ex(afi_obj, "peers", &peers_obj) ||
	    !json_object_is_type(peers_obj, json_type_object))
		goto out;

	json_object_object_foreach(peers_obj, peer_ip, peer_obj) {
		json_object *tmp;
		const char *state = "Unknown";

		if (!json_object_is_type(peer_obj, json_type_object))
			continue;

		if (json_object_object_get_ex(peer_obj, "state", &tmp))
			state = json_object_get_string(tmp);

		if (!first)
			ret += websWrite(wp, ",");
		first = 0;
		ret += websWrite(wp, "\"%s\":\"%s\"", peer_ip, state ? state : "Unknown");
	}

out:
	json_object_put(root);
	ret += websWrite(wp, "}");
	return ret;
}

static int frr_write_bfd_peer_status(webs_t wp)
{
	struct frr_command_output output;
	json_object *root = NULL;
	json_object *map = json_object_new_object();
	size_t index;
	int ret;
	if (!map) return websWrite(wp, "{}");
	if (frr_daemon_running("bfdd") && frr_daemon_capture(FRR_VTY_BFDD, FRR_BFD_PEERS_CMD, &output)) {
		root = json_tokener_parse(output.data);
		frr_command_output_free(&output);
	}
	if (root && json_object_is_type(root, json_type_array)) {
		for (index = 0; index < json_object_array_length(root); index++) {
			json_object *peer = json_object_array_get_idx(root, index);
			const char *address = frr_ui_string(peer, "peer");
			if (*address) frr_ui_set(map, address, frr_ui_string(peer, "status"));
		}
	}
	ret = websWrite(wp, "%s", json_object_to_json_string_ext(map, JSON_C_TO_STRING_PLAIN));
	if (root) json_object_put(root);
	json_object_put(map);
	return ret;
}

static int frr_extract_bfd_config_from_conf(char *peer, size_t peer_len,
		char *tx, size_t tx_len,
		char *rx, size_t rx_len)
{
	char line[256];
	char *cursor;
	int in_bfd = 0;
	int found_peer = 0;
	struct frr_command_output output;

	if (!peer || !tx || !rx || peer_len == 0 || tx_len == 0 || rx_len == 0)
		return 0;

	peer[0] = '\0';
	tx[0] = '\0';
	rx[0] = '\0';

	if (!frr_daemon_capture(FRR_VTY_BFDD, FRR_RUNNING_CONFIG_CMD, &output))
		return 0;

	cursor = output.data;
	while (cursor && *cursor) {
		char *p = line;
		char *line_end = strchr(cursor, '\n');
		size_t line_len;

		if (line_end)
			line_len = line_end - cursor + 1;
		else
			line_len = strlen(cursor);

		if (line_len >= sizeof(line))
			line_len = sizeof(line) - 1;

		memcpy(line, cursor, line_len);
		line[line_len] = '\0';

		if (line_end)
			cursor = line_end + 1;
		else
			cursor += line_len;

		while (*p && isspace((unsigned char)*p))
			p++;

		line_len = strlen(p);
		while (line_len > 0 && isspace((unsigned char)p[line_len - 1]))
			p[--line_len] = '\0';

		if (!*p || *p == '\n' || *p == '\r')
			continue;

		if (*p == '!' || *p == '#') {
			if (in_bfd)
				break;
			continue;
		}

		if (!strcmp(p, "bfd")) {
			in_bfd = 1;
			continue;
		}

		if (!in_bfd)
			continue;

		if (!strncmp(p, "peer", 4) && isspace((unsigned char)p[4])) {
			char *value = p + 4;
			if (found_peer)
				break;
			while (*value && isspace((unsigned char)*value))
				value++;
			value[strcspn(value, " \t")] = '\0';
			strlcpy(peer, value, peer_len);
			found_peer = (*peer != '\0');
			continue;
		}

		if (!strncmp(p, "transmit-interval", 17) && isspace((unsigned char)p[17])) {
			char *value = p + 17;
			while (*value && isspace((unsigned char)*value))
				value++;
			strlcpy(tx, value, tx_len);
			continue;
		}

		if (!strncmp(p, "receive-interval", 16) && isspace((unsigned char)p[16])) {
			char *value = p + 16;
			while (*value && isspace((unsigned char)*value))
				value++;
			strlcpy(rx, value, rx_len);
			continue;
		}
	}

	frr_command_output_free(&output);
	return found_peer;
}

/* Check if a FRR daemon is running */
int frr_daemon_running(const char *daemon_name)
{
	char pid_file[128];
	FILE *fp;
	int pid;
	char proc_path[128];
	struct stat st;

	/* Construct PID file path */
	snprintf(pid_file, sizeof(pid_file), "/var/run/frr/%s.pid", daemon_name);

	/* Check if PID file exists */
	fp = fopen(pid_file, "r");
	if (!fp)
		return 0;

	/* Read PID from file */
	if (fscanf(fp, "%d", &pid) != 1) {
		fclose(fp);
		return 0;
	}
	fclose(fp);

	/* Check if process exists */
	snprintf(proc_path, sizeof(proc_path), "/proc/%d", pid);
	if (stat(proc_path, &st) == 0)
		return 1;

	return 0;
}

/* Get daemon uptime in seconds */
unsigned long frr_daemon_uptime(const char *daemon_name)
{
	char pid_file[128];
	struct stat st;
	time_t now;

	snprintf(pid_file, sizeof(pid_file), "/var/run/frr/%s.pid", daemon_name);

	if (stat(pid_file, &st) != 0)
		return 0;

	time(&now);
	return (unsigned long)(now - st.st_mtime);
}

/* ASP function: Get FRR enable status */
int ej_get_frr_enabled(int eid, webs_t wp, int argc, char_t **argv)
{
	int enabled = nvram_match("frr_enable", "1") ? 1 : 0;
	return websWrite(wp, "%d", enabled);
}

/* ASP function: Get FRR daemon status as JSON */
int ej_get_frr_daemon_status(int eid, webs_t wp, int argc, char_t **argv)
{
	int frr_enabled = nvram_match("frr_enable", "1");
	int ret = 0;

	ret += websWrite(wp, "{\n");
	ret += websWrite(wp, "  \"frr_enabled\": %d,\n", frr_enabled ? 1 : 0);

	if (frr_enabled) {
		ret += websWrite(wp, "  \"zebra_running\": %d,\n", frr_daemon_running("zebra"));
		ret += websWrite(wp, "  \"bgpd_running\": %d,\n", frr_daemon_running("bgpd"));
		ret += websWrite(wp, "  \"ospfd_running\": %d,\n", frr_daemon_running("ospfd"));
		ret += websWrite(wp, "  \"staticd_running\": %d,\n", frr_daemon_running("staticd"));
		ret += websWrite(wp, "  \"bfdd_running\": %d,\n", frr_daemon_running("bfdd"));
		ret += websWrite(wp, "  \"watchfrr_running\": %d,\n", frr_daemon_running("watchfrr"));
		ret += websWrite(wp, "  \"zebra_uptime\": %lu,\n", frr_daemon_uptime("zebra"));
		ret += websWrite(wp, "  \"timestamp\": %lu\n", (unsigned long)time(NULL));
	} else {
		ret += websWrite(wp, "  \"zebra_running\": 0,\n");
		ret += websWrite(wp, "  \"bgpd_running\": 0,\n");
		ret += websWrite(wp, "  \"ospfd_running\": 0,\n");
		ret += websWrite(wp, "  \"staticd_running\": 0,\n");
		ret += websWrite(wp, "  \"bfdd_running\": 0,\n");
		ret += websWrite(wp, "  \"watchfrr_running\": 0,\n");
		ret += websWrite(wp, "  \"timestamp\": %lu\n", (unsigned long)time(NULL));
	}

	ret += websWrite(wp, ",\n  \"bgp_peer_status\": ");
	ret += frr_enabled ? frr_write_bgp_neighbor_status_map(wp) : websWrite(wp, "{}");
	ret += websWrite(wp, ",\n  \"bfd_peer_status\": ");
	ret += frr_enabled ? frr_write_bfd_peer_status(wp) : websWrite(wp, "{}");
	ret += websWrite(wp, "}\n");
	return ret;
}

/* ASP function: Get BGP configuration */
int ej_get_frr_bgp_config(int eid, webs_t wp, int argc, char_t **argv)
{
	char directory[160];
	char path[192];
	char *data;
	char *daemons;
	size_t length;
	json_object *config;
	int ret;
	int read_error = 0;
	strlcpy(directory, nvram_safe_get("frr_config_dir"), sizeof(directory));
	if (!*directory || directory[0] != '/' || strstr(directory, ".."))
		strlcpy(directory, "/jffs/configs/frr", sizeof(directory));
	length = strlen(directory);
	while (length > 1 && (directory[length - 1] == '/' || directory[length - 1] == '.'))
		directory[--length] = '\0';
	if (!strcmp(directory, "/etc")) strlcpy(directory, "/jffs/configs/frr", sizeof(directory));
	snprintf(path, sizeof(path), "%s/frr.conf", directory);
	data = frr_ui_read_file(path);
	if (!data && errno == ENOENT) data = frr_ui_read_file("/etc/frr.conf");
	if (!data && errno != ENOENT) read_error = 1;
	config = frr_ui_parse(data ? data : "");
	if (!config) { free(data); return websWrite(wp, "{\"error\":\"FRR configuration could not be parsed\"}"); }
	json_object_object_add(config, "exists", json_object_new_boolean(data != NULL));
	if (read_error) frr_ui_set(config, "error", "FRR configuration could not be read safely");
	frr_ui_set(config, "frr_config_dir", directory);
	frr_ui_set(config, "frr_enable", nvram_safe_get("frr_enable"));
	snprintf(path, sizeof(path), "%s/daemons", directory);
	daemons = frr_ui_read_file(path);
	if (!daemons && errno == ENOENT) daemons = frr_ui_read_file("/etc/daemons");
	if (daemons) frr_ui_parse_daemons(config, daemons);
	else if (errno != ENOENT) frr_ui_set(config, "error", "FRR daemon configuration could not be read safely");
	ret = websWrite(wp, "%s", json_object_to_json_string_ext(config, JSON_C_TO_STRING_PLAIN));
	json_object_put(config);
	free(data);
	free(daemons);
	return ret;
}

int ej_get_frr_bgp_neighbor_list(int eid, webs_t wp, int argc, char_t **argv)
{
	char *bgp_neighbors = nvram_safe_get("frr_bgp_neighbor");
	char parsed_neighbors[512];
	char parsed_neighbor_as[512];
	char parsed_neighbor_desc[768];
	char parsed_neighbor_src[512];

	/* If NVRAM has configured neighbors, use them */
	if (frr_has_list_value(bgp_neighbors))
		return websWrite(wp, "%s", bgp_neighbors);

	/* If BGP daemon is running, try to extract runtime-discovered peers from running config */
	if (frr_daemon_running("bgpd")) {
		if (frr_get_bgp_neighbors_cached(parsed_neighbors, sizeof(parsed_neighbors),
		    parsed_neighbor_as, sizeof(parsed_neighbor_as),
		    parsed_neighbor_desc, sizeof(parsed_neighbor_desc),
		    parsed_neighbor_src, sizeof(parsed_neighbor_src)) > 0)
			return websWrite(wp, "%s", parsed_neighbors);
	}

	return 0;
}

int ej_get_frr_bgp_neighbor_as_list(int eid, webs_t wp, int argc, char_t **argv)
{
	char *bgp_neighbors = nvram_safe_get("frr_bgp_neighbor");
	char *bgp_neighbor_as = nvram_safe_get("frr_bgp_neighbor_as");
	char parsed_neighbors[512];
	char parsed_neighbor_as[512];
	char parsed_neighbor_desc[768];
	char parsed_neighbor_src[512];

	/*
	 * If NVRAM owns the neighbor list, stay in NVRAM for all fields.
	 * Never mix NVRAM neighbors with runtime AS numbers — mismatched
	 * counts corrupt the JS table.
	 */
	if (frr_has_list_value(bgp_neighbors))
		return frr_has_list_value(bgp_neighbor_as)
			? websWrite(wp, "%s", bgp_neighbor_as) : 0;

	/* Both lists come from runtime or neither does */
	if (frr_daemon_running("bgpd")) {
		if (frr_get_bgp_neighbors_cached(parsed_neighbors, sizeof(parsed_neighbors),
		    parsed_neighbor_as, sizeof(parsed_neighbor_as),
		    parsed_neighbor_desc, sizeof(parsed_neighbor_desc),
		    parsed_neighbor_src, sizeof(parsed_neighbor_src)) > 0)
			return websWrite(wp, "%s", parsed_neighbor_as);
	}

	return 0;
}

int ej_get_frr_bgp_neighbor_desc_list(int eid, webs_t wp, int argc, char_t **argv)
{
	char *bgp_neighbors = nvram_safe_get("frr_bgp_neighbor");
	char *bgp_neighbor_desc = nvram_safe_get("frr_bgp_neighbor_desc");
	char parsed_neighbors[512];
	char parsed_neighbor_as[512];
	char parsed_neighbor_desc[768];
	char parsed_neighbor_src[512];

	if (frr_has_list_value(bgp_neighbors))
		return frr_has_list_value(bgp_neighbor_desc)
			? websWrite(wp, "%s", bgp_neighbor_desc) : 0;

	if (frr_daemon_running("bgpd")) {
		if (frr_get_bgp_neighbors_cached(parsed_neighbors, sizeof(parsed_neighbors),
		    parsed_neighbor_as, sizeof(parsed_neighbor_as),
		    parsed_neighbor_desc, sizeof(parsed_neighbor_desc),
		    parsed_neighbor_src, sizeof(parsed_neighbor_src)) > 0)
			return websWrite(wp, "%s", parsed_neighbor_desc);
	}

	return 0;
}

int ej_get_frr_bgp_neighbor_src_list(int eid, webs_t wp, int argc, char_t **argv)
{
	char *bgp_neighbors = nvram_safe_get("frr_bgp_neighbor");
	char *bgp_neighbor_src = nvram_safe_get("frr_bgp_neighbor_src");
	char parsed_neighbors[512];
	char parsed_neighbor_as[512];
	char parsed_neighbor_desc[768];
	char parsed_neighbor_src[512];

	if (frr_has_list_value(bgp_neighbors))
		return frr_has_list_value(bgp_neighbor_src)
			? websWrite(wp, "%s", bgp_neighbor_src) : 0;

	if (frr_daemon_running("bgpd")) {
		if (frr_get_bgp_neighbors_cached(parsed_neighbors, sizeof(parsed_neighbors),
		    parsed_neighbor_as, sizeof(parsed_neighbor_as),
		    parsed_neighbor_desc, sizeof(parsed_neighbor_desc),
		    parsed_neighbor_src, sizeof(parsed_neighbor_src)) > 0)
			return websWrite(wp, "%s", parsed_neighbor_src);
	}

	return 0;
}

int ej_get_frr_bgp_neighbor_status_map(int eid, webs_t wp, int argc, char_t **argv)
{
	return frr_write_bgp_neighbor_status_map(wp);
}

/* ASP function: Get OSPF configuration */
int ej_get_frr_ospf_config(int eid, webs_t wp, int argc, char_t **argv)
{
	char *ospf_enable = nvram_safe_get("frr_ospf_enable");
	char *ospf_area = nvram_safe_get("frr_ospf_area");
	char *ospf_networks = nvram_safe_get("frr_ospf_networks");
	int ret = 0;

	ret += websWrite(wp, "{\n");
	ret += websWrite(wp, "  \"enabled\": %d,\n", atoi(ospf_enable));
	ret += websWrite(wp, "  \"area\": \"%s\",\n", ospf_area);
	ret += websWrite(wp, "  \"networks\": \"%s\"\n", ospf_networks);
	ret += websWrite(wp, "}\n");

	return ret;
}

/* ASP function: Get BFD configuration */
int ej_get_frr_bfd_config(int eid, webs_t wp, int argc, char_t **argv)
{
	char *bfd_enable = nvram_safe_get("frr_bfd_enable");
	char *bfd_peer = nvram_safe_get("frr_bfd_peer");
	char *bfd_tx = nvram_safe_get("frr_bfd_tx");
	char *bfd_rx = nvram_safe_get("frr_bfd_rx");
	char parsed_peer[64];
	char parsed_tx[16];
	char parsed_rx[16];
	const char *peer_value = bfd_peer;
	const char *tx_value = bfd_tx;
	const char *rx_value = bfd_rx;
	int ret = 0;

	parsed_peer[0] = '\0';
	parsed_tx[0] = '\0';
	parsed_rx[0] = '\0';

	if ((!*bfd_peer || !*bfd_tx || !*bfd_rx) &&
	    frr_extract_bfd_config_from_conf(parsed_peer, sizeof(parsed_peer),
	    parsed_tx, sizeof(parsed_tx), parsed_rx, sizeof(parsed_rx))) {
		if (!*bfd_peer && parsed_peer[0])
			peer_value = parsed_peer;
		if (!*bfd_tx && parsed_tx[0])
			tx_value = parsed_tx;
		if (!*bfd_rx && parsed_rx[0])
			rx_value = parsed_rx;
	}

	ret += websWrite(wp, "{\n");
	ret += websWrite(wp, "  \"enabled\": %d,\n", atoi(bfd_enable));
	ret += websWrite(wp, "  \"peer\": \"%s\",\n", peer_value);
	ret += websWrite(wp, "  \"tx\": \"%s\",\n", tx_value);
	ret += websWrite(wp, "  \"rx\": \"%s\"\n", rx_value);
	ret += websWrite(wp, "}\n");

	return ret;
}

int ej_get_frr_route_origin_array(int eid, webs_t wp, int argc, char_t **argv)
{
	int ret = 0;
	int valid_v4 = 0;
	int valid_v6 = 0;

	ret += frr_write_route_origin_object(wp, "frr_route_origin_v4", FRR_SHOW_IP_ROUTE_CMD, &valid_v4);
	ret += frr_write_route_origin_object(wp, "frr_route_origin_v6", FRR_SHOW_IPV6_ROUTE_CMD, &valid_v6);
	ret += websWrite(wp, "var frr_route_overlay_enabled = %d;\n", valid_v4 && valid_v6);

	return ret;
}
