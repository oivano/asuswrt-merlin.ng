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
#include <signal.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <time.h>

#include <bcmnvram.h>
#include <shutils.h>

#include "httpd.h"
#include "frr_web.h"
#include <json.h>

#define FRR_RUNNING_CONFIG_CMD  "show running-config"
#define FRR_BGP_SUMMARY_CMD     "show bgp summary json"
#define FRR_SHOW_IP_ROUTE_CMD   "show ip route json"
#define FRR_SHOW_IPV6_ROUTE_CMD "show ipv6 route json"
#define FRR_VTYSH_TIMEOUT_SEC 5
#define FRR_MAX_CAPTURE_SIZE 65536
#define FRR_VTYSH_RETRY_DELAY_SEC 5

struct frr_bgp_cache {
	char neighbors[512];
	char neighbor_as[512];
	char neighbor_desc[768];
	char neighbor_src[512];
	time_t ts;
	int valid;
};

static time_t frr_vtysh_backoff_until = 0;
static struct frr_bgp_cache frr_bgp_cache = {{0}, {0}, {0}, {0}, 0, 0};

struct frr_command_output {
	char *data;
	size_t len;
};

static const char *frr_vtysh_path(void)
{
	static const char *cached_path = NULL;
	static int checked = 0;
	static const char *const candidates[] = {
		"/usr/bin/vtysh",
		"/usr/sbin/vtysh",
		"/bin/vtysh",
		"/sbin/vtysh",
		"/usr/lib/frr/vtysh",
		NULL
	};
	int i;

	if (checked)
		return cached_path;

	for (i = 0; candidates[i] != NULL; i++) {
		if (access(candidates[i], X_OK) == 0) {
			cached_path = candidates[i];
			break;
		}
	}

	checked = 1;
	return cached_path;
}

static int frr_command_capture(const char *cmd, struct frr_command_output *output)
{
	int pipefd[2];
	int nullfd = -1;
	pid_t pid;
	int exit_code = -1;
	int wait_status;
	int sel;
	int timed_out = 0;
	fd_set rfds;
	struct timeval tv;
	char buffer[1024];
	ssize_t bytes_read;
	time_t deadline;
	const char *vtysh;
	char *const *argv;

	if (!cmd || !*cmd || !output)
		return 0;

	if (frr_vtysh_backoff_until > 0 && time(NULL) < frr_vtysh_backoff_until)
		return 0;

	vtysh = frr_vtysh_path();
	if (!vtysh)
		return 0;

	argv = (char *const[]){ (char *)vtysh, "-c", (char *)cmd, NULL };

	memset(output, 0, sizeof(*output));

	if (pipe(pipefd) != 0)
		return 0;

	pid = fork();
	if (pid < 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return 0;
	}

	if (pid == 0) {
		nullfd = open("/dev/null", O_WRONLY);
		if (nullfd >= 0) {
			dup2(nullfd, STDERR_FILENO);
			close(nullfd);
		}
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		execv(vtysh, argv);
		_exit(127);
	}

	close(pipefd[1]);
	deadline = time(NULL) + FRR_VTYSH_TIMEOUT_SEC;

	while (1) {
		time_t now = time(NULL);
		int remaining;

		if (now >= deadline) {
			timed_out = 1;
			break;
		}

		remaining = (int)(deadline - now);
		FD_ZERO(&rfds);
		FD_SET(pipefd[0], &rfds);
		tv.tv_sec = remaining;
		tv.tv_usec = 0;

		sel = select(pipefd[0] + 1, &rfds, NULL, NULL, &tv);
		if (sel < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (sel == 0) {
			timed_out = 1;
			break;
		}

		bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1);
		if (bytes_read < 0) {
			if (errno == EINTR)
				continue;
			break;
		}

		if (bytes_read == 0)
			break;

		if ((output->len + bytes_read) >= FRR_MAX_CAPTURE_SIZE)
			bytes_read = FRR_MAX_CAPTURE_SIZE - output->len - 1;

		if (bytes_read > 0) {
			char *new_buf = realloc(output->data, output->len + bytes_read + 1);
			if (!new_buf)
				break;

			output->data = new_buf;
			memcpy(output->data + output->len, buffer, bytes_read);
			output->len += bytes_read;
			output->data[output->len] = '\0';
		}

		if (output->len >= (FRR_MAX_CAPTURE_SIZE - 1))
			break;
	}

	close(pipefd[0]);

	if (timed_out) {
		kill(pid, SIGKILL);
		while (waitpid(pid, &wait_status, 0) < 0 && errno == EINTR)
			;
		free(output->data);
		output->data = NULL;
		output->len = 0;
		frr_vtysh_backoff_until = time(NULL) + FRR_VTYSH_RETRY_DELAY_SEC;
		return 0;
	}

	/*
	 * We read EOF from the pipe — the child has exited (that is the only way
	 * the write end closes).  Reap it now.  Handle ECHILD: httpd's own
	 * SIGCHLD handler may have already called waitpid() on this pid, which
	 * is a race that is impossible to avoid without blocking SIGCHLD around
	 * the entire fork/exec/read sequence.  If we get ECHILD but captured
	 * data, treat the exit as successful (exit code 0 synthesised).
	 */
	{
		pid_t rc;
		do {
			rc = waitpid(pid, &wait_status, 0);
		} while (rc < 0 && errno == EINTR);

		if (rc < 0) {
			if (errno == ECHILD && output->len > 0) {
				/* Already reaped by SIGCHLD handler; we have valid data. */
				wait_status = 0; /* synthesise normal exit 0 */
			} else {
				free(output->data);
				output->data = NULL;
				output->len = 0;
				frr_vtysh_backoff_until = time(NULL) + FRR_VTYSH_RETRY_DELAY_SEC;
				return 0;
			}
		}
	}

	if (WIFEXITED(wait_status))
		exit_code = WEXITSTATUS(wait_status);

	if (exit_code != 0) {
		free(output->data);
		output->data = NULL;
		output->len = 0;
		frr_vtysh_backoff_until = time(NULL) + FRR_VTYSH_RETRY_DELAY_SEC;
		return 0;
	}

	if (!output->data) {
		output->data = strdup("");
		if (!output->data)
			return 0;
	}

	frr_vtysh_backoff_until = 0;

	return 1;
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
	 * Route queries rely on zebra via vtysh. Some deployments can run
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
static int frr_write_route_origin_object(webs_t wp, const char *var_name, const char *cmd)
{
	struct frr_command_output output;
	json_object *root = NULL;
	int ret = 0;
	int first_prefix = 1;

	ret += websWrite(wp, "var %s = {\n", var_name);

	if (!frr_route_overlay_ready()) {
		ret += websWrite(wp, "};\n");
		return ret;
	}

	if (!frr_command_capture(cmd, &output)) {
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

static void frr_append_delimited(char *dst, size_t dst_len, const char *value)
{
	size_t used;
	size_t add;

	if (!dst || dst_len == 0 || !value || !*value)
		return;

	used = strlen(dst);
	if (used >= (dst_len - 1))
		return;

	if (used > 0) {
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

	if (!frr_command_capture(FRR_BGP_SUMMARY_CMD, &output))
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
		snprintf(asn_buf, sizeof(asn_buf), "%d", json_object_get_int(tmp));

		/* desc is optional */
		if (json_object_object_get_ex(peer_obj, "desc", &tmp))
			desc = json_object_get_string(tmp);

		frr_append_delimited(neighbors,     neighbors_len,     peer_ip);
		frr_append_delimited(neighbor_as,   neighbor_as_len,   asn_buf);
		frr_append_delimited(neighbor_desc, neighbor_desc_len, desc);
		frr_append_delimited(neighbor_src,  neighbor_src_len,  "");

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

	if (!frr_command_capture(FRR_BGP_SUMMARY_CMD, &output)) {
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

	if (!frr_command_capture(FRR_RUNNING_CONFIG_CMD, &output))
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
			while (*value && isspace((unsigned char)*value))
				value++;
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

	ret += websWrite(wp, "}\n");
	return ret;
}

/* ASP function: Get BGP configuration */
int ej_get_frr_bgp_config(int eid, webs_t wp, int argc, char_t **argv)
{
	char *bgp_enable = nvram_safe_get("frr_bgp_enable");
	char *bgp_as = nvram_safe_get("frr_bgp_as");
	char *bgp_neighbors = nvram_safe_get("frr_bgp_neighbor");
	char *bgp_neighbor_as = nvram_safe_get("frr_bgp_neighbor_as");
	int ret = 0;

	ret += websWrite(wp, "{\n");
	ret += websWrite(wp, "  \"enabled\": %d,\n", atoi(bgp_enable));
	ret += websWrite(wp, "  \"as_number\": \"%s\",\n", bgp_as);
	ret += websWrite(wp, "  \"neighbors\": \"%s\",\n", bgp_neighbors);
	ret += websWrite(wp, "  \"neighbor_as\": \"%s\"\n", bgp_neighbor_as);
	ret += websWrite(wp, "}\n");

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

	ret += websWrite(wp, "var frr_route_overlay_enabled = %d;\n", frr_route_overlay_ready() ? 1 : 0);
	ret += frr_write_route_origin_object(wp, "frr_route_origin_v4", FRR_SHOW_IP_ROUTE_CMD);
	ret += frr_write_route_origin_object(wp, "frr_route_origin_v6", FRR_SHOW_IPV6_ROUTE_CMD);

	return ret;
}
