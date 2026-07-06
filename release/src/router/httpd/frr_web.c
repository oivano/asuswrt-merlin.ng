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

#define FRR_RUNNING_CONFIG_CMD "show running-config"
#define FRR_SHOW_IP_ROUTE_CMD "show ip route"
#define FRR_SHOW_IPV6_ROUTE_CMD "show ipv6 route"
#define FRR_VTYSH_TIMEOUT_SEC 5
#define FRR_MAX_CAPTURE_SIZE 65536

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

		if (now >= deadline)
			break;

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
		waitpid(pid, &wait_status, 0);
		free(output->data);
		output->data = NULL;
		output->len = 0;
		return 0;
	}

	if (waitpid(pid, &wait_status, 0) < 0) {
		free(output->data);
		output->data = NULL;
		output->len = 0;
		return 0;
	}

	if (WIFEXITED(wait_status))
		exit_code = WEXITSTATUS(wait_status);

	if (exit_code != 0) {
		free(output->data);
		output->data = NULL;
		output->len = 0;
		return 0;
	}

	if (!output->data) {
		output->data = strdup("");
		if (!output->data)
			return 0;
	}

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
	if (!frr_daemon_running("watchfrr") || !frr_daemon_running("zebra"))
		return 0;

	return 1;
}

static const char *frr_route_proto_name(char code)
{
	switch (code) {
	case 'B':
		return "BGP";
	case 'O':
		return "OSPF";
	case 'R':
		return "RIP";
	case 'I':
		return "ISIS";
	case 'S':
		return "STATIC";
	case 'K':
		return "KERNEL";
	case 'C':
		return "CONNECTED";
	case 'L':
		return "LOCAL";
	default:
		return "DYNAMIC";
	}
}

static int frr_is_route_prefix_token(const char *token)
{
	if (!token || !*token)
		return 0;

	if (strcmp(token, "default") == 0)
		return 1;

	if (strchr(token, '/'))
		return 1;

	return 0;
}

static int frr_write_route_origin_object(webs_t wp, const char *var_name, const char *cmd)
{
	struct frr_command_output output;
	char line[512];
	char *cursor;
	char prefixes[256][64];
	char protos[256][16];
	int active_flags[256];
	int route_count = 0;
	int i;
	int ret = 0;

	ret += websWrite(wp, "var %s = {\n", var_name);

	if (!frr_route_overlay_ready()) {
		ret += websWrite(wp, "};\n");
		return ret;
	}

	if (!frr_command_capture(cmd, &output)) {
		ret += websWrite(wp, "};\n");
		return ret;
	}

	cursor = output.data;
	while (cursor && *cursor) {
		char *p = line;
		char *line_end = strchr(cursor, '\n');
		char *token_start;
		char *token_end;
		char *prefix;
		char *prefix_end;
		char code = '\0';
		int active = 0;
		const char *proto;
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

		if (strncmp(p, "Codes:", 6) == 0 || strncmp(p, "Gateway", 7) == 0)
			continue;

		prefix = NULL;
		while (*p) {
			while (*p && isspace((unsigned char)*p))
				p++;

			if (!*p || *p == '\n' || *p == '\r')
				break;

			token_start = p;
			while (*p && !isspace((unsigned char)*p) && *p != ',' && *p != '\n' && *p != '\r')
				p++;

			token_end = p;
			if (token_end == token_start)
				continue;

			/* Learn protocol code/flags from first marker token(s). */
			if (code == '\0') {
				char *q;
				for (q = token_start; q < token_end; q++) {
					if (isalpha((unsigned char)*q) && code == '\0')
						code = *q;
					if (*q == '>' || *q == '*')
						active = 1;
				}
			}

			/* Additional standalone flags like '*' can appear as separate token. */
			if ((token_end - token_start) == 1 &&
			    (token_start[0] == '>' || token_start[0] == '*')) {
				active = 1;
				continue;
			}

			if (frr_is_route_prefix_token(token_start)) {
				prefix = token_start;
				break;
			}
		}

		if (code == '\0' || !prefix)
			continue;

		prefix_end = p;
		*prefix_end = '\0';

		proto = frr_route_proto_name(code);

		for (i = 0; i < route_count; i++) {
			if (!strcmp(prefixes[i], prefix)) {
				if (active)
					active_flags[i] = 1;
				break;
			}
		}

		if (i < route_count)
			continue;

		if (route_count >= 256)
			continue;

		strlcpy(prefixes[route_count], prefix, sizeof(prefixes[route_count]));
		strlcpy(protos[route_count], proto, sizeof(protos[route_count]));
		active_flags[route_count] = active ? 1 : 0;
		route_count++;
	}

	frr_command_output_free(&output);

	for (i = 0; i < route_count; i++) {
		ret += websWrite(wp,
			"\"%s\":{\"proto\":\"%s\",\"active\":%d},\n",
			prefixes[i], protos[i], active_flags[i]);
	}

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

struct frr_neighbor_info {
	char ip[64];
	char asn[32];
	char desc[96];
	char src[64];
};

static int frr_find_neighbor(struct frr_neighbor_info *list, int count, const char *ip)
{
	int i;

	for (i = 0; i < count; i++) {
		if (!strcmp(list[i].ip, ip))
			return i;
	}

	return -1;
}

/* Parse active lines like: neighbor <ip> remote-as <asn>, description, update-source. */
static int frr_extract_bgp_neighbors_from_conf(char *neighbors, size_t neighbors_len,
		char *neighbor_as, size_t neighbor_as_len,
		char *neighbor_desc, size_t neighbor_desc_len,
		char *neighbor_src, size_t neighbor_src_len)
{
	char line[256];
	char *cursor;
	struct frr_neighbor_info entries[64];
	int entry_count = 0;
	int i;
	struct frr_command_output output;

	if (!neighbors || !neighbor_as || !neighbor_desc || !neighbor_src ||
	    neighbors_len == 0 || neighbor_as_len == 0 ||
	    neighbor_desc_len == 0 || neighbor_src_len == 0)
		return 0;

	neighbors[0] = '\0';
	neighbor_as[0] = '\0';
	neighbor_desc[0] = '\0';
	neighbor_src[0] = '\0';

	if (!frr_route_overlay_ready())
		return 0;

	if (!frr_command_capture(FRR_RUNNING_CONFIG_CMD, &output))
		return 0;

	cursor = output.data;
	while (cursor && *cursor) {
		char *p = line;
		char *line_end = strchr(cursor, '\n');
		char ip[64];
		char cmd[32];
		char val[96];
		int idx;
		int i;
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

		if (*p == '\0' || *p == '\n' || *p == '\r' || *p == '!' || *p == '#')
			continue;

		if (strncmp(p, "neighbor", 8) != 0 || !isspace((unsigned char)p[8]))
			continue;

		p += 8;
		while (*p && isspace((unsigned char)*p))
			p++;

		i = 0;
		while (*p && !isspace((unsigned char)*p) && i < (int)(sizeof(ip) - 1))
			ip[i++] = *p++;
		ip[i] = '\0';

		while (*p && isspace((unsigned char)*p))
			p++;

		i = 0;
		while (*p && !isspace((unsigned char)*p) && i < (int)(sizeof(cmd) - 1))
			cmd[i++] = *p++;
		cmd[i] = '\0';

		while (*p && isspace((unsigned char)*p))
			p++;

		if (!*cmd || !*p)
			continue;

		i = 0;
		while (*p && *p != '\n' && *p != '\r' && i < (int)(sizeof(val) - 1))
			val[i++] = *p++;
		val[i] = '\0';

		/* trim trailing spaces */
		for (i = strlen(val) - 1; i >= 0; i--) {
			if (!isspace((unsigned char)val[i]))
				break;
			val[i] = '\0';
		}

		if (!*ip)
			continue;

		idx = frr_find_neighbor(entries, entry_count, ip);
		if (idx < 0) {
			if (entry_count >= 64)
				continue;
			idx = entry_count++;
			memset(&entries[idx], 0, sizeof(entries[idx]));
			strlcpy(entries[idx].ip, ip, sizeof(entries[idx].ip));
		}

		if (!strcmp(cmd, "remote-as")) {
			char *v = val;
			i = 0;
			while (*v && !isspace((unsigned char)*v) && i < (int)(sizeof(entries[idx].asn) - 1))
				entries[idx].asn[i++] = *v++;
			entries[idx].asn[i] = '\0';
		}
		else if (!strcmp(cmd, "description")) {
			strlcpy(entries[idx].desc, val, sizeof(entries[idx].desc));
		}
		else if (!strcmp(cmd, "update-source")) {
			char *v = val;
			i = 0;
			while (*v && !isspace((unsigned char)*v) && i < (int)(sizeof(entries[idx].src) - 1))
				entries[idx].src[i++] = *v++;
			entries[idx].src[i] = '\0';
		}
	}

	frr_command_output_free(&output);

	for (i = 0; i < entry_count; i++) {
		if (!entries[i].asn[0])
			continue;

		frr_append_delimited(neighbors, neighbors_len, entries[i].ip);
		frr_append_delimited(neighbor_as, neighbor_as_len, entries[i].asn);
		frr_append_delimited(neighbor_desc, neighbor_desc_len, entries[i].desc);
		frr_append_delimited(neighbor_src, neighbor_src_len, entries[i].src);
	}

	return strlen(neighbors) > 0;
}

static int frr_bgp_runtime_ready(void)
{
	/*
	 * If FRR stack isn't healthy, avoid showing stale values from NVRAM
	 * or static config; UI should reflect current daemon status.
	 */
	if (!frr_daemon_running("watchfrr"))
		return 0;
	if (!frr_daemon_running("zebra"))
		return 0;
	if (!frr_daemon_running("bgpd"))
		return 0;

	return 1;
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

	if (!frr_bgp_runtime_ready())
		return 0;

	if (*bgp_neighbors)
		return websWrite(wp, "%s", bgp_neighbors);

	if (frr_extract_bgp_neighbors_from_conf(parsed_neighbors, sizeof(parsed_neighbors),
	    parsed_neighbor_as, sizeof(parsed_neighbor_as),
	    parsed_neighbor_desc, sizeof(parsed_neighbor_desc),
	    parsed_neighbor_src, sizeof(parsed_neighbor_src)) > 0)
		return websWrite(wp, "%s", parsed_neighbors);

	return 0;
}

int ej_get_frr_bgp_neighbor_as_list(int eid, webs_t wp, int argc, char_t **argv)
{
	char *bgp_neighbor_as = nvram_safe_get("frr_bgp_neighbor_as");
	char parsed_neighbors[512];
	char parsed_neighbor_as[512];
	char parsed_neighbor_desc[768];
	char parsed_neighbor_src[512];

	if (!frr_bgp_runtime_ready())
		return 0;

	if (*bgp_neighbor_as)
		return websWrite(wp, "%s", bgp_neighbor_as);

	if (frr_extract_bgp_neighbors_from_conf(parsed_neighbors, sizeof(parsed_neighbors),
	    parsed_neighbor_as, sizeof(parsed_neighbor_as),
	    parsed_neighbor_desc, sizeof(parsed_neighbor_desc),
	    parsed_neighbor_src, sizeof(parsed_neighbor_src)) > 0)
		return websWrite(wp, "%s", parsed_neighbor_as);

	return 0;
}

int ej_get_frr_bgp_neighbor_desc_list(int eid, webs_t wp, int argc, char_t **argv)
{
	char *bgp_neighbor_desc = nvram_safe_get("frr_bgp_neighbor_desc");
	char parsed_neighbors[512];
	char parsed_neighbor_as[512];
	char parsed_neighbor_desc[768];
	char parsed_neighbor_src[512];

	if (!frr_bgp_runtime_ready())
		return 0;

	if (*bgp_neighbor_desc)
		return websWrite(wp, "%s", bgp_neighbor_desc);

	if (frr_extract_bgp_neighbors_from_conf(parsed_neighbors, sizeof(parsed_neighbors),
	    parsed_neighbor_as, sizeof(parsed_neighbor_as),
	    parsed_neighbor_desc, sizeof(parsed_neighbor_desc),
	    parsed_neighbor_src, sizeof(parsed_neighbor_src)) > 0)
		return websWrite(wp, "%s", parsed_neighbor_desc);

	return 0;
}

int ej_get_frr_bgp_neighbor_src_list(int eid, webs_t wp, int argc, char_t **argv)
{
	char *bgp_neighbor_src = nvram_safe_get("frr_bgp_neighbor_src");
	char parsed_neighbors[512];
	char parsed_neighbor_as[512];
	char parsed_neighbor_desc[768];
	char parsed_neighbor_src[512];

	if (!frr_bgp_runtime_ready())
		return 0;

	if (*bgp_neighbor_src)
		return websWrite(wp, "%s", bgp_neighbor_src);

	if (frr_extract_bgp_neighbors_from_conf(parsed_neighbors, sizeof(parsed_neighbors),
	    parsed_neighbor_as, sizeof(parsed_neighbor_as),
	    parsed_neighbor_desc, sizeof(parsed_neighbor_desc),
	    parsed_neighbor_src, sizeof(parsed_neighbor_src)) > 0)
		return websWrite(wp, "%s", parsed_neighbor_src);

	return 0;
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
	int ret = 0;

	ret += websWrite(wp, "{\n");
	ret += websWrite(wp, "  \"enabled\": %d\n", atoi(bfd_enable));
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
