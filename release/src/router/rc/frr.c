/*
 * FRR (Free Range Routing) service control
 * Copyright (C) 2026 AsusWRT-Merlin
 */

#include "rc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <limits.h>
#include <pwd.h>
#include <grp.h>
#include <fcntl.h>

#define FRR_RUN_DIR		"/var/run/frr"
#define FRR_RUNTIME_CONFIG_DIR	"/etc"
#define FRR_CONFIG_DIR_DEFAULT	"/jffs/configs/frr"
#define FRR_SCRIPT		"/usr/sbin/frr"
#define FRR_INIT_SCRIPT		"/usr/sbin/frrinit.sh"
#define FRR_RUNTIME_DAEMONS	FRR_RUNTIME_CONFIG_DIR "/daemons"
#define FRR_RUNTIME_CONF	FRR_RUNTIME_CONFIG_DIR "/frr.conf"
#define FRR_DAEMON_USER		"nobody"
#define FRR_DAEMON_GROUP	"nobody"
#define FRR_STDERR_LOG_FILE	"/tmp/frr-start.stderr.log"

/*
 * These markers delimit protocol-specific WebUI-managed blocks inside frr.conf.
 * - Content between START and AUTO_END is auto-generated and will be replaced on UI Apply
 * - Content between AUTO_END and END is user hand-edits within the block (preserved unless force_regen=1)
 * - Everything outside markers is always preserved across UI applies
 */
#define FRR_BGP_BLOCK_START	"! ### ASUSWRT-MERLIN-BGP-START ###"
#define FRR_BGP_AUTO_END	"! ### ASUSWRT-MERLIN-BGP-AUTO-END ###"
#define FRR_BGP_BLOCK_END	"! ### ASUSWRT-MERLIN-BGP-END ###"

#define FRR_OSPF_BLOCK_START	"! ### ASUSWRT-MERLIN-OSPF-START ###"
#define FRR_OSPF_AUTO_END	"! ### ASUSWRT-MERLIN-OSPF-AUTO-END ###"
#define FRR_OSPF_BLOCK_END	"! ### ASUSWRT-MERLIN-OSPF-END ###"

#define FRR_BFD_BLOCK_START	"! ### ASUSWRT-MERLIN-BFD-START ###"
#define FRR_BFD_AUTO_END	"! ### ASUSWRT-MERLIN-BFD-AUTO-END ###"
#define FRR_BFD_BLOCK_END	"! ### ASUSWRT-MERLIN-BFD-END ###"

#define FRR_ACL_BLOCK_START	"! ### ASUSWRT-MERLIN-ACL-START ###"
#define FRR_ACL_AUTO_END	"! ### ASUSWRT-MERLIN-ACL-AUTO-END ###"
#define FRR_ACL_BLOCK_END	"! ### ASUSWRT-MERLIN-ACL-END ###"

static const char *frr_get_config_dir(char *buf, size_t len);

static int frr_exec_script_capture_stderr(const char *script, const char *action,
		const char *stderr_log, int append)
{
	int fd;
	pid_t pid;
	int status = 0;
	int flags = O_WRONLY | O_CREAT;

	if (!script || !*script || !action || !*action || !stderr_log || !*stderr_log)
		return -1;

	flags |= append ? O_APPEND : O_TRUNC;
	fd = open(stderr_log, flags, 0644);
	if (fd < 0)
		return -1;

	pid = fork();
	if (pid < 0) {
		close(fd);
		return -1;
	}

	if (pid == 0) {
		dup2(fd, STDERR_FILENO);
		close(fd);
		execl(script, script, action, (char *)NULL);
		_exit(127);
	}

	close(fd);

	if (waitpid(pid, &status, 0) < 0)
		return -1;

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	if (WIFSIGNALED(status))
		return 128 + WTERMSIG(status);

	return -1;
}

static void frr_log_captured_stderr(const char *stderr_log)
{
	FILE *fp;
	char line[256];
	int count = 0;

	if (!stderr_log || !*stderr_log || !f_exists(stderr_log))
		return;

	fp = fopen(stderr_log, "r");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp) != NULL) {
		size_t n = strlen(line);
		if (n > 0 && line[n - 1] == '\n')
			line[n - 1] = '\0';
		if (!line[0])
			continue;

		logmessage("FRR", "script stderr: %s", line);
		if (++count >= 50) {
			logmessage("FRR", "script stderr: ... truncated after 50 lines");
			break;
		}
	}

	fclose(fp);
}

static void frr_fix_run_dir_owner(void)
{
	struct passwd *pw;
	struct group *gr;
	uid_t uid;
	gid_t gid;

	pw = getpwnam(FRR_DAEMON_USER);
	if (!pw)
		return;

	uid = pw->pw_uid;
	gid = pw->pw_gid;

	gr = getgrnam(FRR_DAEMON_GROUP);
	if (gr)
		gid = gr->gr_gid;

	/* Keep best-effort: startup script still has fallback behavior. */
	if (chown(FRR_RUN_DIR, uid, gid) != 0)
		_dprintf("FRR: failed to chown %s to %s:%s\n", FRR_RUN_DIR, FRR_DAEMON_USER, FRR_DAEMON_GROUP);
}

static int frr_invoke_script(const char *action)
{
	char cfg_dir[PATH_MAX];
	char saved_cfg_dir[PATH_MAX];
	const char *old_cfg_dir;
	int had_old_cfg_dir = 0;
	int ret;

	if (!action || !*action)
		return -1;

	old_cfg_dir = getenv("FRR_CONFIG_DIR");
	if (old_cfg_dir && *old_cfg_dir) {
		strlcpy(saved_cfg_dir, old_cfg_dir, sizeof(saved_cfg_dir));
		had_old_cfg_dir = 1;
	}

	setenv("FRR_CONFIG_DIR", frr_get_config_dir(cfg_dir, sizeof(cfg_dir)), 1);

	/* Prefer the init script: /usr/sbin/frr can be a no-op on some targets. */
	if (f_exists(FRR_INIT_SCRIPT))
		ret = eval(FRR_INIT_SCRIPT, action);
	else if (f_exists(FRR_SCRIPT))
		ret = eval(FRR_SCRIPT, action);
	else {
		logmessage("FRR", "Init script not found: %s or %s", FRR_SCRIPT, FRR_INIT_SCRIPT);
		_dprintf("FRR init script not found: %s or %s\n", FRR_SCRIPT, FRR_INIT_SCRIPT);
		ret = -1;
	}

	if (had_old_cfg_dir)
		setenv("FRR_CONFIG_DIR", saved_cfg_dir, 1);
	else
		unsetenv("FRR_CONFIG_DIR");

	return ret;
}

static int frr_invoke_script_capture(const char *action, const char *stderr_log, int append)
{
	char cfg_dir[PATH_MAX];
	char saved_cfg_dir[PATH_MAX];
	const char *old_cfg_dir;
	int had_old_cfg_dir = 0;
	int ret;

	if (!action || !*action)
		return -1;

	old_cfg_dir = getenv("FRR_CONFIG_DIR");
	if (old_cfg_dir && *old_cfg_dir) {
		strlcpy(saved_cfg_dir, old_cfg_dir, sizeof(saved_cfg_dir));
		had_old_cfg_dir = 1;
	}

	setenv("FRR_CONFIG_DIR", frr_get_config_dir(cfg_dir, sizeof(cfg_dir)), 1);

	/* Prefer the init script: /usr/sbin/frr can be a no-op on some targets. */
	if (f_exists(FRR_INIT_SCRIPT))
		ret = frr_exec_script_capture_stderr(FRR_INIT_SCRIPT, action, stderr_log, append);
	else if (f_exists(FRR_SCRIPT))
		ret = frr_exec_script_capture_stderr(FRR_SCRIPT, action, stderr_log, append);
	else {
		logmessage("FRR", "Init script not found: %s or %s", FRR_SCRIPT, FRR_INIT_SCRIPT);
		_dprintf("FRR init script not found: %s or %s\n", FRR_SCRIPT, FRR_INIT_SCRIPT);
		ret = -1;
	}

	if (had_old_cfg_dir)
		setenv("FRR_CONFIG_DIR", saved_cfg_dir, 1);
	else
		unsetenv("FRR_CONFIG_DIR");

	return ret;
}

static void frr_force_stop_daemons(void)
{
	/* Last-resort stop path if init script cannot stop FRR stack. */
	logmessage("FRR", "Force-stopping FRR daemons (watchfrr/bgpd/ospfd/bfdd/staticd/zebra)");
	killall_tk("watchfrr");
	killall_tk("bgpd");
	killall_tk("ospfd");
	killall_tk("bfdd");
	killall_tk("staticd");
	killall_tk("zebra");
}

static const char *frr_get_config_dir(char *buf, size_t len)
{
	const char *cfg_dir;
	size_t n;

	if (!buf || len == 0)
		return FRR_CONFIG_DIR_DEFAULT;

	cfg_dir = nvram_safe_get("frr_config_dir");
	if (!cfg_dir || !*cfg_dir || cfg_dir[0] != '/' || strstr(cfg_dir, "..")) {
		strlcpy(buf, FRR_CONFIG_DIR_DEFAULT, len);
		return buf;
	}

	strlcpy(buf, cfg_dir, len);
	n = strlen(buf);
	while (n > 1 && (buf[n - 1] == '/' || buf[n - 1] == '.')) {
		/* Handle accidental trailing dot from UI/NVRAM path entry. */
		buf[n - 1] = '\0';
		n--;
	}

	if (!strcmp(buf, FRR_RUNTIME_CONFIG_DIR))
		strlcpy(buf, FRR_CONFIG_DIR_DEFAULT, len);

	return buf;
}

static void frr_get_config_paths(char *cfg_dir, size_t cfg_dir_len,
		char *daemons_path, size_t daemons_path_len,
		char *conf_path, size_t conf_path_len)
{
	frr_get_config_dir(cfg_dir, cfg_dir_len);
	snprintf(daemons_path, daemons_path_len, "%s/daemons", cfg_dir);
	snprintf(conf_path, conf_path_len, "%s/frr.conf", cfg_dir);
}

static int frr_copy_file(const char *src, const char *dst)
{
	FILE *in = NULL;
	FILE *out = NULL;
	char buf[1024];
	size_t n;
	int ok = 0;

	in = fopen(src, "r");
	if (!in)
		goto done;

	out = fopen(dst, "w");
	if (!out)
		goto done;

	while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
		if (fwrite(buf, 1, n, out) != n)
			goto done;
	}

	if (ferror(in))
		goto done;

	ok = 1;

done:
	if (out)
		fclose(out);
	if (in)
		fclose(in);

	return ok;
}

static int frr_should_regenerate_file(const char *path, int force_regen)
{
	struct stat st;

	if (force_regen)
		return 1;

	if (!path || !*path)
		return 1;

	return (stat(path, &st) != 0);
}

static void frr_sync_runtime_config(const char *cfg_dir,
		const char *daemons_path,
		const char *conf_path)
{
	if (!cfg_dir || !*cfg_dir)
		return;

	if (!strcmp(cfg_dir, FRR_RUNTIME_CONFIG_DIR))
		return;

	if (f_exists(daemons_path)) {
		if (frr_copy_file(daemons_path, FRR_RUNTIME_DAEMONS))
			chmod(FRR_RUNTIME_DAEMONS, 0644);
	}

	if (f_exists(conf_path)) {
		if (frr_copy_file(conf_path, FRR_RUNTIME_CONF))
			chmod(FRR_RUNTIME_CONF, 0644);
	}
}

/* Check if FRR is enabled in NVRAM */
static int is_frr_enabled(void)
{
	/* Check routing mode and FRR enable flag */
	if (!is_routing_enabled()) {
		_dprintf("FRR: Routing is not enabled\n");
		return 0;
	}
	
	return nvram_match("frr_enable", "1");
}

static int frr_should_defer_until_pppd(void)
{
	char prefix[] = "wanX_";
	int wan_unit;
	int wan_proto;

	for (wan_unit = WAN_UNIT_FIRST; wan_unit < WAN_UNIT_MAX; ++wan_unit) {
		prefix[3] = '0' + wan_unit;
		wan_proto = get_wan_proto(prefix);
		if (wan_proto == WAN_PPPOE || wan_proto == WAN_PPTP || wan_proto == WAN_L2TP) {
			if (pidof("pppd") <= 0)
				return 1;
			return 0;
		}
	}

	return 0;
}

/* Create necessary directories */
static void frr_create_dirs(void)
{
	char cfg_dir[PATH_MAX];

	frr_get_config_dir(cfg_dir, sizeof(cfg_dir));

	mkdir_if_none(FRR_RUN_DIR);
	mkdir_if_none(cfg_dir);
	frr_fix_run_dir_owner();
	
	/* Set permissions */
	chmod(FRR_RUN_DIR, 0755);
	chmod(cfg_dir, 0755);
}

/*
 * Write the auto-generated BGP configuration block.
 * Content between START and AUTO_END is replaced on every UI Apply.
 * User can add custom BGP config after AUTO_END, within the block.
 */
static void frr_write_bgp_block(FILE *fp, const char *lan_ip)
{
	fprintf(fp, "%s\n", FRR_BGP_BLOCK_START);
	fprintf(fp, "!\n");

	if (nvram_match("frr_bgp_enable", "1")) {
		char *bgp_as        = nvram_safe_get("frr_bgp_as");
		char *bgp_neighbor  = nvram_safe_get("frr_bgp_neighbor");
		char *bgp_neighbor_as   = nvram_safe_get("frr_bgp_neighbor_as");
		char *bgp_neighbor_desc = nvram_safe_get("frr_bgp_neighbor_desc");
		char *bgp_networks  = nvram_safe_get("frr_bgp_networks");

		if (*bgp_as) {
			char *neighbor_list = NULL, *neighbor_as_list = NULL;
			char *neighbor_desc_list = NULL, *activate_list = NULL;

			fprintf(fp, "router bgp %s\n", bgp_as);
			fprintf(fp, " bgp router-id %s\n", lan_ip);

			if (*bgp_neighbor && *bgp_neighbor_as) {
				char *n_cur, *a_cur, *d_cur;
				char *tok_ip, *tok_as, *tok_desc;

				fprintf(fp, " !\n");
				neighbor_list      = strdup(bgp_neighbor);
				neighbor_as_list   = strdup(bgp_neighbor_as);
				neighbor_desc_list = strdup(bgp_neighbor_desc);

				if (neighbor_list && neighbor_as_list) {
					n_cur = neighbor_list;
					a_cur = neighbor_as_list;
					d_cur = neighbor_desc_list;

					while ((tok_ip = strsep(&n_cur, ">")) != NULL &&
					       (tok_as = strsep(&a_cur, ">")) != NULL) {
						tok_desc = d_cur ? strsep(&d_cur, ">") : NULL;
						if (!*tok_ip || !*tok_as)
							continue;
						fprintf(fp, " neighbor %s remote-as %s\n", tok_ip, tok_as);
						if (tok_desc && *tok_desc)
							fprintf(fp, " neighbor %s description %s\n", tok_ip, tok_desc);
					}
				}

				fprintf(fp, " !\n");
				fprintf(fp, " address-family ipv4 unicast\n");

				if (*bgp_networks) {
					char *netlist = strdup(bgp_networks);
					char *nc = netlist, *net;
					while (nc && (net = strsep(&nc, " \t\r\n")) != NULL) {
						if (*net) fprintf(fp, "  network %s\n", net);
					}
					free(netlist);
				}

				activate_list = strdup(bgp_neighbor);
				if (activate_list) {
					char *ac = activate_list, *aip;
					while ((aip = strsep(&ac, ">")) != NULL) {
						if (*aip) fprintf(fp, "  neighbor %s activate\n", aip);
					}
					free(activate_list);
				}

				fprintf(fp, " exit-address-family\n");
				free(neighbor_list);
				free(neighbor_as_list);
				free(neighbor_desc_list);
			}
			fprintf(fp, "!\n");
		}
	}

	fprintf(fp, "%s\n", FRR_BGP_AUTO_END);
	fprintf(fp, "! User custom BGP config can be added here\n");
	fprintf(fp, "%s\n", FRR_BGP_BLOCK_END);
	fprintf(fp, "!\n");
}

/*
 * Write the auto-generated OSPF configuration block.
 */
static void frr_write_ospf_block(FILE *fp, const char *lan_ip, const char *wan_if)
{
	fprintf(fp, "%s\n", FRR_OSPF_BLOCK_START);
	fprintf(fp, "!\n");

	if (nvram_match("frr_ospf_enable", "1")) {
		char *ospf_area     = nvram_safe_get("frr_ospf_area");
		char *ospf_networks = nvram_safe_get("frr_ospf_networks");

		if (!*ospf_area) ospf_area = "0";

		fprintf(fp, "router ospf\n");
		fprintf(fp, " ospf router-id %s\n", lan_ip);
		fprintf(fp, " log-adjacency-changes\n");
		fprintf(fp, " !\n");

		if (*ospf_networks) {
			char *nl = strdup(ospf_networks), *nc = nl, *net;
			while (nc && (net = strsep(&nc, " \t\r\n>")) != NULL) {
				if (*net) fprintf(fp, " network %s area %s\n", net, ospf_area);
			}
			free(nl);
		} else {
			fprintf(fp, " network 0.0.0.0/0 area %s\n", ospf_area);
		}

		fprintf(fp, " !\n");
#if !defined(BLUECAVE)
		fprintf(fp, " passive-interface vlan2\n");
		fprintf(fp, " passive-interface vlan3\n");
#else
		fprintf(fp, " passive-interface eth1.2\n");
		fprintf(fp, " passive-interface eth1.3\n");
#endif
		if (wan_if && *wan_if)
			fprintf(fp, " passive-interface %s\n", wan_if);
		fprintf(fp, "!\n");
	}

	fprintf(fp, "%s\n", FRR_OSPF_AUTO_END);
	fprintf(fp, "! User custom OSPF config can be added here\n");
	fprintf(fp, "%s\n", FRR_OSPF_BLOCK_END);
	fprintf(fp, "!\n");
}

/*
 * Write the auto-generated BFD configuration block.
 */
static void frr_write_bfd_block(FILE *fp)
{
	fprintf(fp, "%s\n", FRR_BFD_BLOCK_START);
	fprintf(fp, "!\n");

	if (nvram_match("frr_bfd_enable", "1")) {
		char *bfd_peer = nvram_safe_get("frr_bfd_peer");
		char *bfd_tx   = nvram_safe_get("frr_bfd_tx");
		char *bfd_rx   = nvram_safe_get("frr_bfd_rx");

		fprintf(fp, "bfd\n");
		if (*bfd_peer) {
			int tx_ms = atoi(bfd_tx);
			int rx_ms = atoi(bfd_rx);
			fprintf(fp, " peer %s\n", bfd_peer);
			if (rx_ms > 0 && rx_ms != 300)
				fprintf(fp, "  receive-interval %d\n", rx_ms);
			if (tx_ms > 0 && tx_ms != 300)
				fprintf(fp, "  transmit-interval %d\n", tx_ms);
			fprintf(fp, " !\n");
		}
		fprintf(fp, "!\n");
	}

	fprintf(fp, "%s\n", FRR_BFD_AUTO_END);
	fprintf(fp, "! User custom BFD config can be added here\n");
	fprintf(fp, "%s\n", FRR_BFD_BLOCK_END);
	fprintf(fp, "!\n");
}

/*
 * Write the auto-generated ACL and line vty configuration block.
 */
static void frr_write_acl_block(FILE *fp)
{
	fprintf(fp, "%s\n", FRR_ACL_BLOCK_START);
	fprintf(fp, "!\n");
	fprintf(fp, "access-list vty permit 127.0.0.0/8\n");
	if (nvram_match("frr_allow_lan", "1")) {
		char *lip = nvram_safe_get("lan_ipaddr");
		char *lnm = nvram_safe_get("lan_netmask");
		if (*lip && *lnm)
			fprintf(fp, "access-list vty permit %s/%s\n", lip, lnm);
	}
	fprintf(fp, "access-list vty deny any\n");
	fprintf(fp, "line vty\n");
	fprintf(fp, " access-class vty\n");
	fprintf(fp, " exec-timeout 0 0\n");
	fprintf(fp, "!\n");
	fprintf(fp, "%s\n", FRR_ACL_AUTO_END);
	fprintf(fp, "! User custom ACL rules can be added here\n");
	fprintf(fp, "%s\n", FRR_ACL_BLOCK_END);
	fprintf(fp, "!\n");
}

/*
 * Merge multi-block UI-managed sections into conf_path.
 *
 * Protocol blocks (BGP, OSPF, BFD, ACL) each have three sections:
 * - START marker: beginning of block
 * - AUTO_END marker: end of auto-generated section
 * - END marker: end of block
 *
 * On normal Apply (force_regen=0):
 *   - Replace auto-generated section (between START and AUTO_END)
 *   - Preserve user additions (between AUTO_END and END)
 * On Force Regen (force_regen=1):
 *   - Replace entire block (between START and END)
 * If block doesn't exist:
 *   - Append new block
 *
 * Everything outside blocks is always preserved.
 */
static void frr_merge_ui_into_conf(const char *conf_path,
		const char *lan_ip, const char *wan_if,
		const char *frr_passwd, const char *frr_enpasswd,
		const char *hostname, int force_regen)
{
	FILE *fp;
	char *buf = NULL;
	long fsize;

	fp = fopen(conf_path, "r");
	if (!fp) {
		/* File does not exist — create from scratch */
		fp = fopen(conf_path, "w");
		if (!fp) return;
		fprintf(fp, "!\n! FRR configuration — managed by AsusWRT-Merlin WebUI\n");
		fprintf(fp, "! Blocks marked with ###ASUSWRT-MERLIN-*-START/END### are UI-managed\n");
		fprintf(fp, "! User additions within blocks after ###-AUTO-END### are preserved\n");
		fprintf(fp, "!\n");
		fprintf(fp, "frr version 8.1\n");
		fprintf(fp, "frr defaults traditional\n");
		fprintf(fp, "hostname %s\n", hostname);
		fprintf(fp, "password %s\n", frr_passwd);
		fprintf(fp, "enable password %s\n", frr_enpasswd);
		fprintf(fp, "!\n");
		fprintf(fp, "log syslog informational\n");
		fprintf(fp, "!\n");
		fprintf(fp, "service integrated-vtysh-config\n");
		fprintf(fp, "!\n");
		frr_write_bgp_block(fp, lan_ip);
		frr_write_ospf_block(fp, lan_ip, wan_if);
		frr_write_bfd_block(fp);
		frr_write_acl_block(fp);
		append_custom_config("frr.conf", fp);
		fclose(fp);
		chmod(conf_path, 0644);
		return;
	}

	/* Read entire existing file */
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	rewind(fp);

	if (fsize > 0)
		buf = malloc(fsize + 1);

	if (!buf || fsize <= 0 || (long)fread(buf, 1, fsize, fp) != fsize) {
		fclose(fp);
		free(buf);
		/* Fall back to creating fresh file */
		fp = fopen(conf_path, "w");
		if (!fp) return;
		fprintf(fp, "!\n! FRR configuration — managed by AsusWRT-Merlin WebUI\n");
		fprintf(fp, "! Blocks marked with ###ASUSWRT-MERLIN-*-START/END### are UI-managed\n");
		fprintf(fp, "! User additions within blocks after ###-AUTO-END### are preserved\n");
		fprintf(fp, "!\n");
		fprintf(fp, "frr version 8.1\n");
		fprintf(fp, "frr defaults traditional\n");
		fprintf(fp, "hostname %s\n", hostname);
		fprintf(fp, "password %s\n", frr_passwd);
		fprintf(fp, "enable password %s\n", frr_enpasswd);
		fprintf(fp, "!\n");
		fprintf(fp, "log syslog informational\n");
		fprintf(fp, "!\n");
		fprintf(fp, "service integrated-vtysh-config\n");
		fprintf(fp, "!\n");
		frr_write_bgp_block(fp, lan_ip);
		frr_write_ospf_block(fp, lan_ip, wan_if);
		frr_write_bfd_block(fp);
		frr_write_acl_block(fp);
		append_custom_config("frr.conf", fp);
		fclose(fp);
		chmod(conf_path, 0644);
		return;
	}

	fclose(fp);
	buf[fsize] = '\0';

	/* For simplicity and robustness, rewrite the entire file from scratch,
	 * but preserve user additions within blocks (after AUTO_END markers)
	 * and everything outside blocks.
	 *
	 * Strategy: Process input sequentially, writing output and substituting
	 * auto-generated sections with fresh ones from NVRAM.
	 */
	FILE *out = fopen(conf_path, "w");
	if (!out) {
		free(buf);
		return;
	}

	char *p = buf;
	char *bgp_start = strstr(buf, FRR_BGP_BLOCK_START);
	char *ospf_start = strstr(buf, FRR_OSPF_BLOCK_START);
	char *bfd_start = strstr(buf, FRR_BFD_BLOCK_START);
	char *acl_start = strstr(buf, FRR_ACL_BLOCK_START);

	/* Find which block comes first */
	#define MIN_PTR(a, b) ((a && b) ? (a < b ? a : b) : (a ? a : b))
	char *next_block = NULL;

	/* Copy content before first block */
	next_block = bgp_start;
	next_block = MIN_PTR(next_block, ospf_start);
	next_block = MIN_PTR(next_block, bfd_start);
	next_block = MIN_PTR(next_block, acl_start);

	if (next_block) {
		fwrite(buf, 1, next_block - buf, out);
		p = next_block;
	} else {
		/* No blocks found, preserve entire file and append blocks at end */
		fwrite(buf, 1, fsize, out);
		frr_write_bgp_block(out, lan_ip);
		frr_write_ospf_block(out, lan_ip, wan_if);
		frr_write_bfd_block(out);
		frr_write_acl_block(out);
		append_custom_config("frr.conf", out);
		goto finish;
	}

	/* Process BGP block */
	if (bgp_start) {
		char *bgp_auto_end = strstr(bgp_start, FRR_BGP_AUTO_END);
		char *bgp_end = strstr(bgp_start, FRR_BGP_BLOCK_END);
		
		if (bgp_auto_end && bgp_end && bgp_end > bgp_auto_end) {
			/* Block exists with user section - write fresh auto section, preserve user section */
			frr_write_bgp_block(out, lan_ip);
			if (!force_regen) {
				/* Preserve user additions: from AUTO_END marker to END marker */
				char *user_start = bgp_auto_end + strlen(FRR_BGP_AUTO_END);
				char *user_end = bgp_end;
				fwrite(user_start, 1, user_end - user_start, out);
			}
			p = bgp_end + strlen(FRR_BGP_BLOCK_END);
			while (*p == '\r' || *p == '\n') p++;
		}
	}

	/* Find next block to process */
	next_block = ospf_start;
	next_block = MIN_PTR(next_block, bfd_start);
	next_block = MIN_PTR(next_block, acl_start);
	if (next_block && next_block > p) {
		fwrite(p, 1, next_block - p, out);
		p = next_block;
	}

	/* Process OSPF block */
	if (ospf_start) {
		char *ospf_auto_end = strstr(ospf_start, FRR_OSPF_AUTO_END);
		char *ospf_end = strstr(ospf_start, FRR_OSPF_BLOCK_END);
		
		if (ospf_auto_end && ospf_end && ospf_end > ospf_auto_end) {
			frr_write_ospf_block(out, lan_ip, wan_if);
			if (!force_regen) {
				char *user_start = ospf_auto_end + strlen(FRR_OSPF_AUTO_END);
				char *user_end = ospf_end;
				fwrite(user_start, 1, user_end - user_start, out);
			}
			p = ospf_end + strlen(FRR_OSPF_BLOCK_END);
			while (*p == '\r' || *p == '\n') p++;
		}
	}

	/* Find next block to process */
	next_block = bfd_start;
	next_block = MIN_PTR(next_block, acl_start);
	if (next_block && next_block > p) {
		fwrite(p, 1, next_block - p, out);
		p = next_block;
	}

	/* Process BFD block */
	if (bfd_start) {
		char *bfd_auto_end = strstr(bfd_start, FRR_BFD_AUTO_END);
		char *bfd_end = strstr(bfd_start, FRR_BFD_BLOCK_END);
		
		if (bfd_auto_end && bfd_end && bfd_end > bfd_auto_end) {
			frr_write_bfd_block(out);
			if (!force_regen) {
				char *user_start = bfd_auto_end + strlen(FRR_BFD_AUTO_END);
				char *user_end = bfd_end;
				fwrite(user_start, 1, user_end - user_start, out);
			}
			p = bfd_end + strlen(FRR_BFD_BLOCK_END);
			while (*p == '\r' || *p == '\n') p++;
		}
	}

	/* Find ACL block */
	if (acl_start && acl_start > p) {
		fwrite(p, 1, acl_start - p, out);
		p = acl_start;
	}

	/* Process ACL block */
	if (acl_start) {
		char *acl_auto_end = strstr(acl_start, FRR_ACL_AUTO_END);
		char *acl_end = strstr(acl_start, FRR_ACL_BLOCK_END);
		
		if (acl_auto_end && acl_end && acl_end > acl_auto_end) {
			frr_write_acl_block(out);
			if (!force_regen) {
				char *user_start = acl_auto_end + strlen(FRR_ACL_AUTO_END);
				char *user_end = acl_end;
				fwrite(user_start, 1, user_end - user_start, out);
			}
			p = acl_end + strlen(FRR_ACL_BLOCK_END);
			while (*p == '\r' || *p == '\n') p++;
		}
	}

	/* Copy any remaining content */
	if (p < buf + fsize) {
		fwrite(p, 1, (buf + fsize) - p, out);
	}

	/* Add any missing blocks */
	if (!bgp_start)
		frr_write_bgp_block(out, lan_ip);
	if (!ospf_start)
		frr_write_ospf_block(out, lan_ip, wan_if);
	if (!bfd_start)
		frr_write_bfd_block(out);
	if (!acl_start)
		frr_write_acl_block(out);

	append_custom_config("frr.conf", out);

finish:
	fclose(out);
	free(buf);
	chmod(conf_path, 0644);
}

/* Write/merge configuration files on start and UI apply */
static void frr_write_default_config(void)
{
	FILE *fp;
	int force_regen;
	char *frr_passwd, *frr_enpasswd;
	char *hostname;
	char *lan_ip, *wan_if;
	char cfg_dir[PATH_MAX];
	char daemons_path[PATH_MAX];
	char conf_path[PATH_MAX];

	frr_get_config_paths(cfg_dir, sizeof(cfg_dir),
		daemons_path, sizeof(daemons_path),
		conf_path, sizeof(conf_path));
	force_regen = nvram_match("frr_force_regen", "1");

	lan_ip  = nvram_safe_get("lan_ipaddr");
	wan_if  = get_wan_ifname(wan_primary_ifunit());
	
	/* Get passwords from NVRAM (compatible with old zebra_passwd) */
	frr_passwd = nvram_safe_get("frr_passwd");
	if (!*frr_passwd)
		frr_passwd = nvram_safe_get("zebra_passwd"); /* Fallback for Quagga migration */
	if (!*frr_passwd)
		frr_passwd = "zebra"; /* Default */
	
	frr_enpasswd = nvram_safe_get("frr_enpasswd");
	if (!*frr_enpasswd)
		frr_enpasswd = nvram_safe_get("zebra_enpasswd"); /* Fallback for Quagga migration */
	if (!*frr_enpasswd)
		frr_enpasswd = "zebra"; /* Default */
	
	hostname = nvram_safe_get("productid");
	if (!*hostname)
		hostname = "FRR";

#ifdef RTCONFIG_NVRAM_ENCRYPT
	/* Decrypt passwords if encryption is enabled */
	int declen = strlen(frr_passwd);
	char *dec_passwd = NULL;
	if (declen > 0) {
		dec_passwd = malloc(declen + 1);
		if (dec_passwd) {
			memset(dec_passwd, 0, declen + 1);
			if (pw_dec(frr_passwd, dec_passwd, declen, 1) > 0)
				frr_passwd = dec_passwd;
		}
	}
	
	int declen2 = strlen(frr_enpasswd);
	char *dec_enpasswd = NULL;
	if (declen2 > 0) {
		dec_enpasswd = malloc(declen2 + 1);
		if (dec_enpasswd) {
			memset(dec_enpasswd, 0, declen2 + 1);
			if (pw_dec(frr_enpasswd, dec_enpasswd, declen2, 1) > 0)
				frr_enpasswd = dec_enpasswd;
		}
	}
#endif
	
	/*
	 * Preserve an existing external daemons file unless the user explicitly
	 * requests regeneration. This lets a JFFS-hosted integrated FRR config set
	 * remain authoritative across reboots.
	 */
	if (frr_should_regenerate_file(daemons_path, force_regen)) {
		fp = fopen(daemons_path, "w");
		if (fp) {
		fprintf(fp, "# FRR daemons configuration\n");
		fprintf(fp, "# Generated by AsusWRT\n");
		fprintf(fp, "#\n");
		fprintf(fp, "zebra=yes\n");
		fprintf(fp, "bgpd=%s\n", nvram_match("frr_bgp_enable", "1") ? "yes" : "no");
		fprintf(fp, "ospfd=%s\n", nvram_match("frr_ospf_enable", "1") ? "yes" : "no");
		fprintf(fp, "staticd=yes\n");
		fprintf(fp, "bfdd=%s\n", nvram_match("frr_bfd_enable", "1") ? "yes" : "no");
		fprintf(fp, "#\n");
		fprintf(fp, "vtysh_enable=yes\n");
		fprintf(fp, "zebra_options=\" -s 90000000 --daemon\"\n");
		fprintf(fp, "bgpd_options=\" --daemon\"\n");
		fprintf(fp, "ospfd_options=\" --daemon\"\n");
		fprintf(fp, "staticd_options=\" --daemon\"\n");
		fprintf(fp, "bfdd_options=\" --daemon\"\n");

			/* Support for custom config additions */
			append_custom_config("frr_daemons", fp);
			fclose(fp);

			/* Allow custom config replacement */
			use_custom_config("frr_daemons", daemons_path);
			run_postconf("frr_daemons", daemons_path);

			chmod(daemons_path, 0644);
		}
	}
	
	/*
	 * Preserve an existing external frr.conf unless the user explicitly
	 * requests regeneration. This avoids rewriting/appending on normal starts
	 * while still allowing initial creation and explicit refresh.
	 */
	if (frr_should_regenerate_file(conf_path, force_regen)) {
		/*
		 * Merge UI settings into frr.conf. The merge function replaces only the
		 * auto-generated portions (between START and AUTO_END markers) and leaves
		 * user additions untouched unless force_regen=1.
		 */
		frr_merge_ui_into_conf(conf_path, lan_ip, wan_if, frr_passwd, frr_enpasswd, hostname, force_regen);

		/*
		 * Allow a full config override: if /jffs/configs/frr.conf exists it
		 * replaces the merged file entirely. run_postconf fires afterward.
		 */
		use_custom_config("frr.conf", conf_path);
		run_postconf("frr.conf", conf_path);
	}

	frr_sync_runtime_config(cfg_dir, daemons_path, conf_path);
	nvram_unset("frr_force_regen");

#ifdef RTCONFIG_NVRAM_ENCRYPT
	/* Free decrypted passwords */
	if (dec_passwd) free(dec_passwd);
	if (dec_enpasswd) free(dec_enpasswd);
#endif
}

void start_frr(void)
{
	int running = 0;
	int have_stderr = 0;

	if (!is_frr_enabled()) {
		_dprintf("FRR is not enabled\n");
		return;
	}

	if (frr_should_defer_until_pppd()) {
		logmessage("FRR", "deferring startup until pppd is running");
		_dprintf("FRR startup deferred: PPP WAN configured but pppd not running yet\n");
		return;
	}

	running = (pidof("watchfrr") > 0);
	unlink(FRR_STDERR_LOG_FILE);
	
	_dprintf("Starting FRR routing services...\n");
	
	/* Create directories and default configs */
	frr_create_dirs();
	frr_write_default_config();

	/*
	 * Keep start idempotent: WAN/PPP link events can call start_frr() while
	 * FRR is healthy, and forcing a full stop/start there destabilizes peers.
	 */
	if (running) {
		logmessage("FRR", "watchfrr already running, leaving daemons untouched");
		_dprintf("FRR watchfrr already running - no restart required\n");
		return;
	}
	else {
		if (frr_invoke_script_capture("start", FRR_STDERR_LOG_FILE, 1) != 0) {
			have_stderr = 1;
			_dprintf("FRR start via init script failed\n");
			logmessage("FRR", "start command failed");
		}
		else {
			have_stderr = 1;
		}
	}

	if (pidof("watchfrr") > 0) {
		logmessage("FRR", "start completed successfully");
		_dprintf("FRR started\n");
	}
	else {
		logmessage("FRR", "start completed but watchfrr is not running");
		if (have_stderr)
			frr_log_captured_stderr(FRR_STDERR_LOG_FILE);
		_dprintf("FRR start failed\n");
	}
}

void stop_frr(void)
{
	int have_stderr = 0;

	_dprintf("Stopping FRR routing services...\n");
	unlink(FRR_STDERR_LOG_FILE);

	/* Stop FRR using init script; if it fails, force-stop daemon processes. */
	if (frr_invoke_script_capture("stop", FRR_STDERR_LOG_FILE, 1) != 0) {
		have_stderr = 1;
		logmessage("FRR", "stop command failed, forcing daemon stop fallback");
		frr_force_stop_daemons();
	}
	else {
		have_stderr = 1;
	}

	if (pidof("watchfrr") <= 0) {
		logmessage("FRR", "stop completed successfully");
		_dprintf("FRR stopped\n");
	}
	else {
		logmessage("FRR", "stop: watchfrr still running after stop command, forcing daemon stop");
		frr_force_stop_daemons();

		if (pidof("watchfrr") <= 0) {
			logmessage("FRR", "stop completed successfully after forced daemon stop");
			_dprintf("FRR stopped after forced daemon stop\n");
			return;
		}

		logmessage("FRR", "stop completed but watchfrr is still running");
		if (have_stderr)
			frr_log_captured_stderr(FRR_STDERR_LOG_FILE);
		_dprintf("FRR stop incomplete\n");
	}
}

void restart_frr(void)
{
	int was_running;
	int have_stderr = 0;

	if (!is_frr_enabled()) {
		_dprintf("FRR restart requested while disabled - stopping daemons\n");
		logmessage("FRR", "restart requested while disabled; stopping FRR daemons");
		stop_frr();
		return;
	}

	was_running = (pidof("watchfrr") > 0);
	unlink(FRR_STDERR_LOG_FILE);

	/*
	 * Apply UI configuration updates only when explicitly requested:
	 * - Only update config files if force_regen=1 (user clicked Apply on FRR page)
	 * - Never update on daemon crashes (watchfrr restart) - use existing config
	 * - Preserve existing config outside UI block if present
	 *
	 * This prevents unintended regeneration when watchfrr restarts a crashed daemon,
	 * while ensuring UI changes (new BGP neighbors, etc.) are applied when users
	 * explicitly click Apply on the FRR configuration page.
	 */
	frr_create_dirs();
	
	if (nvram_match("frr_force_regen", "1")) {
		/* User explicitly requested config update via UI Apply */
		frr_write_default_config();
	}

	/*
	 * Use an explicit stop/start cycle for deterministic restart behavior.
	 * Some init script restart implementations can be a no-op in practice.
	 */
	if (was_running) {
		if (frr_invoke_script_capture("stop", FRR_STDERR_LOG_FILE, 1) != 0) {
			have_stderr = 1;
			logmessage("FRR", "restart: stop command failed, forcing daemon stop fallback");
			frr_force_stop_daemons();
		}
		else {
			have_stderr = 1;
		}

		if (pidof("watchfrr") > 0) {
			logmessage("FRR", "restart: watchfrr still running after stop, forcing daemon stop");
			frr_force_stop_daemons();
		}
	}

	sleep(1);

	if (frr_invoke_script_capture("start", FRR_STDERR_LOG_FILE, 1) != 0) {
		have_stderr = 1;
		logmessage("FRR", "restart: start command failed, retrying after forced stop");
		frr_force_stop_daemons();
		sleep(1);
		if (frr_invoke_script_capture("start", FRR_STDERR_LOG_FILE, 1) != 0)
			have_stderr = 1;
	}
	else {
		have_stderr = 1;
	}

	if (pidof("watchfrr") > 0)
		logmessage("FRR", "restart completed successfully");
	else {
		logmessage("FRR", "restart failed: watchfrr is not running after stop/start cycle");
		if (have_stderr)
			frr_log_captured_stderr(FRR_STDERR_LOG_FILE);
	}
}
