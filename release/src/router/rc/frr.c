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
#define FRR_RUNTIME_VTYSH_CONF	FRR_RUNTIME_CONFIG_DIR "/vtysh.conf"
#define FRR_DAEMON_USER		"nobody"
#define FRR_DAEMON_GROUP	"nobody"
#define FRR_STDERR_LOG_FILE	"/tmp/frr-start.stderr.log"

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

	if (f_exists(FRR_SCRIPT))
		ret = eval(FRR_SCRIPT, action);
	else if (f_exists(FRR_INIT_SCRIPT))
		ret = eval(FRR_INIT_SCRIPT, action);
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

	if (f_exists(FRR_SCRIPT))
		ret = frr_exec_script_capture_stderr(FRR_SCRIPT, action, stderr_log, append);
	else if (f_exists(FRR_INIT_SCRIPT))
		ret = frr_exec_script_capture_stderr(FRR_INIT_SCRIPT, action, stderr_log, append);
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
	while (n > 1 && buf[n - 1] == '/') {
		buf[n - 1] = '\0';
		n--;
	}

	if (!strcmp(buf, FRR_RUNTIME_CONFIG_DIR))
		strlcpy(buf, FRR_CONFIG_DIR_DEFAULT, len);

	return buf;
}

static void frr_get_config_paths(char *cfg_dir, size_t cfg_dir_len,
		char *daemons_path, size_t daemons_path_len,
		char *conf_path, size_t conf_path_len,
		char *vtysh_conf_path, size_t vtysh_conf_path_len)
{
	frr_get_config_dir(cfg_dir, cfg_dir_len);
	snprintf(daemons_path, daemons_path_len, "%s/daemons", cfg_dir);
	snprintf(conf_path, conf_path_len, "%s/frr.conf", cfg_dir);
	snprintf(vtysh_conf_path, vtysh_conf_path_len, "%s/vtysh.conf", cfg_dir);
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
		const char *conf_path,
		const char *vtysh_conf_path)
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

	if (f_exists(vtysh_conf_path)) {
		if (frr_copy_file(vtysh_conf_path, FRR_RUNTIME_VTYSH_CONF))
			chmod(FRR_RUNTIME_VTYSH_CONF, 0644);
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

/* Write default configuration files if they don't exist */
static void frr_write_default_config(void)
{
	FILE *fp;
	int force_regen;
	char *frr_passwd, *frr_enpasswd;
	char *hostname;
	char cfg_dir[PATH_MAX];
	char daemons_path[PATH_MAX];
	char conf_path[PATH_MAX];
	char vtysh_conf_path[PATH_MAX];

	frr_get_config_paths(cfg_dir, sizeof(cfg_dir),
		daemons_path, sizeof(daemons_path),
		conf_path, sizeof(conf_path),
		vtysh_conf_path, sizeof(vtysh_conf_path));
	force_regen = nvram_match("frr_force_regen", "1");
	
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
		fprintf(fp, "zebra_options=\" -s 90000000 --daemon -A 127.0.0.1\"\n");
		fprintf(fp, "bgpd_options=\" --daemon -A 127.0.0.1\"\n");
		fprintf(fp, "ospfd_options=\" --daemon -A 127.0.0.1\"\n");
		fprintf(fp, "staticd_options=\" --daemon -A 127.0.0.1\"\n");
		fprintf(fp, "bfdd_options=\" --daemon -A 127.0.0.1\"\n");

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
	 * Preserve an existing integrated frr.conf in the configured directory unless
	 * regeneration is explicitly requested. This is the authoritative config used
	 * by vtysh for all daemons.
	 */
	if (frr_should_regenerate_file(conf_path, force_regen)) {
		fp = fopen(conf_path, "w");
		if (fp) {
			char *lan_ip, *wan_if;
			char *bgp_as, *bgp_neighbor, *bgp_neighbor_as, *bgp_neighbor_desc, *bgp_neighbor_src, *bgp_networks;
			char *ospf_area, *ospf_networks;
			char *bfd_peer, *bfd_tx, *bfd_rx;
			
			lan_ip = nvram_safe_get("lan_ipaddr");
			wan_if = get_wan_ifname(wan_primary_ifunit());
			
			fprintf(fp, "!\n");
			fprintf(fp, "! FRR configuration\n");
			fprintf(fp, "! Generated by AsusWRT for compiled daemons:\n");
			fprintf(fp, "! zebra, bgpd, ospfd, staticd, bfdd\n");
			fprintf(fp, "!\n");
			fprintf(fp, "frr version 7.5.1\n");
			fprintf(fp, "frr defaults traditional\n");
			fprintf(fp, "hostname %s\n", hostname);
			fprintf(fp, "password %s\n", frr_passwd);
			fprintf(fp, "enable password %s\n", frr_enpasswd);
			fprintf(fp, "!\n");
			fprintf(fp, "log syslog informational\n");
			fprintf(fp, "!\n");
			fprintf(fp, "service integrated-vtysh-config\n");
			fprintf(fp, "!\n");
			
			/* === ZEBRA Configuration (always enabled) === */
			fprintf(fp, "! Zebra routing manager configuration\n");
			fprintf(fp, "! Manages kernel routing table and redistributes routes\n");
			fprintf(fp, "!\n");
			
			/* === STATIC Routes Configuration (staticd - always enabled) === */
			fprintf(fp, "! Static routes configuration\n");
			fprintf(fp, "! Add custom static routes via JFFS configs\n");
			fprintf(fp, "!\n");
			
			/* === BGP Configuration === */
			if (nvram_match("frr_bgp_enable", "1")) {
				bgp_as = nvram_safe_get("frr_bgp_as");
				bgp_neighbor = nvram_safe_get("frr_bgp_neighbor");
				bgp_neighbor_as = nvram_safe_get("frr_bgp_neighbor_as");
				bgp_neighbor_desc = nvram_safe_get("frr_bgp_neighbor_desc");
				bgp_neighbor_src = nvram_safe_get("frr_bgp_neighbor_src");
				bgp_networks = nvram_safe_get("frr_bgp_networks");
				
				if (*bgp_as) {
					char *neighbor_list = NULL;
					char *neighbor_as_list = NULL;
					char *neighbor_desc_list = NULL;
					char *neighbor_src_list = NULL;
					char *activate_list = NULL;
					fprintf(fp, "! BGP (Border Gateway Protocol) Configuration\n");
					fprintf(fp, "router bgp %s\n", bgp_as);
					fprintf(fp, " bgp router-id %s\n", lan_ip);
					fprintf(fp, " bgp log-neighbor-changes\n");
					
					/* BGP neighbor configuration */
					if (*bgp_neighbor && *bgp_neighbor_as) {
						char *n_cur;
						char *a_cur;
						char *d_cur;
						char *s_cur;
						char *token_ip;
						char *token_as;
						char *token_desc;
						char *token_src;
						fprintf(fp, " !\n");

						neighbor_list = strdup(bgp_neighbor);
						neighbor_as_list = strdup(bgp_neighbor_as);
						neighbor_desc_list = strdup(bgp_neighbor_desc);
						neighbor_src_list = strdup(bgp_neighbor_src);

						if (neighbor_list && neighbor_as_list) {
							n_cur = neighbor_list;
							a_cur = neighbor_as_list;
							d_cur = neighbor_desc_list;
							s_cur = neighbor_src_list;

							while ((token_ip = strsep(&n_cur, ">")) != NULL &&
							       (token_as = strsep(&a_cur, ">")) != NULL) {
								token_desc = d_cur ? strsep(&d_cur, ">") : NULL;
								token_src = s_cur ? strsep(&s_cur, ">") : NULL;
								if (!*token_ip || !*token_as)
									continue;

								fprintf(fp, " neighbor %s remote-as %s\n", token_ip, token_as);
								if (token_desc && *token_desc)
									fprintf(fp, " neighbor %s description %s\n", token_ip, token_desc);
								if (token_src && *token_src)
									fprintf(fp, " neighbor %s update-source %s\n", token_ip, token_src);
								fprintf(fp, " neighbor %s password %s\n", token_ip, frr_passwd);
							}
						}

						fprintf(fp, " !\n");
						fprintf(fp, " address-family ipv4 unicast\n");
						if (*bgp_networks) {
							char *netlist = strdup(bgp_networks);
							char *net_cur = netlist;
							char *net;

							while (net_cur && (net = strsep(&net_cur, " \t\r\n")) != NULL) {
								if (!*net)
									continue;
								fprintf(fp, "  network %s\n", net);
							}

							if (netlist)
								free(netlist);
						}
						else {
							fprintf(fp, "  network %s/24\n", lan_ip);
						}

						activate_list = strdup(bgp_neighbor);
						if (activate_list) {
							char *act_cur = activate_list;
							char *act_ip;

							while ((act_ip = strsep(&act_cur, ">")) != NULL) {
								if (!*act_ip)
									continue;

								fprintf(fp, "  neighbor %s activate\n", act_ip);
							}
						}

						fprintf(fp, " exit-address-family\n");

						if (activate_list)
							free(activate_list);
						if (neighbor_as_list)
							free(neighbor_as_list);
						if (neighbor_src_list)
							free(neighbor_src_list);
						if (neighbor_desc_list)
							free(neighbor_desc_list);
						if (neighbor_list)
							free(neighbor_list);
					}
					
					fprintf(fp, "!\n");
				}
			}
			
			/* === OSPF Configuration === */
			if (nvram_match("frr_ospf_enable", "1")) {
				ospf_area = nvram_safe_get("frr_ospf_area");
				ospf_networks = nvram_safe_get("frr_ospf_networks");
				
				if (!*ospf_area)
					ospf_area = "0"; /* Default backbone area */
				
				fprintf(fp, "! OSPF (Open Shortest Path First) Configuration\n");
				fprintf(fp, "router ospf\n");
				fprintf(fp, " ospf router-id %s\n", lan_ip);
				fprintf(fp, " log-adjacency-changes\n");
				fprintf(fp, " !\n");
				
				/* Network statements */
				if (*ospf_networks) {
					/* User-defined networks from NVRAM */
					fprintf(fp, " ! Custom networks from NVRAM\n");
					fprintf(fp, " ! Set frr_ospf_networks to networks separated by spaces\n");
					fprintf(fp, " ! Example: nvram set frr_ospf_networks=\"192.168.0.0/24 192.168.1.0/24\"\n");
					/* Networks are added via custom config or postconf */
				} else {
					/* Default: advertise all connected networks */
					fprintf(fp, " network 0.0.0.0/0 area %s\n", ospf_area);
				}
				
				fprintf(fp, " !\n");
				fprintf(fp, " ! Passive interfaces (don't send OSPF hello packets)\n");
#if !defined(BLUECAVE)
				fprintf(fp, " passive-interface vlan2\n");
				fprintf(fp, " passive-interface vlan3\n");
#else
				fprintf(fp, " passive-interface eth1.2\n");
				fprintf(fp, " passive-interface eth1.3\n");
#endif
				/* Add WAN interface as passive if exists */
				if (wan_if && *wan_if) {
					fprintf(fp, " passive-interface %s\n", wan_if);
				}
				
				fprintf(fp, "!\n");
			}
			
			/* === BFD Configuration === */
			if (nvram_match("frr_bfd_enable", "1")) {
				bfd_peer = nvram_safe_get("frr_bfd_peer");
				bfd_tx = nvram_safe_get("frr_bfd_tx");
				bfd_rx = nvram_safe_get("frr_bfd_rx");
				fprintf(fp, "! BFD (Bidirectional Forwarding Detection) Configuration\n");
				fprintf(fp, "! Provides fast failure detection for routing protocols\n");
				fprintf(fp, "bfd\n");
				if (*bfd_peer) {
					fprintf(fp, " peer %s\n", bfd_peer);
					fprintf(fp, "  transmit-interval %s\n", *bfd_tx ? bfd_tx : "150");
					fprintf(fp, "  receive-interval %s\n", *bfd_rx ? bfd_rx : "150");
					fprintf(fp, " !\n");
				}
				else {
					fprintf(fp, " ! Configure peer and intervals from WebUI\n");
				}
				fprintf(fp, "!\n");
			}
			
			/* === Access Control === */
			fprintf(fp, "! Access control for vty (telnet/ssh) connections\n");
			fprintf(fp, "access-list vty permit 127.0.0.0/8\n");
			
			/* Allow LAN access if configured */
			if (nvram_match("frr_allow_lan", "1")) {
				char *lan_netmask = nvram_safe_get("lan_netmask");
				if (*lan_ip && *lan_netmask) {
					fprintf(fp, "access-list vty permit %s/%s\n", lan_ip, lan_netmask);
				}
			}
			
			fprintf(fp, "access-list vty deny any\n");
			fprintf(fp, "!\n");
			fprintf(fp, "line vty\n");
			fprintf(fp, " access-class vty\n");
			fprintf(fp, " exec-timeout 0 0\n");
			fprintf(fp, "!\n");
			
			/* === Per-daemon custom configs === */
			fprintf(fp, "! Custom configurations\n");
			fprintf(fp, "! Add custom FRR commands via JFFS:\n");
			fprintf(fp, "! /jffs/configs/frr.conf.add\n");
			fprintf(fp, "!\n");
			
			/* Support for custom config additions */
			append_custom_config("frr.conf", fp);
			fclose(fp);
			
			/* Allow custom config replacement */
			use_custom_config("frr.conf", conf_path);
			run_postconf("frr.conf", conf_path);
			
			chmod(conf_path, 0644);
		}
	}
	
	/* Create vtysh.conf if missing */
	if (frr_should_regenerate_file(vtysh_conf_path, force_regen)) {
		fp = fopen(vtysh_conf_path, "w");
		if (fp) {
			fprintf(fp, "!\n");
			fprintf(fp, "service integrated-vtysh-config\n");
			fprintf(fp, "!\n");
			fclose(fp);
			chmod(vtysh_conf_path, 0644);
		}
	}

	frr_sync_runtime_config(cfg_dir, daemons_path, conf_path, vtysh_conf_path);
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

	running = (pidof("watchfrr") > 0);
	unlink(FRR_STDERR_LOG_FILE);
	
	_dprintf("Starting FRR routing services...\n");
	
	/* Create directories and default configs */
	frr_create_dirs();
	frr_write_default_config();

	/* If already running, do a controlled restart so config changes always apply. */
	if (running) {
		_dprintf("FRR watchfrr already running - invoking restart\n");
		logmessage("FRR", "watchfrr already running, invoking restart to apply config changes");
		if (frr_invoke_script_capture("restart", FRR_STDERR_LOG_FILE, 1) != 0) {
			have_stderr = 1;
			_dprintf("FRR restart via init script failed - forcing stop/start\n");
			logmessage("FRR", "restart command failed, forcing daemon stop/start fallback");
			frr_force_stop_daemons();
			if (frr_invoke_script_capture("start", FRR_STDERR_LOG_FILE, 1) != 0) {
				have_stderr = 1;
				_dprintf("FRR start failed after forced stop\n");
				logmessage("FRR", "start command failed after forced stop fallback");
			}
		}
		else {
			have_stderr = 1;
		}
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
		logmessage("FRR", "stop completed but watchfrr is still running");
		if (have_stderr)
			frr_log_captured_stderr(FRR_STDERR_LOG_FILE);
		_dprintf("FRR stop incomplete\n");
	}
}

void restart_frr(void)
{
	int have_stderr = 0;

	if (!is_frr_enabled()) {
		_dprintf("FRR restart requested while disabled - stopping daemons\n");
		logmessage("FRR", "restart requested while disabled; stopping FRR daemons");
		stop_frr();
		return;
	}

	unlink(FRR_STDERR_LOG_FILE);

	/* Ensure latest UI/NVRAM settings are materialized before restart. */
	frr_create_dirs();
	frr_write_default_config();

	if (frr_invoke_script_capture("restart", FRR_STDERR_LOG_FILE, 1) != 0) {
		have_stderr = 1;
		_dprintf("FRR restart via init script failed - fallback stop/start\n");
		logmessage("FRR", "restart command failed, using stop/start fallback");
		stop_frr();
		sleep(1);
		start_frr();
	}
	else {
		have_stderr = 1;
	}

	if (pidof("watchfrr") > 0)
		logmessage("FRR", "restart completed successfully");
	else {
		logmessage("FRR", "restart completed but watchfrr is not running");
		if (have_stderr)
			frr_log_captured_stderr(FRR_STDERR_LOG_FILE);
	}
}
