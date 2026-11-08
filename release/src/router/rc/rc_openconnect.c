/*
 * OpenConnect VPN Client Control for Asuswrt-Merlin
 * Copyright (C) 2024
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * Implementation of OpenConnect VPN client control functions
 * Supports multiple VPN protocols: AnyConnect, Juniper, Pulse, GlobalProtect, F5, Fortinet
 */

#include <rc.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bcmnvram.h>
#include <shutils.h>
#include <syslog.h>
#include <errno.h>
#include "rc_openconnect.h"

#define OPENCONNECT_BIN "/usr/sbin/openconnect"
#define OPENCONNECT_VPNC_SCRIPT "/etc/vpnc/vpnc-script"
#define OPENCONNECT_CONF_DIR "/tmp/openconnect"
#define OPENCONNECT_LOG_DIR "/tmp/ipsec-private"
#define OPENCONNECT_PID_BASE "/var/run/openconnect_"

static const char *protocol_names[] = {
	"anyconnect",    /* Cisco AnyConnect (default) */
	"nc",            /* Juniper Network Connect */
	"pulse",         /* Pulse Secure */
	"gp",            /* Palo Alto GlobalProtect */
	"f5",            /* F5 Big-IP */
	"fortinet"       /* Fortinet */
};

/* Check if OpenConnect client is enabled */
int openconnect_client_enabled(int unit)
{
	char varname[32];
	
	if (unit < 1 || unit > OPENCONNECT_CLIENT_MAX)
		return 0;
	
	snprintf(varname, sizeof(varname), "openconnect_client%d_enable", unit);
	return nvram_get_int(varname);
}

/* Get PID file path for OpenConnect client */
static void get_pid_file(int unit, char *buf, size_t len)
{
	snprintf(buf, len, "%s%d.pid", OPENCONNECT_PID_BASE, unit);
}

static int openconnect_secure_dir(int descriptor)
{
	struct stat st;

	if (fstat(descriptor, &st) < 0 || !S_ISDIR(st.st_mode) ||
		st.st_uid != 0 || st.st_gid != 0 || (st.st_mode & 0022) ||
		fchmod(descriptor, 0700) < 0 || fstat(descriptor, &st) < 0 ||
		(st.st_mode & 0777) != 0700)
		return -1;
	return 0;
}

static int openconnect_config_dir(int unit)
{
	struct stat st;
	char dirname[16];
	int parentfd, descriptor;

	if (lstat("/tmp", &st) < 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
		((st.st_mode & 0022) && !(st.st_mode & S_ISVTX)))
		return -1;
	if (mkdir(OPENCONNECT_CONF_DIR, 0700) < 0 && errno != EEXIST)
		return -1;
	parentfd = open(OPENCONNECT_CONF_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (parentfd < 0)
		return -1;
	if (openconnect_secure_dir(parentfd) < 0) {
		close(parentfd);
		return -1;
	}
	snprintf(dirname, sizeof(dirname), "client%d", unit);
	if (mkdirat(parentfd, dirname, 0700) < 0 && errno != EEXIST) {
		close(parentfd);
		return -1;
	}
	descriptor = openat(parentfd, dirname, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	close(parentfd);
	if (descriptor < 0)
		return -1;
	if (openconnect_secure_dir(descriptor) < 0) {
		close(descriptor);
		return -1;
	}
	return descriptor;
}

static int openconnect_write_all(int descriptor, const char *data, size_t length)
{
	while (length) {
		ssize_t written = write(descriptor, data, length);

		if (written < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (written == 0)
			return -1;
		data += written;
		length -= written;
	}
	return 0;
}

static int openconnect_write_secret(int dirfd, const char *name,
					    const char *first, const char *second)
{
	struct stat st;
	int descriptor, result = -1;

	descriptor = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL |
			    O_NOFOLLOW | O_NONBLOCK, 0600);
	if (descriptor < 0)
		return -1;
	if (fstat(descriptor, &st) < 0 || !S_ISREG(st.st_mode) ||
		st.st_uid != 0 || st.st_gid != 0 || st.st_nlink != 1 ||
		fchmod(descriptor, 0600) < 0)
		goto done;
	if (openconnect_write_all(descriptor, first, strlen(first)) < 0)
		goto done;
	if (second && (openconnect_write_all(descriptor, "\n", 1) < 0 ||
		openconnect_write_all(descriptor, second, strlen(second)) < 0 ||
		openconnect_write_all(descriptor, "\n", 1) < 0))
		goto done;
	result = 0;
done:
	if (close(descriptor) < 0)
		result = -1;
	if (result < 0)
		unlinkat(dirfd, name, 0);
	return result;
}

static int openconnect_log_open(int unit)
{
	struct stat st;
	char path[96];
	int descriptor;

	if (mkdir(OPENCONNECT_LOG_DIR, 0700) < 0 && errno != EEXIST)
		return -1;
	descriptor = open(OPENCONNECT_LOG_DIR, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
	if (descriptor < 0)
		return -1;
	if (fstat(descriptor, &st) < 0 || !S_ISDIR(st.st_mode) ||
		st.st_uid != 0 || st.st_gid != 0 || fchmod(descriptor, 0700) < 0) {
		close(descriptor);
		return -1;
	}
	close(descriptor);

	snprintf(path, sizeof(path), OPENCONNECT_LOG_DIR "/openconnect_client%d.log", unit);
	descriptor = open(path, O_WRONLY | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0600);
	if (descriptor < 0)
		return -1;
	if (fstat(descriptor, &st) < 0 || !S_ISREG(st.st_mode) ||
		st.st_uid != 0 || st.st_gid != 0 || st.st_nlink != 1 ||
		fchmod(descriptor, 0600) < 0 || ftruncate(descriptor, 0) < 0) {
		close(descriptor);
		return -1;
	}
	return descriptor;
}

/* Check if OpenConnect client is running */
int is_openconnect_running(int unit)
{
	char pidfile[64];
	FILE *fp;
	int pid;
	
	get_pid_file(unit, pidfile, sizeof(pidfile));
	
	fp = fopen(pidfile, "r");
	if (!fp)
		return 0;
	
	if (fscanf(fp, "%d", &pid) == 1) {
		fclose(fp);
		if (kill(pid, 0) == 0)
			return 1;
	} else {
		fclose(fp);
	}
	
	unlink(pidfile);
	return 0;
}

/* Update OpenConnect client status in NVRAM */
void update_openconnect_status(int unit, openconnect_state_t state, openconnect_errno_t err)
{
	char varname[32];
	
	if (unit < 1 || unit > OPENCONNECT_CLIENT_MAX)
		return;
	
	snprintf(varname, sizeof(varname), "openconnect_client%d_state", unit);
	nvram_set_int(varname, state);
	
	snprintf(varname, sizeof(varname), "openconnect_client%d_errno", unit);
	nvram_set_int(varname, err);
	
	/* Clear IP info when stopped */
	if (state == OPENCONNECT_STATE_STOPPED || state == OPENCONNECT_STATE_ERROR) {
		snprintf(varname, sizeof(varname), "openconnect_client%d_addr", unit);
		nvram_set(varname, "");
		snprintf(varname, sizeof(varname), "openconnect_client%d_rip", unit);
		nvram_set(varname, "");
	}
}

/* Get OpenConnect client status */
int get_openconnect_status(int unit)
{
	char varname[32];
	
	if (unit < 1 || unit > OPENCONNECT_CLIENT_MAX)
		return OPENCONNECT_STATE_STOPPED;
	
	snprintf(varname, sizeof(varname), "openconnect_client%d_state", unit);
	return nvram_get_int(varname);
}

/* Get OpenConnect client error number */
int get_openconnect_errno(int unit)
{
	char varname[32];
	
	if (unit < 1 || unit > OPENCONNECT_CLIENT_MAX)
		return OPENCONNECT_ERRNO_NONE;
	
	snprintf(varname, sizeof(varname), "openconnect_client%d_errno", unit);
	return nvram_get_int(varname);
}

/* Write OpenConnect configuration and credential files */
int write_openconnect_config(int unit)
{
	int dirfd;
	char varname[32], *server, *username, *password, *authgroup, *cert, *key, *ca;
	int ret = 0;
	
	if (unit < 1 || unit > OPENCONNECT_CLIENT_MAX)
		return -1;
	
	dirfd = openconnect_config_dir(unit);
	if (dirfd < 0) {
		logmessage("openconnect", "Refusing unsafe config directory for client %d", unit);
		return -1;
	}
	if ((unlinkat(dirfd, "auth.txt", 0) < 0 && errno != ENOENT) ||
		(unlinkat(dirfd, "client.crt", 0) < 0 && errno != ENOENT) ||
		(unlinkat(dirfd, "client.key", 0) < 0 && errno != ENOENT) ||
		(unlinkat(dirfd, "ca.crt", 0) < 0 && errno != ENOENT)) {
		close(dirfd);
		return -1;
	}
	
	/* Get configuration from NVRAM */
	snprintf(varname, sizeof(varname), "openconnect_client%d_", unit);
	
	server = nvram_pf_safe_get(varname, "server");
	username = nvram_pf_safe_get(varname, "username");
	password = nvram_pf_safe_get(varname, "password");
	authgroup = nvram_pf_safe_get(varname, "authgroup");
	cert = nvram_pf_safe_get(varname, "cert");
	key = nvram_pf_safe_get(varname, "key");
	ca = nvram_pf_safe_get(varname, "ca");
	
	/* Write username/password file if provided */
	if (username && *username && password && *password) {
		if (openconnect_write_secret(dirfd, "auth.txt", username, password) < 0)
			ret = -1;
	}
	
	/* Write certificate if provided */
	if (!ret && cert && *cert &&
		openconnect_write_secret(dirfd, "client.crt", cert, NULL) < 0)
		ret = -1;
	
	/* Write key if provided */
	if (!ret && key && *key &&
		openconnect_write_secret(dirfd, "client.key", key, NULL) < 0)
		ret = -1;
	
	/* Write CA certificate if provided */
	if (!ret && ca && *ca &&
		openconnect_write_secret(dirfd, "ca.crt", ca, NULL) < 0)
		ret = -1;
	if (ret) {
		unlinkat(dirfd, "auth.txt", 0);
		unlinkat(dirfd, "client.crt", 0);
		unlinkat(dirfd, "client.key", 0);
		unlinkat(dirfd, "ca.crt", 0);
		logmessage("openconnect", "Failed to write config for client %d", unit);
	}
	close(dirfd);
	return ret;
}

/* Start OpenConnect client */
int start_openconnect_client(int unit)
{
	char varname[32], confdir[64], pidfile[64], authfile[128];
	char certfile[128], keyfile[128], cafile[128];
	char *server, *username, *password, *authgroup, *cert, *key, *ca;
	char *protocol_str, *interface;
	int protocol, port, disable_ipv6, background, reconnect_timeout;
	char *argv[64];
	int argc = 0;
	pid_t pid;
	
	if (unit < 1 || unit > OPENCONNECT_CLIENT_MAX) {
		logmessage("openconnect", "Invalid client unit: %d", unit);
		return -1;
	}
	
	if (!openconnect_client_enabled(unit)) {
		logmessage("openconnect", "Client %d is not enabled", unit);
		return -1;
	}
	
	/* Stop if already running */
	if (is_openconnect_running(unit)) {
		logmessage("openconnect", "Client %d already running, stopping first", unit);
		stop_openconnect_client(unit);
		sleep(1);
	}
	
	/* Get configuration */
	snprintf(varname, sizeof(varname), "openconnect_client%d_", unit);
	snprintf(confdir, sizeof(confdir), "%s/client%d", OPENCONNECT_CONF_DIR, unit);
	
	server = nvram_pf_safe_get(varname, "server");
	if (!server || !*server) {
		logmessage("openconnect", "No server specified for client %d", unit);
		update_openconnect_status(unit, OPENCONNECT_STATE_ERROR, OPENCONNECT_ERRNO_CONFIG_ERROR);
		return -1;
	}
	
	username = nvram_pf_safe_get(varname, "username");
	password = nvram_pf_safe_get(varname, "password");
	authgroup = nvram_pf_safe_get(varname, "authgroup");
	cert = nvram_pf_safe_get(varname, "cert");
	key = nvram_pf_safe_get(varname, "key");
	ca = nvram_pf_safe_get(varname, "ca");
	protocol_str = nvram_pf_safe_get(varname, "protocol");
	interface = nvram_pf_safe_get(varname, "interface");
	port = nvram_pf_get_int(varname, "port");
	disable_ipv6 = nvram_pf_get_int(varname, "disable_ipv6");
	background = nvram_pf_get_int(varname, "background");
	reconnect_timeout = nvram_pf_get_int(varname, "reconnect_timeout");
	
	/* Parse protocol */
	protocol = OPENCONNECT_PROTO_ANYCONNECT;  /* default */
	if (protocol_str && *protocol_str) {
		int i;
		for (i = 0; i < sizeof(protocol_names)/sizeof(protocol_names[0]); i++) {
			if (strcmp(protocol_str, protocol_names[i]) == 0) {
				protocol = i;
				break;
			}
		}
	}
	
	/* Write config files */
	if (write_openconnect_config(unit) != 0) {
		logmessage("openconnect", "Failed to write config for client %d", unit);
		update_openconnect_status(unit, OPENCONNECT_STATE_ERROR, OPENCONNECT_ERRNO_CONFIG_ERROR);
		return -1;
	}
	
	/* Build command line arguments */
	argv[argc++] = OPENCONNECT_BIN;
	
	/* Protocol */
	if (protocol != OPENCONNECT_PROTO_ANYCONNECT) {
		argv[argc++] = "--protocol";
		argv[argc++] = (char *)protocol_names[protocol];
	}
	
	/* Interface name */
	if (interface && *interface) {
		argv[argc++] = "--interface";
		argv[argc++] = interface;
	} else {
		char ifname[16];
		snprintf(ifname, sizeof(ifname), "tun%d", unit + 10);  /* tun11, tun12 */
		argv[argc++] = "--interface";
		argv[argc++] = strdup(ifname);
	}
	
	/* Authentication group */
	if (authgroup && *authgroup) {
		argv[argc++] = "--authgroup";
		argv[argc++] = authgroup;
	}
	
	/* Username */
	if (username && *username) {
		argv[argc++] = "--user";
		argv[argc++] = username;
	}
	
	/* Password file (contains username and password) */
	if (username && *username && password && *password) {
		snprintf(authfile, sizeof(authfile), "%s/auth.txt", confdir);
		argv[argc++] = "--passwd-on-stdin";
	}
	
	/* Client certificate */
	if (cert && *cert) {
		snprintf(certfile, sizeof(certfile), "%s/client.crt", confdir);
		argv[argc++] = "--certificate";
		argv[argc++] = certfile;
	}
	
	/* Client key */
	if (key && *key) {
		snprintf(keyfile, sizeof(keyfile), "%s/client.key", confdir);
		argv[argc++] = "--sslkey";
		argv[argc++] = keyfile;
	}
	
	/* CA certificate */
	if (ca && *ca) {
		snprintf(cafile, sizeof(cafile), "%s/ca.crt", confdir);
		argv[argc++] = "--cafile";
		argv[argc++] = cafile;
	}
	
	/* VPN script */
	argv[argc++] = "--script";
	argv[argc++] = OPENCONNECT_VPNC_SCRIPT;
	
	/* Background mode */
	if (background) {
		argv[argc++] = "--background";
	}
	
	/* Disable IPv6 */
	if (disable_ipv6) {
		argv[argc++] = "--disable-ipv6";
	}
	
	/* PID file */
	get_pid_file(unit, pidfile, sizeof(pidfile));
	argv[argc++] = "--pid-file";
	argv[argc++] = pidfile;
	
	/* Reconnect timeout */
	if (reconnect_timeout > 0) {
		char timeout_str[16];
		snprintf(timeout_str, sizeof(timeout_str), "%d", reconnect_timeout);
		argv[argc++] = "--reconnect-timeout";
		argv[argc++] = strdup(timeout_str);
	}
	
	/* Non-interactive mode */
	argv[argc++] = "--non-inter";
	
	/* Quiet mode */
	argv[argc++] = "--quiet";
	
	/* Server (must be last argument) */
	if (port > 0) {
		char server_port[256];
		snprintf(server_port, sizeof(server_port), "%s:%d", server, port);
		argv[argc++] = strdup(server_port);
	} else {
		argv[argc++] = server;
	}
	
	argv[argc] = NULL;
	
	/* Log command */
	logmessage("openconnect", "Starting client %d: %s", unit, server);
	
	/* Update status to connecting */
	update_openconnect_status(unit, OPENCONNECT_STATE_CONNECTING, OPENCONNECT_ERRNO_NONE);
	
	/* Fork and execute openconnect */
	pid = fork();
	if (pid < 0) {
		logmessage("openconnect", "Failed to fork for client %d: %s", unit, strerror(errno));
		update_openconnect_status(unit, OPENCONNECT_STATE_ERROR, OPENCONNECT_ERRNO_UNKNOWN);
		return -1;
	}
	
	if (pid == 0) {
		/* Child process */
		
		/* Redirect stdin if password file exists */
		if (username && *username && password && *password) {
			snprintf(authfile, sizeof(authfile), "%s/auth.txt", confdir);
			int fd = open(authfile, O_RDONLY);
			if (fd >= 0) {
				dup2(fd, STDIN_FILENO);
				close(fd);
			}
		}
		
		/* Redirect stdout/stderr to log file */
		int fd = openconnect_log_open(unit);
		if (fd >= 0) {
			dup2(fd, STDOUT_FILENO);
			dup2(fd, STDERR_FILENO);
			close(fd);
		}
		
		/* Execute openconnect */
		execv(OPENCONNECT_BIN, argv);
		
		/* If we get here, exec failed */
		logmessage("openconnect", "Failed to execute openconnect for client %d: %s", unit, strerror(errno));
		exit(1);
	}
	
	/* Parent process */
	logmessage("openconnect", "Client %d started with PID %d", unit, pid);
	
	/* Free allocated strings */
	{
		int i;
		for (i = 0; i < argc; i++) {
			if (argv[i] != OPENCONNECT_BIN && argv[i] != server && 
			    argv[i] != username && argv[i] != authgroup &&
			    argv[i] != OPENCONNECT_VPNC_SCRIPT && argv[i] != pidfile &&
			    argv[i] && strstr(argv[i], confdir) == NULL) {
				/* Only free strings we allocated with strdup */
				if (strstr(argv[i], "tun") || strstr(argv[i], ":") || isdigit(argv[i][0])) {
					free(argv[i]);
				}
			}
		}
	}
	
	return 0;
}

/* Stop OpenConnect client */
void stop_openconnect_client(int unit)
{
	char pidfile[64], confdir[64];
	FILE *fp;
	int pid;
	
	if (unit < 1 || unit > OPENCONNECT_CLIENT_MAX)
		return;
	
	logmessage("openconnect", "Stopping client %d", unit);
	
	/* Get PID */
	get_pid_file(unit, pidfile, sizeof(pidfile));
	fp = fopen(pidfile, "r");
	if (fp) {
		if (fscanf(fp, "%d", &pid) == 1) {
			fclose(fp);
			
			/* Try graceful shutdown first */
			if (kill(pid, SIGTERM) == 0) {
				/* Wait up to 5 seconds for process to exit */
				int count = 0;
				while (count < 50 && kill(pid, 0) == 0) {
					usleep(100000);  /* 100ms */
					count++;
				}
				
				/* Force kill if still running */
				if (kill(pid, 0) == 0) {
					logmessage("openconnect", "Force killing client %d (PID %d)", unit, pid);
					kill(pid, SIGKILL);
				}
			}
		} else {
			fclose(fp);
		}
		unlink(pidfile);
	}
	
	/* Clean up config directory */
	snprintf(confdir, sizeof(confdir), "%s/client%d", OPENCONNECT_CONF_DIR, unit);
	eval("rm", "-rf", confdir);
	
	/* Update status */
	update_openconnect_status(unit, OPENCONNECT_STATE_STOPPED, OPENCONNECT_ERRNO_NONE);
	
	logmessage("openconnect", "Client %d stopped", unit);
}

/* Stop all OpenConnect clients */
void stop_openconnect_all(void)
{
	int unit;
	
	for (unit = 1; unit <= OPENCONNECT_CLIENT_MAX; unit++) {
		if (is_openconnect_running(unit)) {
			stop_openconnect_client(unit);
		}
	}
}

/* Handle connection up event */
void openconnect_up_handler(int unit)
{
	char varname[32];
	char *addr, *remoteaddr;
	
	if (unit < 1 || unit > OPENCONNECT_CLIENT_MAX)
		return;
	
	logmessage("openconnect", "Client %d connection established", unit);
	
	/* Update status */
	update_openconnect_status(unit, OPENCONNECT_STATE_CONNECTED, OPENCONNECT_ERRNO_NONE);
	
	/* Store IP addresses if provided via environment */
	addr = getenv("INTERNAL_IP4_ADDRESS");
	if (addr) {
		snprintf(varname, sizeof(varname), "openconnect_client%d_addr", unit);
		nvram_set(varname, addr);
	}
	
	remoteaddr = getenv("VPN_GATEWAY");
	if (remoteaddr) {
		snprintf(varname, sizeof(varname), "openconnect_client%d_rip", unit);
		nvram_set(varname, remoteaddr);
	}
	
	/* Run user script if exists */
	char script[128];
	snprintf(script, sizeof(script), "/jffs/scripts/openconnect-up.%d", unit);
	if (f_exists(script)) {
		logmessage("openconnect", "Running user script: %s", script);
		eval(script);
	}
}

/* Handle connection down event */
void openconnect_down_handler(int unit)
{
	char varname[32];
	
	if (unit < 1 || unit > OPENCONNECT_CLIENT_MAX)
		return;
	
	logmessage("openconnect", "Client %d connection terminated", unit);
	
	/* Update status */
	update_openconnect_status(unit, OPENCONNECT_STATE_STOPPED, OPENCONNECT_ERRNO_NONE);
	
	/* Clear IP addresses */
	snprintf(varname, sizeof(varname), "openconnect_client%d_addr", unit);
	nvram_set(varname, "");
	snprintf(varname, sizeof(varname), "openconnect_client%d_rip", unit);
	nvram_set(varname, "");
	
	/* Run user script if exists */
	char script[128];
	snprintf(script, sizeof(script), "/jffs/scripts/openconnect-down.%d", unit);
	if (f_exists(script)) {
		logmessage("openconnect", "Running user script: %s", script);
		eval(script);
	}
}
