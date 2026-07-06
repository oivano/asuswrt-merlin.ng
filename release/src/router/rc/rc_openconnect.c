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
	FILE *fp;
	char confdir[64], conffile[128], authfile[128], certfile[128], keyfile[128], cafile[128];
	char varname[32], *server, *username, *password, *authgroup, *cert, *key, *ca;
	int ret = 0;
	
	if (unit < 1 || unit > OPENCONNECT_CLIENT_MAX)
		return -1;
	
	/* Create config directory */
	snprintf(confdir, sizeof(confdir), "%s/client%d", OPENCONNECT_CONF_DIR, unit);
	mkdir(OPENCONNECT_CONF_DIR, 0700);
	mkdir(confdir, 0700);
	
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
		snprintf(authfile, sizeof(authfile), "%s/auth.txt", confdir);
		fp = fopen(authfile, "w");
		if (fp) {
			fprintf(fp, "%s\n%s\n", username, password);
			fclose(fp);
			chmod(authfile, 0600);
		} else {
			logmessage("openconnect", "Failed to write auth file for client %d", unit);
			ret = -1;
		}
	}
	
	/* Write certificate if provided */
	if (cert && *cert) {
		snprintf(certfile, sizeof(certfile), "%s/client.crt", confdir);
		fp = fopen(certfile, "w");
		if (fp) {
			fprintf(fp, "%s", cert);
			fclose(fp);
			chmod(certfile, 0600);
		}
	}
	
	/* Write key if provided */
	if (key && *key) {
		snprintf(keyfile, sizeof(keyfile), "%s/client.key", confdir);
		fp = fopen(keyfile, "w");
		if (fp) {
			fprintf(fp, "%s", key);
			fclose(fp);
			chmod(keyfile, 0600);
		}
	}
	
	/* Write CA certificate if provided */
	if (ca && *ca) {
		snprintf(cafile, sizeof(cafile), "%s/ca.crt", confdir);
		fp = fopen(cafile, "w");
		if (fp) {
			fprintf(fp, "%s", ca);
			fclose(fp);
			chmod(cafile, 0600);
		}
	}
	
	return ret;
}

/* Start OpenConnect client */
int start_openconnect_client(int unit)
{
	char varname[32], confdir[64], pidfile[64], logfile[64], authfile[128];
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
		snprintf(logfile, sizeof(logfile), "/tmp/openconnect_client%d.log", unit);
		int fd = open(logfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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
