/*
 * frr_web.c - FRR WebUI Backend Functions
 * AsusWRT-Merlin FRR Integration
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>

#include <bcmnvram.h>
#include <shutils.h>

#include "httpd.h"
#include "frr_web.h"

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
