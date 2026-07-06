/*
 * frr_web.h - FRR WebUI Backend Functions
 * AsusWRT-Merlin FRR Integration
 */

#ifndef _FRR_WEB_H_
#define _FRR_WEB_H_

/* ASP function prototypes for FRR status and configuration */

/* Get FRR enable status */
extern int ej_get_frr_enabled(int eid, webs_t wp, int argc, char_t **argv);

/* Get FRR daemon running status */
extern int ej_get_frr_daemon_status(int eid, webs_t wp, int argc, char_t **argv);

/* Get BGP configuration */
extern int ej_get_frr_bgp_config(int eid, webs_t wp, int argc, char_t **argv);

/* Get BGP neighbors for UI table (NVRAM, fallback to /etc/frr.conf) */
extern int ej_get_frr_bgp_neighbor_list(int eid, webs_t wp, int argc, char_t **argv);
extern int ej_get_frr_bgp_neighbor_as_list(int eid, webs_t wp, int argc, char_t **argv);
extern int ej_get_frr_bgp_neighbor_desc_list(int eid, webs_t wp, int argc, char_t **argv);
extern int ej_get_frr_bgp_neighbor_src_list(int eid, webs_t wp, int argc, char_t **argv);

/* Get OSPF configuration */
extern int ej_get_frr_ospf_config(int eid, webs_t wp, int argc, char_t **argv);

/* Get BFD configuration */
extern int ej_get_frr_bfd_config(int eid, webs_t wp, int argc, char_t **argv);

/* Get route origin/active metadata from live FRR routing tables */
extern int ej_get_frr_route_origin_array(int eid, webs_t wp, int argc, char_t **argv);

/* Helper function to check if a daemon PID file exists and process is running */
extern int frr_daemon_running(const char *daemon_name);

/* Helper function to read FRR daemon uptime from PID file */
extern unsigned long frr_daemon_uptime(const char *daemon_name);

#endif /* _FRR_WEB_H_ */
