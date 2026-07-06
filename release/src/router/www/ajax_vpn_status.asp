vpn_server1_status = "<% sysinfo("vpnstatus.server.1"); %>";
vpn_server2_status = "<% sysinfo("vpnstatus.server.2"); %>";
vpn_client1_status = "<% sysinfo("vpnstatus.client.1"); %>";
vpn_client2_status = "<% sysinfo("vpnstatus.client.2"); %>";
vpn_client3_status = "<% sysinfo("vpnstatus.client.3"); %>";
vpn_client4_status = "<% sysinfo("vpnstatus.client.4"); %>";
vpn_client5_status = "<% sysinfo("vpnstatus.client.5"); %>";

server1pid = "<% sysinfo("pid.vpnserver1"); %>";
server2pid = "<% sysinfo("pid.vpnserver2"); %>";
pptpdpid = "<% sysinfo("pid.pptpd"); %>";

vpn_client1_ip = "<% sysinfo("vpnip.1"); %>";
vpn_client2_ip = "<% sysinfo("vpnip.2"); %>";
vpn_client3_ip = "<% sysinfo("vpnip.3"); %>";
vpn_client4_ip = "<% sysinfo("vpnip.4"); %>";
vpn_client5_ip = "<% sysinfo("vpnip.5"); %>";

vpn_client1_rip = "<% nvram_get("vpn_client1_rip"); %>";
vpn_client2_rip = "<% nvram_get("vpn_client2_rip"); %>";
vpn_client3_rip = "<% nvram_get("vpn_client3_rip"); %>";
vpn_client4_rip = "<% nvram_get("vpn_client4_rip"); %>";
vpn_client5_rip = "<% nvram_get("vpn_client5_rip"); %>";

/* OpenConnect Client Status */
openconnect_client1_state = "<% nvram_get("openconnect_client1_state"); %>";
openconnect_client1_errno = "<% nvram_get("openconnect_client1_errno"); %>";
openconnect_client1_server = "<% nvram_get("openconnect_client1_server"); %>";
openconnect_client1_protocol = "<% nvram_get("openconnect_client1_protocol"); %>";
openconnect_client1_addr = "<% nvram_get("openconnect_client1_addr"); %>";
openconnect_client1_rip = "<% nvram_get("openconnect_client1_rip"); %>";

openconnect_client2_state = "<% nvram_get("openconnect_client2_state"); %>";
openconnect_client2_errno = "<% nvram_get("openconnect_client2_errno"); %>";
openconnect_client2_server = "<% nvram_get("openconnect_client2_server"); %>";
openconnect_client2_protocol = "<% nvram_get("openconnect_client2_protocol"); %>";
openconnect_client2_addr = "<% nvram_get("openconnect_client2_addr"); %>";
openconnect_client2_rip = "<% nvram_get("openconnect_client2_rip"); %>";
