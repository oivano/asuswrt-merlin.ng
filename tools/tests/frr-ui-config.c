#define _GNU_SOURCE
#include <assert.h>
#include <frr_ui_config.h>

static char *generate(json_object *request)
{
	char *data = NULL;
	size_t size = 0;
	FILE *out = open_memstream(&data, &size);
	assert(out);
	assert(frr_ui_generate(out, request, "192.0.2.254", "DSL-AC68U"));
	assert(fclose(out) == 0);
	return data;
}

static char *merge(const char *old, const char *next)
{
	char *data = NULL;
	size_t size = 0;
	FILE *out = open_memstream(&data, &size);
	assert(out);
	assert(frr_ui_merge(out, old, next));
	assert(fclose(out) == 0);
	return data;
}

int main(void)
{
	const char *original =
		"frr version 8.1\npassword old-password\nenable password old-enable\n"
		"route-map KEEP permit 10\n set metric 99\n!\n"
		"router bgp 65000\n neighbor CORE peer-group\n neighbor CORE remote-as 65001\n"
		" neighbor 192.0.2.1 peer-group CORE\n neighbor 192.0.2.1 route-map KEEP in\n"
		" address-family ipv4 unicast\n  network 10.0.0.0/8 route-map KEEP\n"
		"  neighbor 192.0.2.1 activate\n exit-address-family\n"
		" address-family ipv6 unicast\n  network 2001:db8::/32\n exit-address-family\nexit\n"
		"router ospf\n network 10.0.0.0/8 area 0\n passive-interface eth0\nexit\n"
		"bfd\n peer 192.0.2.1 local-address 192.0.2.254\n  transmit-interval 100\n"
		"  receive-interval 150\n  detect-multiplier 5\n exit\n"
		" peer 192.0.2.2\n  transmit-interval 200\n  receive-interval 250\n exit\nexit\n"
		"access-list vty permit 127.0.0.0/8\naccess-list vty deny any\nline vty\n access-class vty\n!\n";
	const char *request_text =
		"{\"frr_passwd\":\"new-password\",\"frr_enpasswd\":\"new-enable\","
		"\"frr_bgp_enable\":\"1\",\"frr_bgp_as\":\"65000\",\"frr_bgp_networks\":\"10.0.0.0/8\\n192.0.2.0/24\","
		"\"frr_ospf_enable\":\"1\",\"frr_ospf_area\":\"0\",\"frr_ospf_networks\":\"10.0.0.0/8\","
		"\"frr_bfd_enable\":\"1\",\"bgp_peers\":{"
		"\"192.0.2.1\":{\"as_number\":\"65001\",\"description\":\"edited > peer\",\"source\":\"lo\"},"
		"\"192.0.2.3\":{\"as_number\":\"4294967295\",\"description\":\"new peer\"}},"
		"\"bfd_peers\":{\"192.0.2.1\":{\"tx\":\"300\",\"rx\":\"350\",\"options\":\" local-address 192.0.2.254\"},"
		"\"192.0.2.2\":{\"tx\":\"200\",\"rx\":\"250\"},\"192.0.2.3\":{\"tx\":\"400\",\"rx\":\"450\"}}}";
	json_object *request = json_tokener_parse(request_text);
	json_object *parsed = frr_ui_parse(original);
	json_object *peers, *peer;
	char *generated, *merged, *again;
	char asn[32];
	char *empty = frr_ui_read_file("/dev/null");
	assert(empty && !*empty);
	free(empty);
	assert(request && parsed);
	frr_ui_parse_daemons(parsed, " bgpd = 'yes'\nospfd=\"no\"\nbfdd=yes # enabled\n");
	assert(!strcmp(frr_ui_string(parsed, "frr_bgp_enable"), "1"));
	assert(!strcmp(frr_ui_string(parsed, "frr_ospf_enable"), "0"));
	assert(!strcmp(frr_ui_string(parsed, "frr_bfd_enable"), "1"));
	{
		char *flags = NULL;
		size_t flag_size = 0;
		FILE *flag_output = open_memstream(&flags, &flag_size);
		assert(flag_output);
		assert(frr_ui_merge_daemons(flag_output, "zebra=yes\nbgpd=no\nbgpd_options=\"--custom-option\"\nwatchfrr_options=\"keep\"\n", request));
		assert(fclose(flag_output) == 0);
		assert(strstr(flags, "bgpd=yes\n"));
		assert(strstr(flags, "bgpd_options=\"--custom-option\"\n"));
		assert(strstr(flags, "watchfrr_options=\"keep\"\n"));
		free(flags);
	}
	assert(frr_ui_request_valid(request));
	assert(!frr_ui_interval("9") && !frr_ui_interval("60001") && !frr_ui_interval("150ms"));
	assert(frr_ui_interval("10") && frr_ui_interval("60000"));
	assert(!strcmp(frr_ui_string(parsed, "frr_bgp_as"), "65000"));
	json_object_object_get_ex(parsed, "bgp_peers", &peers);
	assert(json_object_object_get_ex(peers, "192.0.2.1", &peer));
	assert(!strcmp(frr_ui_string(peer, "as_number"), "65001"));
	json_object_object_get_ex(parsed, "bfd_peers", &peers);
	assert(json_object_object_length(peers) == 2);
	assert(frr_ui_as("65535.65535", asn, sizeof(asn)) && !strcmp(asn, "4294967295"));
	assert(!frr_ui_as("4294967296", asn, sizeof(asn)));
	assert(!frr_ui_as("123junk", asn, sizeof(asn)));
	generated = generate(request);
	merged = merge(original, generated);
	assert(strstr(merged, "password new-password\n"));
	assert(strstr(merged, "neighbor CORE remote-as 65001\n"));
	assert(strstr(merged, "neighbor 192.0.2.1 route-map KEEP in\n"));
	assert(strstr(merged, "network 10.0.0.0/8 route-map KEEP\n"));
	assert(strstr(merged, "network 2001:db8::/32\n"));
	assert(strstr(merged, "detect-multiplier 5\n"));
	assert(strstr(merged, "neighbor 192.0.2.3 remote-as 4294967295\n"));
	assert(strstr(merged, "peer 192.0.2.3\n"));
	again = merge(merged, generated);
	assert(!strcmp(merged, again));
	free(again);
	free(merged);
	merged = merge("password original\n!\n", generated);
	assert(strstr(merged, "router bgp 65000\n"));
	assert(strstr(merged, "router ospf\n"));
	assert(strstr(merged, "peer 192.0.2.3\n"));
	again = merge(merged, generated);
	assert(!strcmp(merged, again));
	free(again);
	free(merged);
	json_object_object_get_ex(request, "bgp_peers", &peers);
	json_object_object_del(peers, "192.0.2.1");
	json_object_object_get_ex(request, "bfd_peers", &peers);
	json_object_object_del(peers, "192.0.2.1");
	free(generated);
	generated = generate(request);
	merged = merge(original, generated);
	assert(!strstr(merged, "neighbor 192.0.2.1 "));
	assert(!strstr(merged, "peer 192.0.2.1 "));
	assert(strstr(merged, "neighbor CORE remote-as 65001\n"));
	assert(strstr(merged, "peer 192.0.2.2\n"));
	free(merged);
	free(generated);
	json_object_put(parsed);
	json_object_put(request);
	puts("PASS: config parsing, inherited peers, AS bounds, merged edits, new BGP/BFD peers, custom settings, idempotence");
	return 0;
}