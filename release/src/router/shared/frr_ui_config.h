#ifndef FRR_UI_CONFIG_H
#define FRR_UI_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <arpa/inet.h>
#include <json.h>

#define FRR_UI_MAX_CONFIG 524288

static const char *frr_ui_string(json_object *object, const char *key)
{
	json_object *value;
	const char *text;
	if (!object || !json_object_object_get_ex(object, key, &value))
		return "";
	text = json_object_get_string(value);
	return text ? text : "";
}

static void frr_ui_set(json_object *object, const char *key, const char *value)
{
	json_object_object_add(object, key, json_object_new_string(value));
}

static char *frr_ui_trim(char *line)
{
	size_t length;
	while (isspace((unsigned char)*line)) line++;
	length = strlen(line);
	while (length && isspace((unsigned char)line[length - 1])) line[--length] = '\0';
	return line;
}

static int frr_ui_as(const char *text, char *result, size_t size)
{
	char *end;
	unsigned long high, low;
	unsigned long long value;
	if (!*text || strspn(text, "0123456789.") != strlen(text)) return 0;
	errno = 0;
	high = strtoul(text, &end, 10);
	if (errno || end == text) return 0;
	value = high;
	if (*end == '.') {
		const char *tail = end + 1;
		low = strtoul(tail, &end, 10);
		if (errno || end == tail || *end || high > 65535 || low > 65535) return 0;
		value = (unsigned long long)high * 65536 + low;
	} else if (*end) return 0;
	if (!value || value > 4294967295ULL) return 0;
	snprintf(result, size, "%llu", value);
	return 1;
}

static json_object *frr_ui_entry(json_object *map, const char *name)
{
	json_object *entry;
	if (!json_object_object_get_ex(map, name, &entry)) {
		entry = json_object_new_object();
		json_object_object_add(map, name, entry);
	}
	return entry;
}

static void frr_ui_network(json_object *config, const char *key, const char *network)
{
	const char *old = frr_ui_string(config, key);
	size_t size = strlen(old) + strlen(network) + 2;
	char *value = malloc(size);
	if (!value) return;
	snprintf(value, size, "%s%s%s", old, *old ? "\n" : "", network);
	frr_ui_set(config, key, value);
	free(value);
}

static char *frr_ui_read_file(const char *path)
{
	FILE *fp = fopen(path, "r");
	long length;
	char *data;
	if (!fp) return NULL;
	if (fseek(fp, 0, SEEK_END) || (length = ftell(fp)) < 0 || length > FRR_UI_MAX_CONFIG) {
		fclose(fp);
		errno = EFBIG;
		return NULL;
	}
	rewind(fp);
	data = malloc(length + 1);
	if (!data || fread(data, 1, length, fp) != (size_t)length) {
		free(data);
		fclose(fp);
		errno = EIO;
		return NULL;
	}
	data[length] = '\0';
	fclose(fp);
	return data;
}

static json_object *frr_ui_parse(const char *data)
{
	json_object *config = json_object_new_object();
	json_object *bgp = json_object_new_object();
	json_object *bfd = json_object_new_object();
	json_object *peer = NULL;
	char *copy = strdup(data);
	char *cursor = copy;
	char *line;
	char name[128], command[64], argument[1024], extra[64], asn[32];
	int section = 0;
	int family = 1;
	int fields;
	if (!config || !bgp || !bfd || !copy) {
		if (config) json_object_put(config);
		if (bgp) json_object_put(bgp);
		if (bfd) json_object_put(bfd);
		free(copy);
		return NULL;
	}
	json_object_object_add(config, "bgp_peers", bgp);
	json_object_object_add(config, "bfd_peers", bfd);
	frr_ui_set(config, "frr_bgp_enable", "0");
	frr_ui_set(config, "frr_ospf_enable", "0");
	frr_ui_set(config, "frr_bfd_enable", "0");
	frr_ui_set(config, "frr_allow_lan", "0");
	while ((line = strsep(&cursor, "\n")) != NULL) {
		char *text = frr_ui_trim(line);
		if (!*text || *text == '!' || *text == '#') continue;
		if (!strncmp(text, "router bgp ", 11)) {
			fields = sscanf(text + 11, "%127s %63s", name, extra);
			section = fields == 1 && frr_ui_as(name, asn, sizeof(asn)) ? 1 : 0;
			if (section) {
				frr_ui_set(config, "frr_bgp_as", asn);
				frr_ui_set(config, "frr_bgp_enable", "1");
			}
			continue;
		}
		if (section == 1 && !strncmp(text, "address-family ", 15)) {
			family = !strcmp(text + 15, "ipv4 unicast");
			continue;
		}
		if (!strcmp(text, "exit-address-family")) { family = 1; continue; }
		if (section == 1 && !strncmp(text, "bgp router-id ", 14)) frr_ui_set(config, "frr_bgp_router_id", text + 14);
		if (section == 2 && !strncmp(text, "ospf router-id ", 15)) frr_ui_set(config, "frr_ospf_router_id", text + 15);
		if (!strcmp(text, "router ospf")) {
			section = 2;
			frr_ui_set(config, "frr_ospf_enable", "1");
			continue;
		}
		if (!strcmp(text, "bfd")) {
			section = 3;
			peer = NULL;
			frr_ui_set(config, "frr_bfd_enable", "1");
			continue;
		}
		if (text == line || !strcmp(text, "exit")) {
			if (section == 3 && peer && text != line && !strcmp(text, "exit")) {
				peer = NULL;
				continue;
			}
			section = 0;
			peer = NULL;
		}
		if (!strncmp(text, "password ", 9)) frr_ui_set(config, "frr_passwd", text + 9);
		else if (!strncmp(text, "enable password ", 16)) frr_ui_set(config, "frr_enpasswd", text + 16);
		else if (!strncmp(text, "access-list vty permit ", 23) && strcmp(text + 23, "127.0.0.0/8")) {
			frr_ui_set(config, "frr_allow_lan", "1");
			frr_ui_set(config, "frr_lan_acl", text + 23);
		}
		if (section == 1 && !strncmp(text, "neighbor ", 9)) {
			fields = sscanf(text + 9, "%127s %63s %1023[^\n]", name, command, argument);
			if (fields < 3) continue;
			peer = frr_ui_entry(bgp, name);
			if (!strcmp(command, "remote-as")) {
				frr_ui_set(peer, "as_number", frr_ui_as(argument, asn, sizeof(asn)) ? asn : argument);
			} else if (!strcmp(command, "description")) frr_ui_set(peer, "description", argument);
			else if (!strcmp(command, "update-source")) frr_ui_set(peer, "source", argument);
			else if (!strcmp(command, "peer-group")) frr_ui_set(peer, "group", argument);
		} else if (section == 1 && family && !strncmp(text, "network ", 8)) {
			if (sscanf(text + 8, "%127s", name) == 1 && strchr(name, '.'))
				frr_ui_network(config, "frr_bgp_networks", name);
		} else if (section == 2 && sscanf(text, "network %127s area %63s", name, extra) == 2) {
			frr_ui_network(config, "frr_ospf_networks", name);
			if (!*frr_ui_string(config, "frr_ospf_area")) frr_ui_set(config, "frr_ospf_area", extra);
		} else if (section == 3 && !strncmp(text, "peer ", 5)) {
			if (sscanf(text + 5, "%127s", name) != 1) continue;
			peer = frr_ui_entry(bfd, name);
			if (*frr_ui_string(peer, "tx") && strcmp(frr_ui_string(peer, "options"), text + 5 + strlen(name)))
				frr_ui_set(config, "error", "Multiple BFD sessions share a peer address; edit the configuration file directly");
			frr_ui_set(peer, "options", text + 5 + strlen(name));
			frr_ui_set(peer, "tx", "300");
			frr_ui_set(peer, "rx", "300");
		} else if (section == 3 && peer) {
			if (!strncmp(text, "transmit-interval ", 18)) frr_ui_set(peer, "tx", text + 18);
			else if (!strncmp(text, "receive-interval ", 17)) frr_ui_set(peer, "rx", text + 17);
		}
	}
	json_object_object_foreach(bgp, peer_name, peer_config) {
		json_object *group = NULL;
		json_object *field;
		const char *keys[] = {"as_number", "description", "source"};
		int index;
		const char *group_name = frr_ui_string(peer_config, "group");
		unsigned char address[16];
		json_object_object_add(peer_config, "is_peer", json_object_new_boolean(
			inet_pton(AF_INET, peer_name, address) == 1 || inet_pton(AF_INET6, peer_name, address) == 1));
		if (*group_name) json_object_object_get_ex(bgp, group_name, &group);
		for (index = 0; group && index < 3; index++) {
			if (!json_object_object_get_ex(peer_config, keys[index], &field) &&
			    json_object_object_get_ex(group, keys[index], &field))
				json_object_object_add(peer_config, keys[index], json_object_get(field));
		}
	}
	free(copy);
	return config;
}

static int frr_ui_interval(const char *text)
{
	unsigned long value;
	char *end;
	if (!*text || strspn(text, "0123456789") != strlen(text)) return 0;
	errno = 0;
	value = strtoul(text, &end, 10);
	return !errno && !*end && value >= 10 && value <= 60000;
}

static int frr_ui_request_valid(json_object *config)
{
	json_object *peers;
	const char *maps[] = {"bgp_peers", "bfd_peers"};
	const char *networks[] = {"frr_bgp_networks", "frr_ospf_networks"};
	int index;
	char asn[32];
	unsigned char address[16];
	if (!config || !json_object_is_type(config, json_type_object)) return 0;
	json_object_object_foreach(config, key, value) {
		if (!strcmp(key, "bgp_peers") || !strcmp(key, "bfd_peers")) {
			if (!json_object_is_type(value, json_type_object)) return 0;
		} else {
			if (!json_object_is_type(value, json_type_string)) return 0;
			if (strcmp(key, "frr_bgp_networks") && strcmp(key, "frr_ospf_networks") &&
			    strpbrk(json_object_get_string(value), "\r\n")) return 0;
		}
	}
	if (!strcmp(frr_ui_string(config, "frr_bgp_enable"), "1") &&
	    !frr_ui_as(frr_ui_string(config, "frr_bgp_as"), asn, sizeof(asn))) return 0;
	if (!strcmp(frr_ui_string(config, "frr_ospf_enable"), "1")) {
		const char *area = frr_ui_string(config, "frr_ospf_area");
		if (*area && inet_pton(AF_INET, area, address) != 1) {
			char *end;
			unsigned long long value;
			if (strspn(area, "0123456789") != strlen(area)) return 0;
			errno = 0;
			value = strtoull(area, &end, 10);
			if (errno || *end || value > 4294967295ULL) return 0;
		}
	}
	for (index = 0; index < 2; index++) {
		if (!json_object_object_get_ex(config, maps[index], &peers)) continue;
		json_object_object_foreach(peers, peer_name, peer_config) {
			if (inet_pton(AF_INET, peer_name, address) != 1 && inet_pton(AF_INET6, peer_name, address) != 1) return 0;
			if (!json_object_is_type(peer_config, json_type_object)) return 0;
			json_object_object_foreach(peer_config, property, field) {
				if (strcmp(property, "as_number") && strcmp(property, "description") && strcmp(property, "source") &&
				    strcmp(property, "tx") && strcmp(property, "rx") && strcmp(property, "options")) return 0;
				if (!json_object_is_type(field, json_type_string) || strpbrk(json_object_get_string(field), "\r\n")) return 0;
			}
			if (!index) {
				const char *remote = frr_ui_string(peer_config, "as_number");
				if (!frr_ui_as(remote, asn, sizeof(asn)) && strcmp(remote, "internal") && strcmp(remote, "external")) return 0;
			} else if (!frr_ui_interval(frr_ui_string(peer_config, "tx")) || !frr_ui_interval(frr_ui_string(peer_config, "rx"))) return 0;
		}
	}
	for (index = 0; index < 2; index++) {
		char *copy = strdup(frr_ui_string(config, networks[index]));
		char *cursor = copy, *network;
		if (!copy) return 0;
		while ((network = strsep(&cursor, " \t\r\n>")) != NULL) {
			char *slash, *end;
			long prefix;
			if (!*network) continue;
			slash = strchr(network, '/');
			if (!slash) { free(copy); return 0; }
			*slash++ = '\0';
			if (inet_pton(AF_INET, network, address) != 1 || !*slash || strspn(slash, "0123456789") != strlen(slash)) { free(copy); return 0; }
			errno = 0;
			prefix = strtol(slash, &end, 10);
			if (errno || *end || prefix < 0 || prefix > 32) { free(copy); return 0; }
		}
		free(copy);
	}
	return 1;
}

static int frr_ui_generate(FILE *out, json_object *config, const char *lan_ip,
			   const char *hostname)
{
	json_object *peers;
	char *copy, *cursor, *network;
	if (!frr_ui_request_valid(config)) return 0;
	fprintf(out, "frr version 8.1\nfrr defaults traditional\nhostname %s\n", hostname);
	if (*frr_ui_string(config, "frr_passwd")) fprintf(out, "password %s\n", frr_ui_string(config, "frr_passwd"));
	if (*frr_ui_string(config, "frr_enpasswd")) fprintf(out, "enable password %s\n", frr_ui_string(config, "frr_enpasswd"));
	fprintf(out, "log syslog informational\nservice integrated-vtysh-config\n!\n");
	if (!strcmp(frr_ui_string(config, "frr_bgp_enable"), "1")) {
		fprintf(out, "router bgp %s\n bgp router-id %s\n", frr_ui_string(config, "frr_bgp_as"), lan_ip);
		if (json_object_object_get_ex(config, "bgp_peers", &peers)) {
			json_object_object_foreach(peers, peer_name, peer_config) {
				fprintf(out, " neighbor %s remote-as %s\n", peer_name, frr_ui_string(peer_config, "as_number"));
				if (*frr_ui_string(peer_config, "description")) fprintf(out, " neighbor %s description %s\n", peer_name, frr_ui_string(peer_config, "description"));
				if (*frr_ui_string(peer_config, "source")) fprintf(out, " neighbor %s update-source %s\n", peer_name, frr_ui_string(peer_config, "source"));
			}
		}
		fprintf(out, " address-family ipv4 unicast\n");
		copy = strdup(frr_ui_string(config, "frr_bgp_networks"));
		if (!copy) return 0;
		cursor = copy;
		while ((network = strsep(&cursor, " \t\r\n>")) != NULL)
			if (*network) fprintf(out, "  network %s\n", network);
		free(copy);
		if (json_object_object_get_ex(config, "bgp_peers", &peers)) {
			json_object_object_foreach(peers, peer_name, peer_config) {
				fprintf(out, "  neighbor %s activate\n", peer_name);
			}
		}
		fprintf(out, " exit-address-family\nexit\n!\n");
	}
	if (!strcmp(frr_ui_string(config, "frr_ospf_enable"), "1")) {
		const char *area = frr_ui_string(config, "frr_ospf_area");
		fprintf(out, "router ospf\n ospf router-id %s\n", lan_ip);
		copy = strdup(frr_ui_string(config, "frr_ospf_networks"));
		if (!copy) return 0;
		cursor = copy;
		while ((network = strsep(&cursor, " \t\r\n>")) != NULL)
			if (*network) fprintf(out, " network %s area %s\n", network, *area ? area : "0");
		free(copy);
		fprintf(out, "exit\n!\n");
	}
	if (!strcmp(frr_ui_string(config, "frr_bfd_enable"), "1")) {
		fprintf(out, "bfd\n");
		if (json_object_object_get_ex(config, "bfd_peers", &peers)) {
			json_object_object_foreach(peers, peer_name, peer_config) {
				fprintf(out, " peer %s%s\n  transmit-interval %s\n  receive-interval %s\n exit\n", peer_name,
					frr_ui_string(peer_config, "options"), frr_ui_string(peer_config, "tx"), frr_ui_string(peer_config, "rx"));
			}
		}
		fprintf(out, "exit\n!\n");
	}
	return !ferror(out);
}

static int frr_ui_has_network(const char *list, const char *network)
{
	char *copy = strdup(list);
	char *cursor = copy;
	char *token;
	int found = 0;
	if (!copy) return 0;
	while ((token = strsep(&cursor, " \t\r\n>")) != NULL) {
		if (!strcmp(token, network)) { found = 1; break; }
	}
	free(copy);
	return found;
}

static int frr_ui_merge(FILE *out, const char *original, const char *generated)
{
	json_object *old = frr_ui_parse(original);
	json_object *next = frr_ui_parse(generated);
	json_object *old_bgp, *next_bgp, *old_bfd, *next_bfd;
	json_object *entry, *previous;
	json_object *bgp_networks = json_object_new_object();
	json_object *ospf_networks = json_object_new_object();
	char *copy = strdup(original);
	char *cursor = copy;
	char *line;
	char name[128], command[64], argument[1024];
	char bfd_name[128] = "";
	int section = 0;
	int family = 1;
	int drop_peer = 0;
	int seen_password = 0, seen_enable_password = 0;
	int seen_lan = 0;
	int pending_bgp = 0, pending_ospf = 0, pending_bfd = 0;
	int fields;
	unsigned char address[16];
	if (!old || !next || !copy || !bgp_networks || !ospf_networks) goto fail;
	if (*frr_ui_string(old, "error") || *frr_ui_string(next, "error")) goto fail;
	json_object_object_get_ex(old, "bgp_peers", &old_bgp);
	json_object_object_get_ex(next, "bgp_peers", &next_bgp);
	json_object_object_get_ex(old, "bfd_peers", &old_bfd);
	json_object_object_get_ex(next, "bfd_peers", &next_bfd);
	if (!*frr_ui_string(old, "frr_bgp_as") && *frr_ui_string(next, "frr_bgp_as")) pending_bgp = 1;
	if (strcmp(frr_ui_string(old, "frr_ospf_enable"), "1") && !strcmp(frr_ui_string(next, "frr_ospf_enable"), "1")) pending_ospf = 1;
	while ((line = strsep(&cursor, "\n")) != NULL) {
		char *trimmed = strdup(line);
		char *text;
		int handled = 0;
		if (!trimmed) goto fail;
		if (!*line && !cursor) { free(trimmed); break; }
		text = frr_ui_trim(trimmed);
		if (!strncmp(text, "router bgp ", 11)) {
			fields = sscanf(text + 11, "%127s %63s", name, command);
			section = fields == 1 ? 1 : 0;
			if (section && *frr_ui_string(next, "frr_bgp_as")) {
				fprintf(out, "router bgp %s\n", frr_ui_string(next, "frr_bgp_as"));
				handled = 1;
			}
		} else if (!strcmp(text, "router ospf")) section = 2;
		else if (!strcmp(text, "bfd")) { section = 3; drop_peer = 0; }
		else if (section == 1 && !strncmp(text, "address-family ", 15)) family = !strcmp(text + 15, "ipv4 unicast");
		else if (!strcmp(text, "exit-address-family")) family = 1;
		else if (*text && *text != '!' && *text != '#' && text == trimmed) {
			section = 0;
			drop_peer = 0;
		}
		if (!strncmp(text, "password ", 9)) {
			if (!seen_password && *frr_ui_string(next, "frr_passwd"))
				fprintf(out, "password %s\n", frr_ui_string(next, "frr_passwd"));
			seen_password = handled = 1;
		} else if (!strncmp(text, "enable password ", 16)) {
			if (!seen_enable_password && *frr_ui_string(next, "frr_enpasswd"))
				fprintf(out, "enable password %s\n", frr_ui_string(next, "frr_enpasswd"));
			seen_enable_password = handled = 1;
		} else if (!strncmp(text, "access-list vty permit ", 23) && strcmp(text + 23, "127.0.0.0/8")) {
			if (!strcmp(frr_ui_string(old, "frr_allow_lan"), frr_ui_string(next, "frr_allow_lan")))
				fprintf(out, "%s\n", line);
			else if (!seen_lan && *frr_ui_string(next, "frr_lan_acl"))
				fprintf(out, "access-list vty permit %s\n", frr_ui_string(next, "frr_lan_acl"));
			seen_lan = handled = 1;
		} else if (!strcmp(text, "access-list vty deny any")) {
			if (!seen_lan && *frr_ui_string(next, "frr_lan_acl"))
				fprintf(out, "access-list vty permit %s\n", frr_ui_string(next, "frr_lan_acl"));
			seen_lan = 1;
		} else if (section == 1 && !strcmp(frr_ui_string(next, "frr_bgp_enable"), "1") && !strncmp(text, "neighbor ", 9)) {
			fields = sscanf(text + 9, "%127s %63s %1023[^\n]", name, command, argument);
			if (fields >= 2 && (inet_pton(AF_INET, name, address) == 1 || inet_pton(AF_INET6, name, address) == 1) &&
			    json_object_object_get_ex(old_bgp, name, &previous) &&
			    *frr_ui_string(previous, "as_number")) {
				if (!json_object_object_get_ex(next_bgp, name, &entry)) handled = 1;
				else {
					const char *key = NULL;
					if (!strcmp(command, "remote-as")) key = "as_number";
					else if (!strcmp(command, "description")) key = "description";
					else if (!strcmp(command, "update-source")) key = "source";
					if (key) {
						if (!strcmp(frr_ui_string(entry, key), frr_ui_string(previous, key))) {
							fprintf(out, "%s\n", line);
						} else if (*frr_ui_string(entry, key)) {
							fprintf(out, " neighbor %s %s %s\n", name, command, frr_ui_string(entry, key));
						}
						json_object_object_add(entry, command, json_object_new_boolean(1));
						handled = 1;
					}
				}
			}
		} else if (((section == 1 && family) || section == 2) && !strncmp(text, "network ", 8)) {
			const char *enable = section == 1 ? "frr_bgp_enable" : "frr_ospf_enable";
			const char *key = section == 1 ? "frr_bgp_networks" : "frr_ospf_networks";
			if (!strcmp(frr_ui_string(next, enable), "1") && sscanf(text + 8, "%127s", name) == 1 && strchr(name, '.')) {
				if (frr_ui_has_network(frr_ui_string(next, key), name)) {
					if (section == 2 && strcmp(frr_ui_string(old, "frr_ospf_area"), frr_ui_string(next, "frr_ospf_area")))
						fprintf(out, " network %s area %s\n", name, frr_ui_string(next, "frr_ospf_area"));
					else fprintf(out, "%s\n", line);
					json_object_object_add(section == 1 ? bgp_networks : ospf_networks, name, json_object_new_boolean(1));
				}
				handled = 1;
			}
		} else if (section == 3 && !strcmp(frr_ui_string(next, "frr_bfd_enable"), "1") && !strncmp(text, "peer ", 5)) {
			if (sscanf(text + 5, "%127s", bfd_name) == 1) {
				drop_peer = !json_object_object_get_ex(next_bfd, bfd_name, &entry);
				if (!drop_peer) json_object_object_add(entry, "seen_peer", json_object_new_boolean(1));
			}
		} else if (section == 3 && !strcmp(frr_ui_string(next, "frr_bfd_enable"), "1") && (!strncmp(text, "transmit-interval ", 18) ||
					 !strncmp(text, "receive-interval ", 17))) {
			if (json_object_object_get_ex(next_bfd, bfd_name, &entry)) {
				const char *key = *text == 't' ? "tx" : "rx";
				const char *verb = *text == 't' ? "transmit-interval" : "receive-interval";
				fprintf(out, "  %s %s\n", verb, frr_ui_string(entry, key));
				json_object_object_add(entry, verb, json_object_new_boolean(1));
				handled = 1;
			}
		}
		if (!handled && !(section == 3 && drop_peer)) fprintf(out, "%s\n", line);
		free(trimmed);
	}
	if (!seen_password && *frr_ui_string(next, "frr_passwd")) fprintf(out, "password %s\n", frr_ui_string(next, "frr_passwd"));
	if (!seen_enable_password && *frr_ui_string(next, "frr_enpasswd")) fprintf(out, "enable password %s\n", frr_ui_string(next, "frr_enpasswd"));
	json_object_object_foreach(next_bgp, peer_name, peer_config) {
		const char *keys[] = {"as_number", "description", "source"};
		const char *verbs[] = {"remote-as", "description", "update-source"};
		json_object *seen;
		int index;
		previous = NULL;
		json_object_object_get_ex(old_bgp, peer_name, &previous);
		for (index = 0; index < 3; index++) {
			if (*frr_ui_string(peer_config, keys[index]) && !json_object_object_get_ex(peer_config, verbs[index], &seen)) {
				if (previous && !strcmp(frr_ui_string(peer_config, keys[index]), frr_ui_string(previous, keys[index])))
					json_object_object_add(peer_config, verbs[index], json_object_new_boolean(1));
				else pending_bgp = 1;
			}
		}
	}
	{
		char *networks = strdup(frr_ui_string(next, "frr_bgp_networks"));
		char *network_cursor = networks, *network;
		json_object *seen;
		if (!networks) goto fail;
		while ((network = strsep(&network_cursor, "\n")) != NULL)
			if (*network && !json_object_object_get_ex(bgp_networks, network, &seen)) pending_bgp = 1;
		free(networks);
	}
	if (pending_bgp && *frr_ui_string(next, "frr_bgp_as")) {
		fprintf(out, "router bgp %s\n", frr_ui_string(next, "frr_bgp_as"));
		if (!*frr_ui_string(old, "frr_bgp_as") && *frr_ui_string(next, "frr_bgp_router_id"))
			fprintf(out, " bgp router-id %s\n", frr_ui_string(next, "frr_bgp_router_id"));
		json_object_object_foreach(next_bgp, peer_name, peer_config) {
			const char *keys[] = {"as_number", "description", "source"};
			const char *verbs[] = {"remote-as", "description", "update-source"};
			int index;
			json_object *seen;
			for (index = 0; index < 3; index++) {
				if (*frr_ui_string(peer_config, keys[index]) &&
				    !json_object_object_get_ex(peer_config, verbs[index], &seen))
					fprintf(out, " neighbor %s %s %s\n", peer_name, verbs[index], frr_ui_string(peer_config, keys[index]));
			}
		}
		fprintf(out, " address-family ipv4 unicast\n");
		{
			char *networks = strdup(frr_ui_string(next, "frr_bgp_networks"));
			char *network_cursor = networks, *network;
			json_object *seen;
			if (!networks) goto fail;
			while ((network = strsep(&network_cursor, "\n")) != NULL)
				if (*network && !json_object_object_get_ex(bgp_networks, network, &seen)) fprintf(out, "  network %s\n", network);
			free(networks);
		}
		json_object_object_foreach(next_bgp, activate_name, activate_config) {
			if (!json_object_object_get_ex(old_bgp, activate_name, &previous))
				fprintf(out, "  neighbor %s activate\n", activate_name);
		}
		fprintf(out, " exit-address-family\nexit\n!\n");
	}
	if (!strcmp(frr_ui_string(next, "frr_ospf_enable"), "1")) {
		char *networks = strdup(frr_ui_string(next, "frr_ospf_networks"));
		char *network_cursor = networks, *network;
		const char *area = frr_ui_string(next, "frr_ospf_area");
		json_object *seen;
		if (!networks) goto fail;
		if (pending_ospf) {
			fprintf(out, "router ospf\n");
			if (*frr_ui_string(next, "frr_ospf_router_id")) fprintf(out, " ospf router-id %s\n", frr_ui_string(next, "frr_ospf_router_id"));
		}
		while ((network = strsep(&network_cursor, "\n")) != NULL) {
			if (*network && !json_object_object_get_ex(ospf_networks, network, &seen)) {
				if (!pending_ospf) fprintf(out, "router ospf\n");
				pending_ospf = 1;
				fprintf(out, " network %s area %s\n", network, *area ? area : "0");
			}
		}
		if (pending_ospf) fprintf(out, "exit\n!\n");
		free(networks);
	}
	if (!strcmp(frr_ui_string(next, "frr_bfd_enable"), "1")) {
		json_object_object_foreach(next_bfd, peer_name, peer_config) {
			json_object *seen;
			int new_peer = !json_object_object_get_ex(peer_config, "seen_peer", &seen);
			int tx_pending = !json_object_object_get_ex(peer_config, "transmit-interval", &seen);
			int rx_pending = !json_object_object_get_ex(peer_config, "receive-interval", &seen);
			if (json_object_object_get_ex(old_bfd, peer_name, &previous)) {
				if (!strcmp(frr_ui_string(previous, "tx"), frr_ui_string(peer_config, "tx"))) tx_pending = 0;
				if (!strcmp(frr_ui_string(previous, "rx"), frr_ui_string(peer_config, "rx"))) rx_pending = 0;
			}
			if (!new_peer && !tx_pending && !rx_pending) continue;
			if (!pending_bfd) fprintf(out, "bfd\n");
			pending_bfd = 1;
			fprintf(out, " peer %s%s\n", peer_name, frr_ui_string(peer_config, "options"));
			if (new_peer || tx_pending) fprintf(out, "  transmit-interval %s\n", frr_ui_string(peer_config, "tx"));
			if (new_peer || rx_pending) fprintf(out, "  receive-interval %s\n", frr_ui_string(peer_config, "rx"));
			fprintf(out, " exit\n");
		}
		if (pending_bfd) fprintf(out, "exit\n!\n");
	}
	if (!seen_lan) {
		fprintf(out, "access-list vty permit 127.0.0.0/8\n");
		if (*frr_ui_string(next, "frr_lan_acl")) fprintf(out, "access-list vty permit %s\n", frr_ui_string(next, "frr_lan_acl"));
		fprintf(out, "access-list vty deny any\nline vty\n access-class vty\n exec-timeout 0 0\n!\n");
	}
	free(copy);
	json_object_put(bgp_networks);
	json_object_put(ospf_networks);
	json_object_put(old);
	json_object_put(next);
	return !ferror(out);
fail:
	free(copy);
	if (bgp_networks) json_object_put(bgp_networks);
	if (ospf_networks) json_object_put(ospf_networks);
	if (old) json_object_put(old);
	if (next) json_object_put(next);
	return 0;
}

static int frr_ui_merge_daemons(FILE *out, const char *original, json_object *config)
{
	const char *names[] = {"bgpd", "ospfd", "bfdd"};
	const char *keys[] = {"frr_bgp_enable", "frr_ospf_enable", "frr_bfd_enable"};
	int seen[3] = {0, 0, 0};
	char *copy = strdup(original), *cursor = copy, *line;
	int index;
	if (!copy) return 0;
	while ((line = strsep(&cursor, "\n")) != NULL) {
		char *text = line;
		int handled = 0;
		if (!*line && !cursor) break;
		while (isspace((unsigned char)*text)) text++;
		for (index = 0; index < 3; index++) {
			size_t length = strlen(names[index]);
			char *value;
			if (strncmp(text, names[index], length)) continue;
			value = text + length;
			while (isspace((unsigned char)*value)) value++;
			if (*value != '=') continue;
			if (!seen[index]) fprintf(out, "%s=%s\n", names[index], !strcmp(frr_ui_string(config, keys[index]), "1") ? "yes" : "no");
			seen[index] = handled = 1;
			break;
		}
		if (!handled) fprintf(out, "%s\n", line);
	}
	for (index = 0; index < 3; index++)
		if (!seen[index]) fprintf(out, "%s=%s\n", names[index], !strcmp(frr_ui_string(config, keys[index]), "1") ? "yes" : "no");
	free(copy);
	return !ferror(out);
}

static void frr_ui_parse_daemons(json_object *config, const char *data)
{
	const char *names[] = {"bgpd", "ospfd", "bfdd"};
	const char *keys[] = {"frr_bgp_enable", "frr_ospf_enable", "frr_bfd_enable"};
	char *copy = strdup(data), *cursor = copy, *line;
	int index;
	if (!copy) { frr_ui_set(config, "error", "FRR daemon configuration could not be parsed"); return; }
	while ((line = strsep(&cursor, "\n")) != NULL) {
		char *text = frr_ui_trim(line);
		for (index = 0; index < 3; index++) {
			size_t length = strlen(names[index]);
			char *value;
			if (strncmp(text, names[index], length)) continue;
			value = text + length;
			while (isspace((unsigned char)*value)) value++;
			if (*value++ != '=') continue;
			while (isspace((unsigned char)*value)) value++;
			if (*value == '\'' || *value == '"') value++;
			if (!strncmp(value, "yes", 3) && (!value[3] || isspace((unsigned char)value[3]) || value[3] == '\'' || value[3] == '"'))
				frr_ui_set(config, keys[index], "1");
			else if (!strncmp(value, "no", 2) && (!value[2] || isspace((unsigned char)value[2]) || value[2] == '\'' || value[2] == '"'))
				frr_ui_set(config, keys[index], "0");
			else frr_ui_set(config, "error", "FRR daemon enable flags must use literal yes/no values");
		}
	}
	free(copy);
}

#endif