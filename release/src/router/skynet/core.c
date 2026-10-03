#include "skynet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int skynet_parse_entry(const char *text, char *canonical, size_t size)
{
	const char *cursor = text;
	unsigned int octet;
	unsigned int part;
	unsigned int prefix = 32;
	unsigned int digits;
	uint32_t address = 0;
	int written;

	if (!text || !canonical)
		return -1;
	for (part = 0; part < 4; part++) {
		octet = 0;
		digits = 0;
		while (*cursor >= '0' && *cursor <= '9') {
			octet = octet * 10 + (unsigned int)(*cursor++ - '0');
			if (++digits > 3 || octet > 255)
				return -1;
		}
		if (!digits || (part < 3 && *cursor++ != '.'))
			return -1;
		address = (address << 8) | octet;
	}
	if (*cursor == '/') {
		cursor++;
		prefix = 0;
		digits = 0;
		while (*cursor >= '0' && *cursor <= '9') {
			prefix = prefix * 10 + (unsigned int)(*cursor++ - '0');
			if (++digits > 2 || prefix > 32)
				return -1;
		}
		if (!digits)
			return -1;
	}
	if (*cursor)
		return -1;
	address &= prefix ? UINT32_MAX << (32 - prefix) : 0;
	written = snprintf(canonical, size, "%u.%u.%u.%u/%u", address >> 24,
		(address >> 16) & 255, (address >> 8) & 255, address & 255, prefix);
	return written < 0 || (size_t)written >= size ? -1 : 0;
}

int skynet_validate_url(const char *url)
{
	const unsigned char *cursor;

	if (!url || strncmp(url, "https://", 8) || !url[8] ||
	    url[8] == '/' || strlen(url) >= SKYNET_URL_SIZE)
		return -1;
	for (cursor = (const unsigned char *)url; *cursor; cursor++) {
		if (*cursor <= 32 || *cursor >= 127 || *cursor == '@' || *cursor == '#')
			return -1;
	}
	return 0;
}

const char *skynet_builtin_feed(unsigned int index)
{
	static const char *const builtins[] = {
		"https://iplists.firehol.org/files/bds_atif.ipset",
		"https://iplists.firehol.org/files/cybercrime.ipset",
		"https://iplists.firehol.org/files/et_compromised.ipset",
		"https://iplists.firehol.org/files/firehol_level2.netset",
		"https://iplists.firehol.org/files/firehol_level3.netset",
		"https://iplists.firehol.org/files/ipsum_3.ipset",
		"https://iplists.firehol.org/files/spamhaus_drop.netset",
		"https://threatview.io/Downloads/IP-High-Confidence-Feed.txt"
	};
	return index < sizeof(builtins) / sizeof(builtins[0]) ? builtins[index] : NULL;
}

const char *skynet_resolve_feed(const char *source)
{
	unsigned int index;
	const char *url;

	if (!source)
		return NULL;
	for (index = 0; (url = skynet_builtin_feed(index)) != NULL; index++)
		if (!strcmp(source, strrchr(url, '/') + 1))
			return url;
	return skynet_validate_url(source) ? NULL : source;
}

int skynet_parse_limit(const char *text, unsigned int *limit)
{
	unsigned long parsed;
	char *end;
	const char *cursor;

	if (!text || !*text || !limit)
		return -1;
	for (cursor = text; *cursor; cursor++)
		if (*cursor < '0' || *cursor > '9')
			return -1;
	parsed = strtoul(text, &end, 10);
	if (*end || parsed < 1024 || parsed > SKYNET_MAX_LIMIT)
		return -1;
	*limit = (unsigned int)parsed;
	return 0;
}

static int firewall_token(const char *text, size_t maximum)
{
	const unsigned char *cursor = (const unsigned char *)text;
	if (!*text || strlen(text) >= maximum)
		return -1;
	for (; *cursor; cursor++)
		if (!((*cursor >= 'a' && *cursor <= 'z') || (*cursor >= 'A' && *cursor <= 'Z') ||
		    (*cursor >= '0' && *cursor <= '9') || *cursor == '_' || *cursor == '-' || *cursor == '.'))
			return -1;
	return 0;
}

int skynet_parse_seconds(const char *text, unsigned int *seconds)
{
	const char *cursor;
	unsigned long parsed;
	char *end;
	if (!text || !*text || !seconds)
		return -1;
	for (cursor = text; *cursor; cursor++)
		if (*cursor < '0' || *cursor > '9')
			return -1;
	parsed = strtoul(text, &end, 10);
	if (*end || !parsed || parsed > 604800)
		return -1;
	*seconds = (unsigned int)parsed;
	return 0;
}

int skynet_emit_set_entry(FILE *stream, const char *name, const char *entry, unsigned int seconds)
{
	char canonical[SKYNET_ENTRY_SIZE];
	if (firewall_token(name, 32) || skynet_parse_entry(entry, canonical, sizeof(canonical)) || seconds > 604800)
		return -1;
	if (!strcmp(canonical, "0.0.0.0/0")) {
		fprintf(stream, "add %s 0.0.0.0/1 timeout %u\nadd %s 128.0.0.0/1 timeout %u\n", name, seconds, name, seconds);
	} else {
		fprintf(stream, "add %s %s timeout %u\n", name, canonical, seconds);
	}
	return ferror(stream) ? -1 : 0;
}

int skynet_render_firewall(struct skynet *context, FILE *stream)
{
	if (firewall_token(context->interface, sizeof(context->interface)) ||
	    firewall_token(context->blocked, sizeof(context->blocked)) ||
	    firewall_token(context->allowed, sizeof(context->allowed)))
		return -1;
	fputs("*filter\n:SKN_INPUT - [0:0]\n:SKN_OUTPUT - [0:0]\n:SKN_FORWARD - [0:0]\n"
	      "-F SKN_INPUT\n-F SKN_OUTPUT\n-F SKN_FORWARD\n", stream);
	if (context->inbound) {
		fprintf(stream, "-A SKN_INPUT -i %s -m set --match-set %s src -j RETURN\n", context->interface, context->allowed);
		fprintf(stream, "-A SKN_INPUT -i %s -m set --match-set %s src -j DROP\n", context->interface, context->blocked);
		fprintf(stream, "-A SKN_FORWARD -i %s -m set --match-set %s src -j RETURN\n", context->interface, context->allowed);
		fprintf(stream, "-A SKN_FORWARD -i %s -m set --match-set %s src -j DROP\n", context->interface, context->blocked);
	}
	if (context->outbound) {
		fprintf(stream, "-A SKN_OUTPUT -o %s -m set --match-set %s dst -j RETURN\n", context->interface, context->allowed);
		fprintf(stream, "-A SKN_OUTPUT -o %s -m set --match-set %s dst -j DROP\n", context->interface, context->blocked);
		fprintf(stream, "-A SKN_FORWARD -o %s -m set --match-set %s dst -j RETURN\n", context->interface, context->allowed);
		fprintf(stream, "-A SKN_FORWARD -o %s -m set --match-set %s dst -j DROP\n", context->interface, context->blocked);
	}
	fputs("COMMIT\n", stream);
	return ferror(stream) ? -1 : 0;
}