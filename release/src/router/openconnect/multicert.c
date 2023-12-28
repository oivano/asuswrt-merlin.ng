#include <config.h>

#include "openconnect-internal.h"

static const struct {
	openconnect_hash_type id;
	const char *name;
} digest_table[OPENCONNECT_HASH_MAX + 1] = {
	[ OPENCONNECT_HASH_SHA256 ] = { OPENCONNECT_HASH_SHA256, "sha256" },
	[ OPENCONNECT_HASH_SHA384 ] = { OPENCONNECT_HASH_SHA384, "sha384" },
	[ OPENCONNECT_HASH_SHA512 ] = { OPENCONNECT_HASH_SHA512, "sha512" },
};

const char *multicert_hash_get_name(int id)
{
	size_t i;

	if (id > 0 && (size_t) id < ARRAY_SIZE(digest_table)) {
		i = (size_t) id;
		if (digest_table[i].id)
			return digest_table[i].name;
	}
	return NULL;
}

openconnect_hash_type multicert_hash_get_id(const char *name)
{
	size_t i;

	if (name) {
		for (i = 1; i < ARRAY_SIZE(digest_table); i++) {
			if (digest_table[i].name &&
			    !strcmp(digest_table[i].name, name))
				return digest_table[i].id;
		}
	}
	return OPENCONNECT_HASH_UNKNOWN;
}
