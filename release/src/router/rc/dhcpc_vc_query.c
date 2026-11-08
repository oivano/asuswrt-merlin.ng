#include <errno.h>
#include <fcntl.h>
#include <json.h>
#include <networkmap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define NMP_VC_MAX_ENTRIES 64
#define NMP_VC_MAX_BYTES 16384
#define NMP_VC_MAX_CLASS_LENGTH 255

static int nmp_vc_mac_normalize(const char *source, char destination[18])
{
	int i;

	if (!source || strlen(source) != 17)
		return 0;

	for (i = 0; i < 17; i++) {
		unsigned char c = (unsigned char)source[i];

		if (i % 3 == 2) {
			if (c != ':')
				return 0;
			destination[i] = ':';
		} else if (c >= '0' && c <= '9')
			destination[i] = c;
		else if (c >= 'a' && c <= 'f')
			destination[i] = c - 'a' + 'A';
		else if (c >= 'A' && c <= 'F')
			destination[i] = c;
		else
			return 0;
	}
	destination[17] = '\0';
	return 1;
}

static struct json_object *nmp_vc_load(int *reset)
{
	struct json_object *root;
	struct stat st;
	int fd;

	fd = open(NMP_VC_JSON_FILE, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
	if (fd < 0) {
		if (errno != ENOENT)
			return NULL;
		*reset = 1;
		return json_object_new_object();
	}

	if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
	    st.st_size > NMP_VC_MAX_BYTES) {
		close(fd);
		*reset = 1;
		return json_object_new_object();
	}

	root = json_object_from_fd(fd);
	close(fd);
	if (!root || json_object_get_type(root) != json_type_object) {
		if (root)
			json_object_put(root);
		*reset = 1;
		return json_object_new_object();
	}
	return root;
}

static size_t nmp_vc_size(struct json_object *root)
{
	const char *json = json_object_to_json_string_ext(root, JSON_C_TO_STRING_PLAIN);

	return json ? strlen(json) : (size_t)-1;
}

static int nmp_vc_evict_oldest(struct json_object *root, const char *preserve)
{
	char *oldest = NULL;

	json_object_object_foreach(root, key, value) {
		(void)value;
		if (preserve && !strcmp(key, preserve))
			continue;
		oldest = strdup(key);
		break;
	}
	if (!oldest)
		return 0;
	json_object_object_del(root, oldest);
	free(oldest);
	return 1;
}

static int nmp_vc_prune(struct json_object *root, const char *preserve)
{
	int changed = 0;

	while (json_object_object_length(root) > NMP_VC_MAX_ENTRIES ||
	       nmp_vc_size(root) > NMP_VC_MAX_BYTES) {
		if (!nmp_vc_evict_oldest(root, preserve))
			break;
		changed = 1;
	}
	return changed;
}

static struct json_object *nmp_vc_new_entry(const char *mac, const char *vendor_class)
{
	struct json_object *entry;
	struct json_object *value;

	entry = json_object_new_object();
	if (!entry)
		return NULL;

	value = json_object_new_string(mac);
	if (!value || json_object_object_add(entry, "mac", value) < 0) {
		if (value)
			json_object_put(value);
		json_object_put(entry);
		return NULL;
	}

	value = json_object_new_string(vendor_class);
	if (!value || json_object_object_add(entry, "vendorclass", value) < 0) {
		if (value)
			json_object_put(value);
		json_object_put(entry);
		return NULL;
	}
	return entry;
}

static int nmp_vc_save(struct json_object *root)
{
	if (nmp_vc_size(root) > NMP_VC_MAX_BYTES)
		return -1;
	return json_object_to_file(NMP_VC_JSON_FILE, root);
}

int nmp_get_vendorclass(int argc, char **argv)
{
	struct json_object *root = NULL;
	struct json_object *entry = NULL;
	struct json_object *field = NULL;
	const char *vendor_class;
	const char *current_class;
	char mac[18];
	size_t vendor_length;
	int lock = -1;
	int reset = 0;
	int changed = 0;
	int result = 0;
	int is_delete;

	if (argc < 3 || !argv || !argv[1] || !argv[2] ||
	    (strcmp(argv[1], "add") && strcmp(argv[1], "old") && strcmp(argv[1], "del")) ||
	    !nmp_vc_mac_normalize(argv[2], mac))
		return 0;

	is_delete = !strcmp(argv[1], "del");
	vendor_class = getenv("DNSMASQ_VENDOR_CLASS");
	if (!is_delete && vendor_class) {
		for (vendor_length = 0;
		     vendor_length <= NMP_VC_MAX_CLASS_LENGTH && vendor_class[vendor_length];
		     vendor_length++)
			;
		if (vendor_length > NMP_VC_MAX_CLASS_LENGTH)
			return 0;
	}

	lock = file_lock(NMP_VC_FILE_LOCK);
	if (lock < 0)
		return 0;

	root = nmp_vc_load(&reset);
	if (!root)
		goto done;

	if (is_delete || !vendor_class) {
		if (json_object_object_get_ex(root, mac, &entry)) {
			json_object_object_del(root, mac);
			changed = 1;
		}
	} else if (json_object_object_get_ex(root, mac, &entry) &&
		   json_object_object_get_ex(entry, "vendorclass", &field)) {
		current_class = json_object_get_string(field);
		if (current_class && !strcmp(current_class, vendor_class))
			goto maybe_save;
	}

	if (!is_delete && vendor_class) {
		entry = nmp_vc_new_entry(mac, vendor_class);
		if (!entry)
			goto maybe_save;

		json_object_object_del(root, mac);
		if (json_object_object_add(root, mac, entry) < 0) {
			json_object_put(entry);
			goto maybe_save;
		}
		changed = 1;

	}

maybe_save:
	if (nmp_vc_prune(root, mac))
		changed = 1;
	if (changed || reset)
		result = nmp_vc_save(root);

done:
	if (root)
		json_object_put(root);
	file_unlock(lock);
	return result;
}