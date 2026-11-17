#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <fcntl.h>
#include <json.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "rc.h"

#define GITHUB_RELEASE_API "https://api.github.com/repos/oivano/asuswrt-merlin.ng/releases/latest"
#define GITHUB_ASSET_PREFIX "https://github.com/oivano/asuswrt-merlin.ng/releases/download/"
#define GITHUB_RELEASE_PAGE_PREFIX "https://github.com/oivano/asuswrt-merlin.ng/releases/tag/"
#define GITHUB_RESPONSE_MAX (1024 * 1024)

struct response_buffer {
	char *data;
	size_t length;
};

struct release_version {
	unsigned long major;
	unsigned long minor;
	unsigned long revision;
	char suffix[64];
};

static size_t append_response(void *data, size_t size, size_t count, void *context)
{
	struct response_buffer *buffer = context;
	size_t chunk = size * count;
	char *resized;

	if (size && chunk / size != count)
		return 0;
	if (chunk > GITHUB_RESPONSE_MAX - buffer->length)
		return 0;
	resized = realloc(buffer->data, buffer->length + chunk + 1);
	if (!resized)
		return 0;
	buffer->data = resized;
	memcpy(buffer->data + buffer->length, data, chunk);
	buffer->length += chunk;
	buffer->data[buffer->length] = '\0';
	return chunk;
}

static int parse_number(const char **cursor, unsigned long *value)
{
	char *end;

	if (!isdigit((unsigned char)**cursor))
		return -1;
	errno = 0;
	*value = strtoul(*cursor, &end, 10);
	if (errno || end == *cursor)
		return -1;
	*cursor = end;
	return 0;
}

static int parse_base_version(const char *text, struct release_version *version,
			      const char **end)
{
	const char *cursor = text;

	if (!text || parse_number(&cursor, &version->major) || *cursor++ != '.' ||
	    parse_number(&cursor, &version->minor))
		return -1;
	*end = cursor;
	return 0;
}

static int parse_release_tag(const char *tag, struct release_version *version)
{
	const char *cursor;
	size_t suffix_length;

	if (parse_base_version(tag, version, &cursor) || *cursor++ != '_' ||
	    parse_number(&cursor, &version->revision))
		return -1;
	if (*cursor && *cursor != '-')
		return -1;
	suffix_length = strlen(cursor);
	if (suffix_length >= sizeof(version->suffix))
		return -1;
	memcpy(version->suffix, cursor, suffix_length + 1);
	return 0;
}

static int parse_current_version(struct release_version *version)
{
	const char *build = nvram_safe_get("buildno");
	const char *end;
	char full_build[48];

	if (!strchr(build, '.')) {
		if (snprintf(full_build, sizeof(full_build), "%s.%s",
			     nvram_safe_get("firmver"), build) >= sizeof(full_build))
			return -1;
		build = full_build;
	}
	if (parse_base_version(build, version, &end) || *end)
		return -1;

	const char *extension = nvram_safe_get("extendno");
	if (isdigit((unsigned char)*extension)) {
		if (parse_number(&extension, &version->revision) ||
		    (*extension && *extension != '-'))
			return -1;
	} else {
		version->revision = ULONG_MAX;
	}
	if (strlen(extension) >= sizeof(version->suffix))
		return -1;
	strcpy(version->suffix, extension);
	return 0;
}

static int release_is_newer(const struct release_version *available,
			    const struct release_version *current)
{
	if (available->major != current->major)
		return available->major > current->major;
	if (available->minor != current->minor)
		return available->minor > current->minor;
	if (available->revision != current->revision)
		return available->revision > current->revision;
	return strcmp(available->suffix, current->suffix) > 0;
}

static const char *json_string_member(struct json_object *object, const char *key)
{
	struct json_object *value;

	if (!json_object_object_get_ex(object, key, &value) ||
	    !json_object_is_type(value, json_type_string))
		return NULL;
	return json_object_get_string(value);
}

static int publish_release_notes(const char *notes)
{
	char temporary_path[] = "/tmp/release_note0.txt.XXXXXX";
	char *note_path = "/tmp/release_note0.txt";
	size_t remaining;
	const char *cursor;
	ssize_t written;
	int descriptor;

	if (!notes || !*notes)
		return -1;
	descriptor = mkstemp(temporary_path);
	if (descriptor < 0)
		return -1;
	if (fchmod(descriptor, 0600) != 0)
		goto error;
	cursor = notes;
	remaining = strlen(notes);
	while (remaining > 0) {
		written = write(descriptor, cursor, remaining);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			goto error;
		}
		if (written == 0)
			goto error;
		cursor += written;
		remaining -= written;
	}
	if (close(descriptor) != 0) {
		descriptor = -1;
		goto error;
	}
	if (rename(temporary_path, note_path) != 0)
		goto error;
	return 0;

error:
	if (descriptor >= 0)
		close(descriptor);
	unlink(temporary_path);
	return -1;
}

static int fetch_latest_release(struct json_object **release)
{
	static const char user_agent[] = "asuswrt-merlin-dsl-ac68u-firmware-check";
	struct response_buffer buffer = {0};
	struct curl_slist *headers = NULL;
	CURL *curl;
	CURLcode code;
	long response_code = 0;
	int result = -1;

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return -1;
	curl = curl_easy_init();
	if (!curl)
		goto done_global;
	headers = curl_slist_append(headers, "Accept: application/vnd.github+json");
	if (!headers)
		goto done_curl;
	curl_easy_setopt(curl, CURLOPT_URL, GITHUB_RELEASE_API);
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, append_response);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
	code = curl_easy_perform(curl);
	if (code != CURLE_OK ||
	    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code) != CURLE_OK ||
	    response_code != 200 || !buffer.data)
		goto done_curl;
	*release = json_tokener_parse(buffer.data);
	if (!*release || !json_object_is_type(*release, json_type_object))
		goto done_curl;
	result = 0;
done_curl:
	if (result && *release) {
		json_object_put(*release);
		*release = NULL;
	}
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);
done_global:
	curl_global_cleanup();
	free(buffer.data);
	return result;
}

static int find_dsl_asset(struct json_object *release, const char *tag,
			  char *asset_url, size_t asset_url_size)
{
	struct json_object *assets, *asset;
	char expected_prefix[160];
	char asset_version[96];
	char *separator;
	const char *asset_prefix = "DSL-AC68U_";
	const char *url_prefix = GITHUB_ASSET_PREFIX;
	const char *name, *url, *state;
	int index;

	if (strlen(tag) >= sizeof(asset_version))
		return -1;
	strcpy(asset_version, tag);
	separator = strchr(asset_version, '_');
	if (!separator)
		return -1;
	*separator = '-';
	if (snprintf(expected_prefix, sizeof(expected_prefix), "%s%s_DSL_",
		     asset_prefix, asset_version) >= sizeof(expected_prefix))
		return -1;
	if (!json_object_object_get_ex(release, "assets", &assets) ||
	    !json_object_is_type(assets, json_type_array))
		return -1;

	for (index = 0; index < json_object_array_length(assets); ++index) {
		asset = json_object_array_get_idx(assets, index);
		name = json_string_member(asset, "name");
		url = json_string_member(asset, "browser_download_url");
		state = json_string_member(asset, "state");
		if (!name || !url || !state || strcmp(state, "uploaded") ||
		    strncmp(name, expected_prefix, strlen(expected_prefix)) ||
		    strlen(name) < 4 || strcmp(name + strlen(name) - 4, ".trx") ||
		    strncmp(url, url_prefix, strlen(url_prefix)))
			continue;
		if (strlcpy(asset_url, url, asset_url_size) >= asset_url_size)
			return -1;
		return 0;
	}
	return -1;
}

int firmware_release_check_main(int argc, char *argv[])
{
	struct json_object *release = NULL;
	struct json_object *value;
	struct release_version available, current;
	const char *tag, *release_page_url, *release_notes;
	char asset_url[512];
	char release_page_url_copy[512];
	int newer;

	if (argc != 1)
		return -1;

	nvram_set("ion_fw_check_status", "checking");
	nvram_set("ion_fw_check_tag", "");
	nvram_set("ion_fw_download_url", "");
	nvram_set("ion_fw_release_url", "");
	unlink("/tmp/release_note0.txt");

	if (fetch_latest_release(&release) != 0)
		goto error;
	tag = json_string_member(release, "tag_name");
	release_page_url = json_string_member(release, "html_url");
	release_notes = json_string_member(release, "body");
	if (!tag || parse_release_tag(tag, &available) ||
	    parse_current_version(&current) ||
	    !release_page_url ||
	    strncmp(release_page_url, GITHUB_RELEASE_PAGE_PREFIX,
		    strlen(GITHUB_RELEASE_PAGE_PREFIX)) ||
	    publish_release_notes(release_notes) ||
	    strlcpy(release_page_url_copy, release_page_url,
		    sizeof(release_page_url_copy)) >= sizeof(release_page_url_copy) ||
	    !json_object_object_get_ex(release, "draft", &value) ||
	    json_object_get_boolean(value) ||
	    !json_object_object_get_ex(release, "prerelease", &value) ||
	    json_object_get_boolean(value) ||
	    find_dsl_asset(release, tag, asset_url, sizeof(asset_url)))
		goto error;

	newer = release_is_newer(&available, &current);
	nvram_set("ion_fw_check_tag", tag);
	nvram_set("ion_fw_download_url", asset_url);
	nvram_set("ion_fw_release_url", release_page_url_copy);
	nvram_set("webs_state_info_am", newer ? tag : "");
	nvram_set("webs_state_flag", newer ? "1" : "0");
	nvram_set("ion_fw_check_status", newer ? "available" : "current");
	json_object_put(release);
	return 0;

error:
	if (release)
		json_object_put(release);
	nvram_set("ion_fw_download_url", "");
	nvram_set("ion_fw_release_url", "");
	nvram_set("ion_fw_check_status", "error");
	logmessage("firmware_check", "GitHub DSL-AC68U release check failed");
	return -1;
}

void auto_ion_firmware_check(void)
{
	static int bootup_check_period = 3;
	static int bootup_check = 1;
	static int last_daily_check = -1;
	time_t now;
	struct tm local;

	if (!nvram_get_int("ntp_ready") || !nvram_get_int("firmware_check_enable"))
		return;

	if (bootup_check_period > 0) {
		bootup_check_period--;
		return;
	}

	if (bootup_check) {
		bootup_check = 0;
		notify_rc("start_ion_firmware_check");
		return;
	}

	time(&now);
	if (!localtime_r(&now, &local))
		return;
	if (local.tm_hour == 2 && local.tm_min < 5 && local.tm_yday != last_daily_check) {
		last_daily_check = local.tm_yday;
		notify_rc("start_ion_firmware_check");
	}
}