#include "skynet.h"
#include <arpa/inet.h>
#include <curl/curl.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

struct download {
	struct skynet *context;
	sqlite3_stmt *insert;
	char line[512];
	size_t length;
	size_t bytes;
	unsigned int entries;
	int failed;
	const char *reason;
};

static int consume_line(struct download *download)
{
	char canonical[SKYNET_ENTRY_SIZE];
	char *cursor = download->line;
	char *end;

	download->line[download->length] = '\0';
	while (*cursor == ' ' || *cursor == '\t' || *cursor == '\r')
		cursor++;
	if (!*cursor || *cursor == '#' || *cursor == ';')
		return 0;
	end = cursor;
	while (*end && *end != ' ' && *end != '\t' && *end != '\r' && *end != '#')
		end++;
	if (*end) {
		*end++ = '\0';
		while (*end == ' ' || *end == '\t' || *end == '\r')
			end++;
		if (*end && *end != '#') {
			download->reason = "unexpected text after IPv4 entry";
			return -1;
		}
	}
	if (strchr(cursor, ':')) {
		struct in6_addr address;
		char *suffix = strchr(cursor, '/');
		unsigned int prefix = 0;
		unsigned int digits = 0;

		if (suffix) {
			*suffix++ = '\0';
			while (*suffix >= '0' && *suffix <= '9') {
				prefix = prefix * 10 + (unsigned int)(*suffix++ - '0');
				if (++digits > 3 || prefix > 128)
					break;
			}
			if (!digits || *suffix || digits > 3 || prefix > 128) {
				download->reason = "invalid IPv6 address or CIDR";
				return -1;
			}
		}
		if (inet_pton(AF_INET6, cursor, &address) != 1) {
			download->reason = "invalid IPv6 address or CIDR";
			return -1;
		}
		return 0;
	}
	if (skynet_parse_entry(cursor, canonical, sizeof(canonical))) {
		download->reason = "invalid IPv4 address or CIDR";
		return -1;
	}
	sqlite3_reset(download->insert);
	sqlite3_bind_text(download->insert, 1, canonical, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(download->insert) != SQLITE_DONE) {
		download->reason = "database insert failed";
		return -1;
	}
	if (sqlite3_changes(download->context->database) && ++download->entries > download->context->limit) {
		download->reason = "feed entry limit exceeded";
		return -1;
	}
	return 0;
}

static size_t receive_data(char *data, size_t size, size_t count, void *opaque)
{
	struct download *download = opaque;
	size_t length;
	size_t offset;

	if (size && count > SKYNET_DOWNLOAD_LIMIT / size) {
		download->reason = "download byte limit exceeded";
		return 0;
	}
	length = size * count;
	if (length > SKYNET_DOWNLOAD_LIMIT - download->bytes) {
		download->reason = "download byte limit exceeded";
		return 0;
	}
	if (skynet_cancelled()) {
		download->reason = "refresh cancelled";
		return 0;
	}
	download->bytes += length;
	for (offset = 0; offset < length; offset++) {
		if (!data[offset]) {
			download->reason = "NUL byte in feed";
			return 0;
		}
		if (data[offset] == '\n') {
			if (consume_line(download)) {
				download->failed = 1;
				return 0;
			}
			download->length = 0;
		} else {
			if (download->length >= sizeof(download->line) - 1) {
				download->reason = "feed line too long";
				return 0;
			}
			download->line[download->length++] = data[offset];
		}
	}
	return length;
}

static int download_feed(struct skynet *context, const char *url, sqlite3_int64 identifier,
	char *failure, size_t failure_size)
{
	struct download download;
	CURL *curl;
	CURLcode result = CURLE_OK;
	long http_status = 0;
	sqlite3_stmt *statement = NULL;
	int status = -1;

	memset(&download, 0, sizeof(download));
	download.context = context;
	download.reason = "database operation failed";
	if (sqlite3_prepare_v2(context->database, "DELETE FROM feed_entries WHERE feed=?1", -1, &statement, NULL) != SQLITE_OK)
		goto finished;
	sqlite3_bind_int64(statement, 1, identifier);
	if (sqlite3_step(statement) != SQLITE_DONE) {
		goto finished;
	}
	sqlite3_finalize(statement);
	statement = NULL;
	if (sqlite3_prepare_v2(context->database, "INSERT OR IGNORE INTO feed_entries(feed,entry) VALUES(?2,?1)",
	    -1, &download.insert, NULL) != SQLITE_OK)
		goto finished;
	sqlite3_bind_int64(download.insert, 2, identifier);
	download.reason = "curl initialization failed";
	curl = curl_easy_init();
	if (!curl)
		goto finished;
	download.reason = NULL;
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "https");
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "https");
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 3L);
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 60L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, receive_data);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &download);
	result = curl_easy_perform(curl);
	curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status);
	curl_easy_cleanup(curl);
	if (result != CURLE_OK || download.failed || (download.length && consume_line(&download)))
		goto finished;
	if (!download.entries) {
		download.reason = "feed contains no IPv4 entries";
		goto finished;
	}
	download.reason = "database timestamp update failed";
	if (sqlite3_prepare_v2(context->database, "UPDATE feeds SET updated=?2,attempted=?2,error='' WHERE id=?1", -1, &statement, NULL) != SQLITE_OK)
		goto finished;
	sqlite3_bind_int64(statement, 1, identifier);
	sqlite3_bind_int64(statement, 2, context->now);
	if (sqlite3_step(statement) == SQLITE_DONE)
		status = 0;
finished:
	if (status) {
		snprintf(failure, failure_size, "%s (curl %d, HTTP %ld)",
		    download.reason ? download.reason : curl_easy_strerror(result), (int)result, http_status);
		syslog(LOG_ERR, "feed %lld refresh failed: %s (curl %d: %s, HTTP %ld, bytes %lu, entries %u, database: %s)",
		    (long long)identifier, download.reason ? download.reason : "HTTPS transfer failed",
		    (int)result, curl_easy_strerror(result), http_status, (unsigned long)download.bytes,
		    download.entries, sqlite3_errmsg(context->database));
	}
	sqlite3_finalize(statement);
	sqlite3_finalize(download.insert);
	return status;
}

static int refresh_feeds(struct skynet *context,
	int (*fetch)(struct skynet *, const char *, sqlite3_int64, char *, size_t))
{
	sqlite3_stmt *feeds = NULL;
	sqlite3_stmt *attempt = NULL;
	unsigned int failed_count = 0;
	char failure[256] = "feed database operation failed";
	int step;
	int result = -1;

	if (!context->time_ready || context->now <= 0)
		return -1;
	if (sqlite3_prepare_v2(context->database, "INSERT OR REPLACE INTO meta(key,value) VALUES('last_attempt',?1)",
	    -1, &attempt, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_int64(attempt, 1, context->now);
	step = sqlite3_step(attempt);
	sqlite3_finalize(attempt);
	attempt = NULL;
	if (step != SQLITE_DONE)
		return -1;
	if (skynet_store_exec(context, "BEGIN IMMEDIATE"))
		goto finished;
	if (sqlite3_prepare_v2(context->database, "SELECT id,url FROM feeds WHERE enabled=1 ORDER BY id", -1, &feeds, NULL) != SQLITE_OK)
		goto rollback;
	if (sqlite3_prepare_v2(context->database, "UPDATE feeds SET attempted=?1,error=?2 WHERE id=?3",
	    -1, &attempt, NULL) != SQLITE_OK)
		goto rollback;
	while ((step = sqlite3_step(feeds)) == SQLITE_ROW) {
		const char *url = (const char *)sqlite3_column_text(feeds, 1);
		sqlite3_int64 identifier = sqlite3_column_int64(feeds, 0);
		int download_result;

		if (skynet_cancelled()) {
			snprintf(failure, sizeof(failure), "refresh cancelled");
			goto rollback;
		}
		if (skynet_store_exec(context, "SAVEPOINT feed_refresh"))
			goto rollback;
		if (skynet_validate_url(url)) {
			snprintf(failure, sizeof(failure), "invalid HTTPS feed URL");
			download_result = -1;
		} else {
			download_result = fetch(context, url, identifier, failure, sizeof(failure));
		}
		if (download_result) {
			if (skynet_store_exec(context, "ROLLBACK TO feed_refresh"))
				goto rollback;
			sqlite3_reset(attempt);
			sqlite3_bind_int64(attempt, 1, context->now);
			sqlite3_bind_text(attempt, 2, failure, -1, SQLITE_TRANSIENT);
			sqlite3_bind_int64(attempt, 3, identifier);
			if (sqlite3_step(attempt) != SQLITE_DONE)
				goto rollback;
			failed_count++;
		}
		if (skynet_store_exec(context, "RELEASE feed_refresh"))
			goto rollback;
	}
	if (step != SQLITE_DONE)
		goto rollback;
	if (skynet_cancelled()) {
		snprintf(failure, sizeof(failure), "refresh cancelled");
		goto rollback;
	}
	if (skynet_store_limit(context)) {
		snprintf(failure, sizeof(failure), "combined policy entry limit exceeded");
		goto rollback;
	}
	sqlite3_finalize(feeds);
	feeds = NULL;
	sqlite3_finalize(attempt);
	attempt = NULL;
	context->dirty = 1;
	result = context->enabled ? skynet_apply(context) : skynet_store_exec(context, "COMMIT");
	if (result) {
		skynet_store_exec(context, "ROLLBACK");
		snprintf(failure, sizeof(failure), "policy publication or commit failed");
		goto record_failure;
	}
	if (failed_count) {
		syslog(LOG_ERR, "refresh completed with %u failed feeds; retained their previous entries", failed_count);
		result = -1;
	}
	goto finished;
rollback:
	sqlite3_finalize(feeds);
	feeds = NULL;
	sqlite3_finalize(attempt);
	attempt = NULL;
	skynet_store_exec(context, "ROLLBACK");
record_failure:
	if (sqlite3_prepare_v2(context->database,
	    "UPDATE feeds SET attempted=?1,error=?2 WHERE enabled=1",
	    -1, &attempt, NULL) == SQLITE_OK) {
		sqlite3_bind_int64(attempt, 1, context->now);
		sqlite3_bind_text(attempt, 2, failure, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(attempt) != SQLITE_DONE)
			syslog(LOG_ERR, "could not record feed failure: %s", sqlite3_errmsg(context->database));
	}
	syslog(LOG_ERR, "refresh retained previous policy: %s", failure);
finished:
	sqlite3_finalize(feeds);
	sqlite3_finalize(attempt);
	return result;
}

int skynet_refresh(struct skynet *context)
{
	int result;

	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return -1;
	result = refresh_feeds(context, download_feed);
	curl_global_cleanup();
	return result;
}

#ifdef SKYNET_TEST
int skynet_test_refresh(struct skynet *context,
	int (*fetch)(struct skynet *, const char *, sqlite3_int64, char *, size_t))
{
	return refresh_feeds(context, fetch);
}

int skynet_test_feed(struct skynet *context, const char *text, size_t length)
{
	struct download download;
	int result = -1;
	memset(&download, 0, sizeof(download));
	download.context = context;
	if (skynet_store_exec(context, "BEGIN IMMEDIATE;"
	    "INSERT OR IGNORE INTO feeds(id,url) VALUES(100,'https://contracts.invalid/feed');"
	    "DELETE FROM feed_entries WHERE feed=100;"))
		return -1;
	if (sqlite3_prepare_v2(context->database, "INSERT OR IGNORE INTO feed_entries(feed,entry) VALUES(100,?1)",
	    -1, &download.insert, NULL) != SQLITE_OK)
		goto finished;
	if (receive_data((char *)text, 1, length, &download) == length &&
	    !download.failed && (!download.length || !consume_line(&download)) &&
	    download.entries && !skynet_store_limit(context))
		result = 0;
finished:
	sqlite3_finalize(download.insert);
	if (skynet_store_exec(context, result ? "ROLLBACK" : "COMMIT"))
		result = -1;
	return result;
}
#endif