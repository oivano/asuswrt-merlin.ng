#include "skynet.h"
#include <curl/curl.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct download {
	struct skynet *context;
	sqlite3_stmt *insert;
	char line[512];
	size_t length;
	size_t bytes;
	unsigned int entries;
	int failed;
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
		if (*end && *end != '#')
			return -1;
	}
	if (skynet_parse_entry(cursor, canonical, sizeof(canonical)))
		return -1;
	sqlite3_reset(download->insert);
	sqlite3_bind_text(download->insert, 1, canonical, -1, SQLITE_TRANSIENT);
	if (sqlite3_step(download->insert) != SQLITE_DONE)
		return -1;
	if (sqlite3_changes(download->context->database) && ++download->entries > download->context->limit)
		return -1;
	return 0;
}

static size_t receive_data(char *data, size_t size, size_t count, void *opaque)
{
	struct download *download = opaque;
	size_t length;
	size_t offset;

	if (size && count > SKYNET_DOWNLOAD_LIMIT / size)
		return 0;
	length = size * count;
	if (length > SKYNET_DOWNLOAD_LIMIT - download->bytes || skynet_cancelled())
		return 0;
	download->bytes += length;
	for (offset = 0; offset < length; offset++) {
		if (!data[offset])
			return 0;
		if (data[offset] == '\n') {
			if (consume_line(download)) {
				download->failed = 1;
				return 0;
			}
			download->length = 0;
		} else {
			if (download->length >= sizeof(download->line) - 1)
				return 0;
			download->line[download->length++] = data[offset];
		}
	}
	return length;
}

static int download_feed(struct skynet *context, const char *url, sqlite3_int64 identifier)
{
	struct download download;
	CURL *curl;
	CURLcode result;
	sqlite3_stmt *statement = NULL;
	int status = -1;

	memset(&download, 0, sizeof(download));
	download.context = context;
	if (sqlite3_prepare_v2(context->database, "DELETE FROM feed_entries WHERE feed=?1", -1, &statement, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_int64(statement, 1, identifier);
	if (sqlite3_step(statement) != SQLITE_DONE) {
		sqlite3_finalize(statement);
		return -1;
	}
	sqlite3_finalize(statement);
	if (sqlite3_prepare_v2(context->database, "INSERT OR IGNORE INTO feed_entries(feed,entry) VALUES(?2,?1)",
	    -1, &download.insert, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_int64(download.insert, 2, identifier);
	curl = curl_easy_init();
	if (!curl)
		goto finished;
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
	curl_easy_cleanup(curl);
	if (result != CURLE_OK || download.failed || (download.length && consume_line(&download)) || !download.entries)
		goto finished;
	if (sqlite3_prepare_v2(context->database, "UPDATE feeds SET updated=strftime('%s','now') WHERE id=?1", -1, &statement, NULL) != SQLITE_OK)
		goto finished;
	sqlite3_bind_int64(statement, 1, identifier);
	if (sqlite3_step(statement) == SQLITE_DONE)
		status = 0;
	sqlite3_finalize(statement);
finished:
	sqlite3_finalize(download.insert);
	return status;
}

int skynet_refresh(struct skynet *context)
{
	sqlite3_stmt *feeds = NULL;
	sqlite3_stmt *attempt = NULL;
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
	if (step != SQLITE_DONE)
		return -1;
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
		return -1;
	if (skynet_store_exec(context, "BEGIN IMMEDIATE"))
		goto finished;
	if (sqlite3_prepare_v2(context->database, "SELECT id,url FROM feeds ORDER BY id", -1, &feeds, NULL) != SQLITE_OK)
		goto rollback;
	while ((step = sqlite3_step(feeds)) == SQLITE_ROW) {
		const char *url = (const char *)sqlite3_column_text(feeds, 1);
		if (skynet_validate_url(url) || download_feed(context, url, sqlite3_column_int64(feeds, 0)))
			goto rollback;
	}
	if (step != SQLITE_DONE || skynet_store_limit(context))
		goto rollback;
	sqlite3_finalize(feeds);
	feeds = NULL;
	context->dirty = 1;
	result = context->enabled ? skynet_apply(context) : skynet_store_exec(context, "COMMIT");
	goto finished;
rollback:
	skynet_store_exec(context, "ROLLBACK");
finished:
	sqlite3_finalize(feeds);
	curl_global_cleanup();
	return result;
}

#ifdef SKYNET_TEST
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