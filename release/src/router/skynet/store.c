#include "skynet.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

int skynet_store_exec(struct skynet *context, const char *sql)
{
	char *message = NULL;
	int result = sqlite3_exec(context->database, sql, NULL, NULL, &message);
	if (result != SQLITE_OK)
		fprintf(stderr, "Skynet database: %s\n", message ? message : "operation failed");
	sqlite3_free(message);
	return result == SQLITE_OK ? 0 : -1;
}

int skynet_store_open(struct skynet *context)
{
	char filename[4096];
	struct stat status;
	sqlite3_stmt *statement = NULL;
	int version;
	int length;

	length = snprintf(filename, sizeof(filename), "%s/policy.db", context->directory);
	if (length < 0 || (size_t)length >= sizeof(filename))
		return -1;
	if (!lstat(filename, &status) && !S_ISREG(status.st_mode))
		return -1;
	if (sqlite3_open_v2(filename, &context->database,
	    SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK)
		goto failed;
	if (chmod(filename, 0600) || sqlite3_busy_timeout(context->database, 5000) != SQLITE_OK)
		goto failed;
	if (skynet_store_exec(context, "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;"
	    "PRAGMA cache_size=-1024; PRAGMA temp_store=FILE; PRAGMA synchronous=FULL;"
	    "PRAGMA journal_mode=DELETE;"))
		goto failed;
	if (sqlite3_prepare_v2(context->database, "PRAGMA user_version", -1, &statement, NULL) != SQLITE_OK ||
	    sqlite3_step(statement) != SQLITE_ROW)
		goto failed;
	version = sqlite3_column_int(statement, 0);
	sqlite3_finalize(statement);
	statement = NULL;
	if (version < 0 || version > SKYNET_SCHEMA_VERSION)
		goto failed;
	if (!version) {
		if (skynet_store_exec(context, "BEGIN IMMEDIATE;"
		    "CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL) WITHOUT ROWID;"
		    "CREATE TABLE rules(entry TEXT NOT NULL,action TEXT NOT NULL CHECK(action IN ('ban','allow')),expires INTEGER NOT NULL DEFAULT 0,"
		    "PRIMARY KEY(entry,action)) WITHOUT ROWID;"
		    "CREATE INDEX rules_expiry ON rules(expires) WHERE expires>0;"
		    "CREATE TABLE feeds(id INTEGER PRIMARY KEY,url TEXT NOT NULL UNIQUE,updated INTEGER NOT NULL DEFAULT 0);"
		    "CREATE TABLE feed_entries(feed INTEGER NOT NULL REFERENCES feeds(id) ON DELETE CASCADE,"
		    "entry TEXT NOT NULL,PRIMARY KEY(feed,entry)) WITHOUT ROWID;"
		    "PRAGMA user_version=2; COMMIT;"))
			goto failed;
	} else if (version == 1) {
		if (skynet_store_exec(context, "BEGIN IMMEDIATE;"
		    "ALTER TABLE rules ADD COLUMN expires INTEGER NOT NULL DEFAULT 0;"
		    "CREATE INDEX rules_expiry ON rules(expires) WHERE expires>0;"
		    "PRAGMA user_version=2; COMMIT;"))
			goto failed;
	}
	return 0;
failed:
	sqlite3_finalize(statement);
	skynet_store_close(context);
	return -1;
}

void skynet_store_close(struct skynet *context)
{
	if (context->database)
		sqlite3_close(context->database);
	context->database = NULL;
}

int skynet_store_limit(struct skynet *context)
{
	sqlite3_stmt *statement = NULL;
	int result = -1;
	if (sqlite3_prepare_v2(context->database,
	    "SELECT count(*) FROM (SELECT entry,action FROM rules UNION SELECT entry,'ban' FROM feed_entries)",
	    -1, &statement, NULL) != SQLITE_OK)
		return -1;
	if (sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_int64(statement, 0) <= context->limit)
		result = 0;
	sqlite3_finalize(statement);
	return result;
}

static int finish_mutation(struct skynet *context, sqlite3_stmt *statement)
{
	int result = sqlite3_step(statement);
	sqlite3_finalize(statement);
	if (result != SQLITE_DONE || skynet_store_limit(context)) {
		skynet_store_exec(context, "ROLLBACK");
		return -1;
	}
	if (context->enabled) {
		context->dirty = 1;
		return skynet_apply(context);
	}
	return skynet_store_exec(context, "COMMIT");
}

int skynet_rule(struct skynet *context, const char *action, const char *entry)
{
	char canonical[SKYNET_ENTRY_SIZE];
	const char *target;
	const char *sql;
	sqlite3_stmt *statement = NULL;

	if (skynet_parse_entry(entry, canonical, sizeof(canonical)))
		return -1;
	if (!strcmp(action, "ban") || !strcmp(action, "whitelist"))
		sql = "INSERT INTO rules(entry,action,expires) VALUES(?1,?2,0) ON CONFLICT(entry,action) DO UPDATE SET expires=0";
	else if (!strcmp(action, "unban") || !strcmp(action, "unwhitelist"))
		sql = "DELETE FROM rules WHERE entry=?1 AND action=?2";
	else
		return -1;
	target = !strcmp(action, "whitelist") || !strcmp(action, "unwhitelist") ? "allow" : "ban";
	if (skynet_store_exec(context, "BEGIN IMMEDIATE"))
		return -1;
	if (sqlite3_prepare_v2(context->database, sql, -1, &statement, NULL) != SQLITE_OK)
		goto failed;
	sqlite3_bind_text(statement, 1, canonical, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(statement, 2, target, -1, SQLITE_STATIC);
	return finish_mutation(context, statement);
failed:
	sqlite3_finalize(statement);
	skynet_store_exec(context, "ROLLBACK");
	return -1;
}

int skynet_feed(struct skynet *context, const char *action, const char *url)
{
	const char *sql;
	sqlite3_stmt *statement = NULL;
	int result;

	if (skynet_validate_url(url))
		return -1;
	if (!strcmp(action, "add"))
		sql = "INSERT OR IGNORE INTO feeds(url) SELECT ?1 WHERE (SELECT count(*) FROM feeds)<16";
	else if (!strcmp(action, "remove"))
		sql = "DELETE FROM feeds WHERE url=?1";
	else
		return -1;
	if (skynet_store_exec(context, "BEGIN IMMEDIATE"))
		return -1;
	if (sqlite3_prepare_v2(context->database, sql, -1, &statement, NULL) != SQLITE_OK)
		goto failed;
	sqlite3_bind_text(statement, 1, url, -1, SQLITE_TRANSIENT);
	result = sqlite3_step(statement);
	sqlite3_finalize(statement);
	statement = NULL;
	if (result != SQLITE_DONE || !sqlite3_changes(context->database))
		goto failed;
	if (context->enabled && !strcmp(action, "remove")) {
		context->dirty = 1;
		return skynet_apply(context);
	}
	return skynet_store_exec(context, "COMMIT");
failed:
	sqlite3_finalize(statement);
	skynet_store_exec(context, "ROLLBACK");
	return -1;
}

int skynet_temporary_ban(struct skynet *context, const char *entry, unsigned int seconds)
{
	char canonical[SKYNET_ENTRY_SIZE];
	sqlite3_stmt *statement = NULL;
	if (!context->time_ready || context->now <= 0 || !seconds || seconds > 604800 ||
	    skynet_parse_entry(entry, canonical, sizeof(canonical)))
		return -1;
	if (skynet_store_exec(context, "BEGIN IMMEDIATE"))
		return -1;
	if (sqlite3_prepare_v2(context->database,
	    "INSERT INTO rules(entry,action,expires) VALUES(?1,'ban',?2) ON CONFLICT(entry,action) "
	    "DO UPDATE SET expires=CASE WHEN rules.expires=0 THEN 0 ELSE excluded.expires END",
	    -1, &statement, NULL) != SQLITE_OK) {
		skynet_store_exec(context, "ROLLBACK");
		return -1;
	}
	sqlite3_bind_text(statement, 1, canonical, -1, SQLITE_TRANSIENT);
	sqlite3_bind_int64(statement, 2, context->now + seconds);
	return finish_mutation(context, statement);
}

int skynet_prune_rules(struct skynet *context)
{
	sqlite3_stmt *statement = NULL;
	int changed;
	if (!context->time_ready)
		return 0;
	if (skynet_store_exec(context, "BEGIN IMMEDIATE"))
		return -1;
	if (sqlite3_prepare_v2(context->database, "DELETE FROM rules WHERE expires>0 AND expires<=?1",
	    -1, &statement, NULL) != SQLITE_OK)
		goto failed;
	sqlite3_bind_int64(statement, 1, context->now);
	if (sqlite3_step(statement) != SQLITE_DONE)
		goto failed;
	changed = sqlite3_changes(context->database);
	sqlite3_finalize(statement);
	statement = NULL;
	if (sqlite3_prepare_v2(context->database, "SELECT EXISTS(SELECT 1 FROM meta WHERE key='time_ready' AND value='0')",
	    -1, &statement, NULL) != SQLITE_OK || sqlite3_step(statement) != SQLITE_ROW)
		goto failed;
	changed |= sqlite3_column_int(statement, 0);
	sqlite3_finalize(statement);
	if (changed && context->enabled) {
		context->dirty = 1;
		return skynet_apply(context);
	}
	return skynet_store_exec(context, "COMMIT");
failed:
	sqlite3_finalize(statement);
	skynet_store_exec(context, "ROLLBACK");
	return -1;
}

int skynet_refresh_due(struct skynet *context, unsigned int hours)
{
	sqlite3_stmt *statement = NULL;
	int due = 0;
	if (!context->time_ready || !hours || hours > 168)
		return 0;
	if (sqlite3_prepare_v2(context->database,
	    "SELECT count(*)>0 AND (?1-min(updated))>=?2 AND "
	    "(?1-COALESCE((SELECT CAST(value AS INTEGER) FROM meta WHERE key='last_attempt'),0))>=900 FROM feeds",
	    -1, &statement, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_int64(statement, 1, context->now);
	sqlite3_bind_int64(statement, 2, (sqlite3_int64)hours * 3600);
	if (sqlite3_step(statement) != SQLITE_ROW)
		due = -1;
	else
		due = sqlite3_column_int(statement, 0);
	sqlite3_finalize(statement);
	return due;
}

int skynet_status(struct skynet *context, int output)
{
	sqlite3_stmt *statement = NULL;
	const unsigned char *json;
	FILE *stream;
	int result = -1;
	const char *sql = "SELECT json_object('enabled',?1,'available',json('true'),'last_error',?2,'time_ready',?4,"
		"'limit',?3,'rules',json(COALESCE((SELECT json_group_array(json_object('entry',entry,'action',action,'expires',expires))"
		"FROM (SELECT entry,action,expires FROM rules ORDER BY action,entry LIMIT 256)),'[]')),"
		"'rule_count',(SELECT count(*) FROM rules),'feed_entries',(SELECT count(DISTINCT entry) FROM feed_entries),"
		"'feeds',json(COALESCE((SELECT json_group_array(json_object('url',url,'updated',updated)) FROM feeds),'[]')))";

	if (sqlite3_prepare_v2(context->database, sql, -1, &statement, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_int(statement, 1, context->enabled);
	sqlite3_bind_int(statement, 2, context->error);
	sqlite3_bind_int(statement, 3, (int)context->limit);
	sqlite3_bind_int(statement, 4, context->time_ready);
	if (sqlite3_step(statement) != SQLITE_ROW)
		goto finished;
	json = sqlite3_column_text(statement, 0);
	stream = fdopen(output, "w");
	if (!stream)
		goto finished;
	result = fprintf(stream, "%s\n", json) < 0 ? -1 : 0;
	if (fclose(stream))
		result = -1;
finished:
	sqlite3_finalize(statement);
	return result;
}