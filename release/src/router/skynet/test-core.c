#include "skynet.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sqlite3.h>

static int fail_apply;
int skynet_test_feed(struct skynet *context, const char *text, size_t length);

int skynet_cancelled(void) { return 0; }
int skynet_stopping(void) { return 0; }

int skynet_apply(struct skynet *context)
{
	return skynet_store_exec(context, fail_apply ? "ROLLBACK" : "COMMIT") || fail_apply ? -1 : 0;
}

static int rule_count(struct skynet *context)
{
	sqlite3_stmt *statement = NULL;
	int count;
	assert(sqlite3_prepare_v2(context->database, "SELECT count(*) FROM rules", -1, &statement, NULL) == SQLITE_OK);
	assert(sqlite3_step(statement) == SQLITE_ROW);
	count = sqlite3_column_int(statement, 0);
	sqlite3_finalize(statement);
	return count;
}

static int feed_count(struct skynet *context)
{
	sqlite3_stmt *statement = NULL;
	int count;
	assert(sqlite3_prepare_v2(context->database, "SELECT count(*) FROM feed_entries", -1, &statement, NULL) == SQLITE_OK);
	assert(sqlite3_step(statement) == SQLITE_ROW);
	count = sqlite3_column_int(statement, 0);
	sqlite3_finalize(statement);
	return count;
}

static void check_entry(const char *input, const char *expected)
{
	char actual[SKYNET_ENTRY_SIZE];
	assert(skynet_parse_entry(input, actual, sizeof(actual)) == 0);
	assert(strcmp(actual, expected) == 0);
}

int main(void)
{
	char output[SKYNET_ENTRY_SIZE];
	unsigned int limit;
	const char *invalid[] = { "", "0", "1.2.3", "1.2.3.256", "-1.2.3.4",
		"1.2.3.4/33", "1.2.3.4/", "1.2.3.4/000", "1.2.3.4;reboot",
		"2001:db8::1", "1.2.3.4\n", "1.2.3.4/24/1" };
	size_t entry;
	struct skynet context;
	char temporary[] = "/tmp/skynet-test-XXXXXX";
	char database[4096];
	FILE *firewall;
	FILE *status;
	sqlite3_stmt *status_check = NULL;
	char rules[4096];
	size_t bytes;

	check_entry("1.2.3.4", "1.2.3.4/32");
	check_entry("192.168.1.12/24", "192.168.1.0/24");
	check_entry("255.255.255.255/0", "0.0.0.0/0");
	check_entry("128.0.0.1/1", "128.0.0.0/1");
	check_entry("001.002.003.004", "1.2.3.4/32");
	for (entry = 0; entry < sizeof(invalid) / sizeof(invalid[0]); entry++)
		assert(skynet_parse_entry(invalid[entry], output, sizeof(output)) != 0);
	assert(skynet_parse_entry("1.2.3.4", output, 4) != 0);
	assert(skynet_validate_url("https://example.org/feed.txt") == 0);
	assert(skynet_validate_url("http://example.org/feed.txt") != 0);
	assert(skynet_validate_url("https://user:password@example.org/feed") != 0);
	assert(skynet_validate_url("https:///feed") != 0);
	assert(skynet_validate_url("https://example.org/\nfeed") != 0);
	assert(skynet_parse_limit("65536", &limit) == 0 && limit == 65536);
	assert(skynet_parse_limit("4294967296000", &limit) != 0);
	assert(skynet_parse_limit("100", &limit) != 0);
	assert(skynet_parse_limit("1024;reboot", &limit) != 0);
	assert(skynet_parse_seconds("3600", &limit) == 0 && limit == 3600);
	assert(skynet_parse_seconds("0", &limit) != 0);
	assert(skynet_parse_seconds("604801", &limit) != 0);
	assert(skynet_parse_seconds("3600;reboot", &limit) != 0);
	memset(&context, 0, sizeof(context));
	assert(mkdtemp(temporary));
	snprintf(context.directory, sizeof(context.directory), "%s", temporary);
	context.limit = 65536;
	strcpy(context.interface, "ppp1");
	strcpy(context.allowed, "SKN_A_1_1");
	strcpy(context.blocked, "SKN_B_1_1");
	context.inbound = context.outbound = 1;
	firewall = tmpfile();
	assert(firewall && skynet_render_firewall(&context, firewall) == 0);
	rewind(firewall);
	bytes = fread(rules, 1, sizeof(rules) - 1, firewall);
	rules[bytes] = '\0';
	assert(strstr(rules, "SKN_A_1_1 src -j RETURN") < strstr(rules, "SKN_B_1_1 src -j DROP"));
	assert(strstr(rules, "-o ppp1 -m set --match-set SKN_B_1_1 dst -j DROP"));
	fclose(firewall);
	firewall = tmpfile();
	assert(firewall && skynet_emit_set_entry(firewall, "SKN_B_1_1", "0.0.0.0/0", 3600) == 0);
	rewind(firewall);
	bytes = fread(rules, 1, sizeof(rules) - 1, firewall);
	rules[bytes] = '\0';
	assert(strstr(rules, "0.0.0.0/1 timeout 3600"));
	assert(strstr(rules, "128.0.0.0/1 timeout 3600"));
	fclose(firewall);
	strcpy(context.interface, "eth0;reboot");
	firewall = tmpfile();
	assert(firewall && skynet_render_firewall(&context, firewall) != 0);
	fclose(firewall);
	assert(skynet_store_open(&context) == 0);
	assert(skynet_rule(&context, "ban", "192.0.2.7/24") == 0);
	assert(skynet_rule(&context, "ban", "192.0.2.1/24") == 0);
	assert(rule_count(&context) == 1);
	context.enabled = 1;
	fail_apply = 1;
	assert(skynet_rule(&context, "ban", "198.51.100.1") != 0);
	assert(rule_count(&context) == 1);
	fail_apply = 0;
	assert(skynet_rule(&context, "whitelist", "192.0.2.1/24") == 0);
	assert(rule_count(&context) == 2);
	assert(skynet_temporary_ban(&context, "198.51.100.99", 60) != 0);
	context.time_ready = 1;
	context.now = 1700000000;
	assert(skynet_temporary_ban(&context, "198.51.100.99", 60) == 0);
	assert(rule_count(&context) == 3);
	context.now += 61;
	fail_apply = 1;
	assert(skynet_prune_rules(&context) != 0);
	assert(rule_count(&context) == 3);
	fail_apply = 0;
	assert(skynet_prune_rules(&context) == 0);
	assert(rule_count(&context) == 2);
	assert(skynet_temporary_ban(&context, "192.0.2.0/24", 60) == 0);
	context.now += 61;
	assert(skynet_prune_rules(&context) == 0);
	assert(rule_count(&context) == 2);
	context.limit = 2;
	assert(skynet_rule(&context, "ban", "203.0.113.1") != 0);
	assert(rule_count(&context) == 2);
	context.limit = 65536;
	assert(skynet_rule(&context, "ban", "192.0.2.1';DROP TABLE rules;") != 0);
	assert(rule_count(&context) == 2);
	assert(skynet_feed(&context, "add", "https://example.org/feed") == 0);
	assert(skynet_refresh_due(&context, 0) == 0);
	assert(skynet_refresh_due(&context, 24) == 1);
	assert(skynet_store_exec(&context, "INSERT INTO meta(key,value) VALUES('last_attempt','1700000122')") == 0);
	assert(skynet_refresh_due(&context, 24) == 0);
	assert(skynet_feed(&context, "remove", "https://example.org/feed") == 0);
	assert(skynet_test_feed(&context, "# list\r\n\r\n203.0.113.9\r\n203.0.113.9\r\n",
		sizeof("# list\r\n\r\n203.0.113.9\r\n203.0.113.9\r\n") - 1) == 0);
	assert(feed_count(&context) == 1);
	assert(skynet_test_feed(&context, "<html>error</html>\n", sizeof("<html>error</html>\n") - 1) != 0);
	assert(skynet_test_feed(&context, "1.2.3.4\n2001:db8::1\n", sizeof("1.2.3.4\n2001:db8::1\n") - 1) != 0);
	assert(skynet_test_feed(&context, "1.2.3.4\0trailing", sizeof("1.2.3.4\0trailing") - 1) != 0);
	assert(skynet_test_feed(&context, "# empty\n", sizeof("# empty\n") - 1) != 0);
	assert(feed_count(&context) == 1);
	context.limit = 1;
	assert(skynet_test_feed(&context, "1.2.3.4\n5.6.7.8\n", 16) != 0);
	assert(feed_count(&context) == 1);
	context.limit = 65536;
	status = tmpfile();
	assert(status && skynet_status(&context, dup(fileno(status))) == 0);
	rewind(status);
	bytes = fread(rules, 1, sizeof(rules) - 1, status);
	rules[bytes] = '\0';
	assert(sqlite3_prepare_v2(context.database, "SELECT json_valid(?1),json_extract(?1,'$.rule_count')",
		-1, &status_check, NULL) == SQLITE_OK);
	sqlite3_bind_text(status_check, 1, rules, -1, SQLITE_TRANSIENT);
	assert(sqlite3_step(status_check) == SQLITE_ROW);
	assert(sqlite3_column_int(status_check, 0) == 1);
	assert(sqlite3_column_int(status_check, 1) == 2);
	sqlite3_finalize(status_check);
	fclose(status);
	skynet_store_close(&context);
	assert(skynet_store_open(&context) == 0);
	assert(rule_count(&context) == 2);
	assert(skynet_store_exec(&context, "DROP INDEX rules_expiry; ALTER TABLE rules DROP COLUMN expires; PRAGMA user_version=1;") == 0);
	skynet_store_close(&context);
	assert(skynet_store_open(&context) == 0);
	assert(rule_count(&context) == 2);
	skynet_store_close(&context);
	snprintf(database, sizeof(database), "%s/policy.db", temporary);
	assert(unlink(database) == 0);
	assert(rmdir(temporary) == 0);
	puts("Skynet C core contracts passed");
	return 0;
}