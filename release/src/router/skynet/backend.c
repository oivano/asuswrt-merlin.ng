#include "skynet.h"
#include <sqlite3.h>
#include <libipset/ipset.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int library_error(struct ipset *handle, void *opaque, int code, const char *format, ...)
{
	va_list arguments;
	(void)handle;
	(void)opaque;
	(void)code;
	va_start(arguments, format);
	vfprintf(stderr, format, arguments);
	va_end(arguments);
	fputc('\n', stderr);
	return -1;
}

static int library_report(struct ipset *handle, void *opaque)
{
	const char *message = ipset_session_report_msg(ipset_session(handle));
	(void)opaque;
	if (message)
		fprintf(stderr, "%s\n", message);
	return -1;
}

static int library_output(struct ipset_session *session, void *opaque, const char *format, ...)
{
	va_list arguments;
	int result = 0;
	(void)session;
	if (opaque) {
		va_start(arguments, format);
		result = vfprintf((FILE *)opaque, format, arguments);
		va_end(arguments);
	}
	return result;
}

static struct ipset *library_open(FILE *output)
{
	struct ipset *handle;
	ipset_load_types();
	handle = ipset_init();
	if (handle)
		ipset_custom_printf(handle, library_error, library_report, library_output, output);
	return handle;
}

static int owned_set(const char *name)
{
	const char *cursor;
	if ((strncmp(name, "SKN_B_", 6) && strncmp(name, "SKN_A_", 6)) ||
	    !name[6] || strlen(name) >= 32)
		return 0;
	for (cursor = name + 6; *cursor; cursor++)
		if ((*cursor < '0' || *cursor > '9') && *cursor != '_')
			return 0;
	return 1;
}

static int set_command(const char *command, const char *name)
{
	struct ipset *handle;
	char *arguments[] = { "skynet", (char *)command, (char *)name, NULL };
	int result;
	if (!owned_set(name))
		return -1;
	handle = library_open(NULL);
	if (!handle)
		return -1;
	result = ipset_parse_argv(handle, 3, arguments);
	ipset_fini(handle);
	return result;
}

static int run_command(char *const arguments[], FILE *input)
{
	pid_t child;
	pid_t result;
	int status;
	struct timespec started;
	struct timespec now;
	struct timespec delay = { 0, 100000000 };

	if (skynet_cancelled() && skynet_stopping())
		return -1;
	if (input && (fflush(input) || fseek(input, 0, SEEK_SET)))
		return -1;
	child = fork();
	if (child < 0)
		return -1;
	if (!child) {
		setpgid(0, 0);
		if (input && dup2(fileno(input), STDIN_FILENO) < 0)
			_exit(127);
		execv(arguments[0], arguments);
		_exit(127);
	}
	setpgid(child, child);
	clock_gettime(CLOCK_MONOTONIC, &started);
	for (;;) {
		result = waitpid(child, &status, WNOHANG);
		if (result == child)
			return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
		if (result < 0 && errno != EINTR)
			return -1;
		clock_gettime(CLOCK_MONOTONIC, &now);
		if (now.tv_sec - started.tv_sec >= 10 || (skynet_cancelled() && skynet_stopping())) {
			kill(-child, SIGKILL);
			while (waitpid(child, &status, 0) < 0 && errno == EINTR) {}
			return -1;
		}
		nanosleep(&delay, NULL);
	}
}

static int publish_rules(struct skynet *context)
{
	char *arguments[] = { "/usr/sbin/iptables-restore", "--noflush", NULL };
	FILE *stream = tmpfile();
	int result;
	if (!stream)
		return -1;
	result = skynet_render_firewall(context, stream);
	if (!result)
		result = run_command(arguments, stream);
	fclose(stream);
	return result;
}

static int hooks(int insert)
{
	static const char *builtins[] = { "INPUT", "OUTPUT", "FORWARD" };
	static const char *chains[] = { "SKN_INPUT", "SKN_OUTPUT", "SKN_FORWARD" };
	size_t chain;
	int result;

	for (chain = 0; chain < 3; chain++) {
		char *check[] = { "/usr/sbin/iptables", "-C", (char *)builtins[chain], "-j", (char *)chains[chain], NULL };
		char *change[] = { "/usr/sbin/iptables", insert ? "-I" : "-D", (char *)builtins[chain], "-j", (char *)chains[chain], NULL };
		result = run_command(check, NULL);
		if (result != 0 && result != 1)
			return -1;
		if (insert && result == 0)
			continue;
		if (!insert && result == 1)
			continue;
		if (run_command(change, NULL))
			return -1;
	}
	return 0;
}

static int metadata(struct skynet *context, const char *key, char *value, size_t size)
{
	sqlite3_stmt *statement = NULL;
	int result = -1;
	value[0] = '\0';
	if (sqlite3_prepare_v2(context->database, "SELECT value FROM meta WHERE key=?1", -1, &statement, NULL) != SQLITE_OK)
		return -1;
	sqlite3_bind_text(statement, 1, key, -1, SQLITE_STATIC);
	if (sqlite3_step(statement) == SQLITE_ROW) {
		const char *stored = (const char *)sqlite3_column_text(statement, 0);
		if (stored && strlen(stored) < size) {
			strcpy(value, stored);
			result = 0;
		}
	}
	sqlite3_finalize(statement);
	return result;
}

static int save_metadata(struct skynet *context)
{
	sqlite3_stmt *statement = NULL;
	const char *keys[] = { "blocked", "allowed", "interface", "direction", "time_ready" };
	const char *values[] = { context->blocked, context->allowed, context->interface,
		context->inbound && context->outbound ? "all" : context->inbound ? "inbound" : "outbound",
		context->time_ready ? "1" : "0" };
	size_t field;
	int result = -1;
	if (sqlite3_prepare_v2(context->database, "INSERT OR REPLACE INTO meta(key,value) VALUES(?1,?2)", -1, &statement, NULL) != SQLITE_OK)
		return -1;
	for (field = 0; field < 5; field++) {
		sqlite3_reset(statement);
		sqlite3_bind_text(statement, 1, keys[field], -1, SQLITE_STATIC);
		sqlite3_bind_text(statement, 2, values[field], -1, SQLITE_TRANSIENT);
		if (sqlite3_step(statement) != SQLITE_DONE)
			goto finished;
	}
	result = 0;
finished:
	sqlite3_finalize(statement);
	return result;
}

static int prepare_sets(struct skynet *context)
{
	static const char *private_ranges[] = { "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
		"169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4" };
	sqlite3_stmt *statement = NULL;
	struct ipset *handle = NULL;
	FILE *stream = tmpfile();
	unsigned int entries = 0;
	size_t range;
	int step;
	int result = -1;

	if (!stream)
		return -1;
	fprintf(stream, "create %s hash:net family inet hashsize 64 maxelem %u timeout 0\n", context->blocked, context->limit + 1);
	fprintf(stream, "create %s hash:net family inet hashsize 64 maxelem %u timeout 0\n", context->allowed, context->limit + 10);
	for (range = 0; range < sizeof(private_ranges) / sizeof(private_ranges[0]); range++)
		if (skynet_emit_set_entry(stream, context->allowed, private_ranges[range], 0))
			goto finished;
	if (sqlite3_prepare_v2(context->database,
	    "SELECT entry,action,min(expires) FROM (SELECT entry,action,expires FROM rules "
	    "WHERE expires=0 OR (?1 AND expires>?2) UNION ALL SELECT entry,'ban',0 FROM feed_entries "
	    "JOIN feeds ON feeds.id=feed_entries.feed WHERE feeds.enabled=1) GROUP BY entry,action ORDER BY 2,1",
	    -1, &statement, NULL) != SQLITE_OK)
		goto finished;
	sqlite3_bind_int(statement, 1, context->time_ready);
	sqlite3_bind_int64(statement, 2, context->now);
	while ((step = sqlite3_step(statement)) == SQLITE_ROW) {
		const char *entry = (const char *)sqlite3_column_text(statement, 0);
		const char *action = (const char *)sqlite3_column_text(statement, 1);
		sqlite3_int64 expiry = sqlite3_column_int64(statement, 2);
		sqlite3_int64 remaining = expiry ? expiry - context->now : 0;
		if (++entries > context->limit || skynet_cancelled() || remaining < 0 || remaining > 604800 ||
		    skynet_emit_set_entry(stream, !strcmp(action, "allow") ? context->allowed : context->blocked, entry, (unsigned int)remaining))
			goto finished;
	}
	if (step != SQLITE_DONE || fflush(stream) || fseek(stream, 0, SEEK_SET))
		goto finished;
	handle = library_open(NULL);
	if (!handle)
		goto finished;
	ipset_envopt_set(ipset_session(handle), IPSET_ENV_EXIST);
	result = ipset_parse_stream(handle, stream);
finished:
	if (handle)
		ipset_fini(handle);
	sqlite3_finalize(statement);
	fclose(stream);
	return result;
}

int skynet_apply(struct skynet *context)
{
	struct skynet previous = *context;
	char direction[16];
	char previous_time[4];
	char *load[] = { "/sbin/modprobe", "xt_set", NULL };
	unsigned long generation = (unsigned long)time(NULL);
	int previous_ready;
	int published = 0;
	int reused = 0;

	if (sqlite3_get_autocommit(context->database) && skynet_store_exec(context, "BEGIN IMMEDIATE"))
		return -1;
	metadata(context, "blocked", previous.blocked, sizeof(previous.blocked));
	metadata(context, "allowed", previous.allowed, sizeof(previous.allowed));
	metadata(context, "interface", previous.interface, sizeof(previous.interface));
	metadata(context, "direction", direction, sizeof(direction));
	metadata(context, "time_ready", previous_time, sizeof(previous_time));
	previous.inbound = !strcmp(direction, "all") || !strcmp(direction, "inbound");
	previous.outbound = !strcmp(direction, "all") || !strcmp(direction, "outbound");
	previous_ready = owned_set(previous.blocked) && owned_set(previous.allowed) &&
		!set_command("list", previous.blocked) && !set_command("list", previous.allowed);
	if (run_command(load, NULL))
		goto failed;
	if (previous_ready && !context->dirty && (!strcmp(previous_time, "1")) == context->time_ready) {
		strcpy(context->blocked, previous.blocked);
		strcpy(context->allowed, previous.allowed);
		reused = 1;
	} else {
		snprintf(context->blocked, sizeof(context->blocked), "SKN_B_%lu_%lu", (unsigned long)getpid(), generation);
		if (!strcmp(context->blocked, previous.blocked))
			generation++;
		snprintf(context->blocked, sizeof(context->blocked), "SKN_B_%lu_%lu", (unsigned long)getpid(), generation);
		snprintf(context->allowed, sizeof(context->allowed), "SKN_A_%lu_%lu", (unsigned long)getpid(), generation);
		if (prepare_sets(context))
			goto failed;
	}
	if (skynet_cancelled() || publish_rules(context))
		goto failed;
	published = 1;
	if (hooks(1) || skynet_cancelled() || save_metadata(context) || skynet_store_exec(context, "COMMIT"))
		goto failed;
	if (!reused) {
		set_command("destroy", previous.blocked);
		set_command("destroy", previous.allowed);
	}
	return 0;
failed:
	skynet_store_exec(context, "ROLLBACK");
	if (published && previous_ready) {
		if (publish_rules(&previous))
			return -1;
	} else if (published && hooks(0)) {
		return -1;
	}
	if (!reused) {
		set_command("destroy", context->blocked);
		set_command("destroy", context->allowed);
	}
	return -1;
}

int skynet_stop(struct skynet *context)
{
	struct ipset *handle;
	FILE *stream;
	char name[64];
	char *list[] = { "skynet", "list", NULL };
	static const char *chains[] = { "SKN_INPUT", "SKN_OUTPUT", "SKN_FORWARD" };
	size_t chain;
	int result = 0;

	if (hooks(0))
		return -1;
	for (chain = 0; chain < 3; chain++) {
		char *flush[] = { "/usr/sbin/iptables", "-F", (char *)chains[chain], NULL };
		char *remove[] = { "/usr/sbin/iptables", "-X", (char *)chains[chain], NULL };
		int flush_result = run_command(flush, NULL);
		if (flush_result != 0 && flush_result != 1)
			return -1;
		if (flush_result == 0 && run_command(remove, NULL))
			return -1;
	}
	stream = tmpfile();
	if (!stream)
		return -1;
	handle = library_open(stream);
	if (!handle) {
		fclose(stream);
		return -1;
	}
	ipset_envopt_set(ipset_session(handle), IPSET_ENV_LIST_SETNAME);
	if (ipset_parse_argv(handle, 2, list))
		result = -1;
	ipset_fini(handle);
	rewind(stream);
	while (fgets(name, sizeof(name), stream)) {
		name[strcspn(name, "\r\n")] = '\0';
		if (owned_set(name) && set_command("destroy", name))
			result = -1;
	}
	fclose(stream);
	if (context->database && skynet_store_exec(context, "DELETE FROM meta WHERE key IN ('blocked','allowed','interface','direction')"))
		result = -1;
	return result;
}