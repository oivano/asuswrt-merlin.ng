#define _GNU_SOURCE
#include "skynet.h"
#include <string.h>
#include <bcmnvram.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define SKYNET_STATE "/tmp/skynet-native"

static volatile sig_atomic_t interrupted;

static void interrupt_worker(int signal_number)
{
	(void)signal_number;
	interrupted = 1;
}

int skynet_cancelled(void)
{
	return interrupted;
}

int skynet_stopping(void)
{
	return !access(SKYNET_STATE "/stopping", F_OK);
}

static const char *setting(const char *name)
{
	const char *value = nvram_get(name);
	return value ? value : "";
}

static int secure_directory(const char *path)
{
	struct stat status;
	if (mkdir(path, 0700) && errno != EEXIST)
		return -1;
	if (lstat(path, &status) || !S_ISDIR(status.st_mode) || status.st_uid != geteuid())
		return -1;
	return chmod(path, 0700);
}

int skynet_storage(struct skynet *context, const char *mountpoint)
{
	char canonical[4096];
	struct mntent *mount;
	FILE *mounts;
	int found = 0;
	int length;
	struct stat status;

	if (!mountpoint || !*mountpoint || !realpath(mountpoint, canonical))
		return -1;
	if (strncmp(canonical, "/tmp/mnt/", 9) && strncmp(canonical, "/mnt/", 5))
		return -1;
	mounts = setmntent("/proc/mounts", "r");
	if (!mounts)
		return -1;
	while ((mount = getmntent(mounts))) {
		if (!strcmp(mount->mnt_dir, canonical) && !strncmp(mount->mnt_fsname, "/dev/", 5) &&
		    (!strcmp(mount->mnt_type, "ext2") || !strcmp(mount->mnt_type, "ext3") || !strcmp(mount->mnt_type, "ext4")) &&
		    hasmntopt(mount, "rw")) {
			found = 1;
			break;
		}
	}
	endmntent(mounts);
	if (!found || chdir(canonical))
		return -1;
	length = snprintf(context->directory, sizeof(context->directory), "%s/skynet-native", canonical);
	if (length < 0 || (size_t)length >= sizeof(context->directory) || secure_directory(context->directory))
		return -1;
	if (stat(context->directory, &status) || access(context->directory, W_OK))
		return -1;
	return 0;
}

int skynet_swap_ready(void)
{
	FILE *stream = fopen("/proc/swaps", "r");
	char line[4096];
	char path[4096];
	char type[32];
	unsigned long size;
	unsigned long total = 0;

	if (!stream)
		return 0;
	while (fgets(line, sizeof(line), stream)) {
		if (sscanf(line, "%4095s %31s %lu", path, type, &size) == 3 && !strcmp(type, "file"))
			total += size;
	}
	fclose(stream);
	return total >= 1048512;
}

int skynet_lock(struct skynet *context)
{
	context->lock = open(SKYNET_STATE "/policy.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (context->lock < 0 || flock(context->lock, LOCK_EX | LOCK_NB))
		return -1;
	context->lock_held = 1;
	return 0;
}

static int same_executable(pid_t worker)
{
	char path[64];
	struct stat candidate;
	struct stat current;
	if (worker <= 1 || worker == getpid())
		return 0;
	snprintf(path, sizeof(path), "/proc/%ld/exe", (long)worker);
	return !stat(path, &candidate) && !stat("/proc/self/exe", &current) &&
		candidate.st_dev == current.st_dev && candidate.st_ino == current.st_ino;
}

static int stop_workers(void)
{
	DIR *directory;
	struct dirent *entry;
	char *end;
	long worker;
	unsigned int attempt;
	int running;
	struct timespec delay = { 0, 100000000 };
	int marker = open(SKYNET_STATE "/stopping", O_CREAT | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);

	if (marker < 0)
		return -1;
	close(marker);
	for (attempt = 0; attempt < 100; attempt++) {
		running = 0;
		directory = opendir(SKYNET_STATE);
		if (!directory)
			return -1;
		while ((entry = readdir(directory))) {
			if (strncmp(entry->d_name, "worker.", 7))
				continue;
			worker = strtol(entry->d_name + 7, &end, 10);
			if (*end || worker <= 1 || worker > 4194304 || !same_executable((pid_t)worker))
				continue;
			running = 1;
			kill((pid_t)worker, attempt < 50 ? SIGTERM : SIGKILL);
		}
		closedir(directory);
		if (!running)
			return 0;
		nanosleep(&delay, NULL);
	}
	return -1;
}

static int addon_active(void)
{
	static const char *paths[] = { "/jffs/scripts/firewall-start", "/jffs/scripts/service-event" };
	size_t path;
	char line[4096];
	for (path = 0; path < sizeof(paths) / sizeof(paths[0]); path++) {
		FILE *stream = fopen(paths[path], "r");
		if (!stream)
			continue;
		while (fgets(line, sizeof(line), stream)) {
			char *cursor = line;
			while (*cursor == ' ' || *cursor == '\t')
				cursor++;
			if (*cursor != '#' && (strstr(cursor, "# Skynet") || strstr(cursor, "/jffs/scripts/firewall"))) {
				fclose(stream);
				return 1;
			}
		}
		fclose(stream);
	}
	return 0;
}

static int publish_status(struct skynet *context)
{
	char temporary[128];
	int output;
	int result;
	snprintf(temporary, sizeof(temporary), SKYNET_STATE "/status.%ld", (long)getpid());
	output = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (output < 0)
		return -1;
	if (context->database) {
		result = skynet_status(context, output);
	} else {
		char response[256];
		int length = snprintf(response, sizeof(response),
			"{\"enabled\":%d,\"available\":false,\"last_error\":%d,\"limit\":%u,\"rules\":[],\"rule_count\":0,\"feed_entries\":0,\"feeds\":[]}\n",
			context->enabled, context->error, context->limit);
		result = write(output, response, (size_t)length) == length ? 0 : -1;
		if (close(output))
			result = -1;
	}
	if (!result)
		result = rename(temporary, SKYNET_STATE "/status.json");
	if (result)
		unlink(temporary);
	if (secure_directory("/www/user/skynet"))
		return -1;
	if (unlink("/www/user/skynet/status.json") && errno != ENOENT)
		return -1;
	if (symlink(SKYNET_STATE "/status.json", "/www/user/skynet/status.json"))
		return -1;
	return result;
}

static int remember_mount(struct skynet *context)
{
	char temporary[128];
	char mountpoint[4096];
	char *separator;
	FILE *stream;
	int result;
	int descriptor;

	strcpy(mountpoint, context->directory);
	separator = strrchr(mountpoint, '/');
	if (!separator)
		return -1;
	*separator = '\0';
	snprintf(temporary, sizeof(temporary), SKYNET_STATE "/mount.%ld", (long)getpid());
	descriptor = open(temporary, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (descriptor < 0)
		return -1;
	stream = fdopen(descriptor, "w");
	if (!stream) {
		close(descriptor);
		unlink(temporary);
		return -1;
	}
	result = fputs(mountpoint, stream) < 0 ? -1 : 0;
	if (fclose(stream))
		result = -1;
	if (!result)
		result = rename(temporary, SKYNET_STATE "/mount");
	if (result)
		unlink(temporary);
	return result;
}

int main(int argc, char **argv)
{
	struct skynet context;
	const char *command = argc > 1 ? argv[1] : "status";
	char key[64];
	char workerfile[128] = "";
	char oldmount[4096];
	char configuredmount[4096];
	FILE *stream;
	int marker;
	int result = -1;
	int stop = !strcmp(command, "stop");
	int policy_command;
	const char *direction;
	const char *mountpoint;
	const char *interface;
	unsigned int unit;
	unsigned int seconds;
	unsigned int hours;
	char *end;
	unsigned long configured_hours;

	memset(&context, 0, sizeof(context));
	context.lock = -1;
	context.limit = SKYNET_DEFAULT_LIMIT;
	context.enabled = !strcmp(setting("skynet_enable"), "1");
	context.time_ready = !strcmp(setting("ntp_ready"), "1");
	context.now = context.time_ready ? (int64_t)time(NULL) : 0;
	openlog("Skynet", LOG_PID, LOG_USER);
	if (geteuid() || secure_directory(SKYNET_STATE))
		return 1;
	signal(SIGTERM, interrupt_worker);
	signal(SIGINT, interrupt_worker);
	if (stop) {
		if (access(SKYNET_STATE "/mount", F_OK)) {
			result = 0;
			goto finished;
		}
		if (stop_workers())
			goto finished;
	} else {
		if (!access(SKYNET_STATE "/stopping", F_OK))
			goto finished;
		snprintf(workerfile, sizeof(workerfile), SKYNET_STATE "/worker.%ld", (long)getpid());
		if (unlink(workerfile) && errno != ENOENT)
			goto finished;
		marker = open(workerfile, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
		if (marker < 0)
			goto finished;
		close(marker);
		if (!access(SKYNET_STATE "/stopping", F_OK))
			goto finished;
	}
	if (!strcmp(command, "watch")) {
		result = skynet_watch();
		goto finished;
	}
	if (skynet_lock(&context)) {
		result = !strcmp(command, "start") ? 0 : -1;
		context.error = 3;
		goto finished;
	}
	if (stop) {
		result = skynet_stop(&context);
		if (!result)
			unlink(SKYNET_STATE "/mount");
		goto finished;
	}
	if (*setting("skynet_max_entries") && skynet_parse_limit(setting("skynet_max_entries"), &context.limit)) {
		context.error = 2;
		goto finished;
	}
	if (!strcmp(command, "start") && !context.enabled) {
		result = 0;
		goto finished;
	}
	if (addon_active()) {
		context.error = 4;
		goto finished;
	}
	mountpoint = setting("skynet_mount");
	if (!*mountpoint && !context.enabled && !strcmp(command, "status")) {
		result = 0;
		goto finished;
	}
	stream = fopen(SKYNET_STATE "/mount", "r");
	if (stream) {
		if (fgets(oldmount, sizeof(oldmount), stream) && realpath(mountpoint, configuredmount) &&
		    strcmp(oldmount, configuredmount) && strcmp(command, "status")) {
			fclose(stream);
			context.error = 5;
			goto finished;
		}
		fclose(stream);
	}
	if (skynet_storage(&context, mountpoint) || skynet_store_open(&context)) {
		context.error = 6;
		goto finished;
	}
	unit = !strcmp(setting("wan1_primary"), "1") ? 1 : 0;
	snprintf(key, sizeof(key), "wan%u_gw_ifname", unit);
	interface = setting(key);
	if (!*interface) {
		snprintf(key, sizeof(key), "wan%u_ifname", unit);
		interface = setting(key);
	}
	if (strlen(interface) >= sizeof(context.interface))
		goto finished;
	strcpy(context.interface, interface);
	direction = setting("skynet_filter");
	context.inbound = !*direction || !strcmp(direction, "all") || !strcmp(direction, "inbound");
	context.outbound = !*direction || !strcmp(direction, "all") || !strcmp(direction, "outbound");
	if (!context.inbound && !context.outbound)
		goto finished;
	policy_command = strcmp(command, "status") && strcmp(command, "install") &&
		!(argc == 4 && !strcmp(command, "feed") && !strcmp(argv[2], "add"));
	if (context.enabled && policy_command &&
	    (!skynet_swap_ready() || strcmp(setting("fw_enable_x"), "1") || strcmp(setting("ctf_disable"), "1"))) {
		context.error = 7;
		goto finished;
	}
	if (!strcmp(command, "start")) {
		if (!context.enabled) {
			result = 0;
		} else if (!remember_mount(&context)) {
			result = skynet_apply(&context);
		}
	} else if (!strcmp(command, "status")) {
		result = skynet_status(&context, dup(STDOUT_FILENO));
	} else if (!strcmp(command, "install")) {
		result = 0;
	} else if (argc == 3 && (!strcmp(command, "ban") || !strcmp(command, "unban") ||
	    !strcmp(command, "whitelist") || !strcmp(command, "unwhitelist"))) {
		result = skynet_rule(&context, command, argv[2]);
	} else if (argc == 4 && !strcmp(command, "feed")) {
		result = skynet_feed(&context, argv[2], argv[3]);
	} else if (argc == 4 && !strcmp(command, "ban")) {
		if (!context.time_ready)
			context.error = 8;
		else if (skynet_parse_seconds(argv[3], &seconds))
			context.error = 2;
		else
			result = skynet_temporary_ban(&context, argv[2], seconds);
	} else if (!strcmp(command, "refresh")) {
		if (!strcmp(setting("ntp_ready"), "1"))
			result = skynet_refresh(&context);
		else
			context.error = 8;
	} else if (!strcmp(command, "maintenance")) {
		result = skynet_prune_rules(&context);
		configured_hours = strtoul(setting("skynet_refresh_hours"), &end, 10);
		if (*end || configured_hours > 168) {
			context.error = 2;
			result = -1;
		} else if (!result && context.enabled) {
			hours = (unsigned int)configured_hours;
			result = skynet_refresh_due(&context, hours);
			if (result > 0)
				result = skynet_refresh(&context);
		}
	} else {
		context.error = 9;
		fprintf(stderr, "Supported: status, install, start, stop, refresh, maintenance, ban CIDR [seconds], unban/whitelist/unwhitelist CIDR, feed add/remove HTTPS-URL\n");
	}
finished:
	if (result && !context.error)
		context.error = 1;
	if (context.lock_held)
		publish_status(&context);
	if (result)
		syslog(LOG_ERR, "%s failed (error %d)", command, context.error);
	skynet_store_close(&context);
	if (context.lock >= 0)
		close(context.lock);
	if (*workerfile)
		unlink(workerfile);
	if (stop)
		unlink(SKYNET_STATE "/stopping");
	closelog();
	return result ? 1 : 0;
}