#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/swap.h>
#include <bcmnvram.h>
#include <shutils.h>

static int skynet_mount_matches(char *path)
{
	char configured[PATH_MAX];
	char mounted[PATH_MAX];
	char active[PATH_MAX];
	FILE *stream;
	int matches = 0;

	if (!path)
		return 1;
	if (!realpath(path, mounted))
		return 0;
	if (realpath(nvram_safe_get("skynet_mount"), configured) && !strcmp(configured, mounted))
		return 1;
	stream = fopen("/tmp/skynet/mount", "r");
	if (stream) {
		matches = fgets(active, sizeof(active), stream) && !strcmp(active, mounted);
		fclose(stream);
	}
	return matches;
}

void start_skynet(char *path)
{
	char *argv[] = { "/usr/sbin/skynet", "start", NULL };
	char *watch[] = { "/usr/sbin/skynet", "watch", NULL };
	int pid;

	if (!skynet_mount_matches(path))
		return;
	if (!nvram_match("skynet_enable", "1"))
		argv[1] = "status";
	_eval(argv, NULL, 0, &pid);
	if (nvram_match("skynet_enable", "1"))
		_eval(watch, NULL, 0, &pid);
}

int stop_skynet(char *path)
{
	char *argv[] = { "/usr/sbin/skynet", "stop", NULL };
	char mounted[PATH_MAX];
	char filename[PATH_MAX];
	int result;
	int length;

	if (!skynet_mount_matches(path))
		return 0;
	result = _eval(argv, NULL, 120, NULL);
	if (result || !path)
		return result;
	if (!realpath(path, mounted))
		return -1;
	length = snprintf(filename, sizeof(filename), "%s/skynet/swap", mounted);
	if (length < 0 || (size_t)length >= sizeof(filename))
		return -1;
	if (swapoff(filename) && errno != EINVAL && errno != ENOENT)
		return -1;
	return 0;
}

int skynet_webui_action(const char *action)
{
	static const char *commands[] = {
		"skynet_status", "skynet_refresh", "skynet_ban", "skynet_unban",
		"skynet_whitelist", "skynet_unwhitelist", "skynet_feedadd", "skynet_feedremove",
		"skynet_feedselect", "skynet_feeddefaults"
	};
	size_t command;
	char *argv[] = { "/usr/sbin/skynet", NULL, NULL, NULL, NULL, NULL, NULL };
	int pid;
	int arguments;

	for (command = 0; command < sizeof(commands) / sizeof(commands[0]); command++) {
		if (strcmp(action, commands[command]))
			continue;
		argv[1] = (char *)action + 7;
		if (command >= 2 && command <= 5)
			argv[2] = nvram_safe_get("skynet_entry");
		else if (command >= 6) {
			static const char *operations[] = { "add", "remove", "select", "defaults" };
			argv[1] = "feed";
			argv[2] = (char *)operations[command - 6];
			argv[3] = command == 9 ? "" : nvram_safe_get("skynet_feed_url");
		}
		if (command == 2 && *nvram_safe_get("skynet_rule_seconds") && !nvram_match("skynet_rule_seconds", "0"))
			argv[3] = nvram_safe_get("skynet_rule_seconds");
		if (*nvram_safe_get("skynet_request")) {
			for (arguments = 0; argv[arguments]; arguments++)
				;
			argv[arguments++] = "--request";
			argv[arguments] = nvram_safe_get("skynet_request");
		}
		_eval(argv, NULL, 0, &pid);
		return 1;
	}
	return 0;
}