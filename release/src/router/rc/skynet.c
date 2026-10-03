#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
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
	stream = fopen("/tmp/skynet-native/mount", "r");
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

	if (skynet_mount_matches(path))
		return _eval(argv, NULL, 120, NULL);
	return 0;
}

int skynet_webui_action(const char *action)
{
	static const char *commands[] = {
		"skynet_status", "skynet_refresh", "skynet_ban", "skynet_unban",
		"skynet_whitelist", "skynet_unwhitelist", "skynet_feedadd", "skynet_feedremove"
	};
	size_t command;
	char *argv[] = { "/usr/sbin/skynet", NULL, NULL, NULL, NULL };
	int pid;

	for (command = 0; command < sizeof(commands) / sizeof(commands[0]); command++) {
		if (strcmp(action, commands[command]))
			continue;
		argv[1] = (char *)action + 7;
		if (command >= 2 && command <= 5)
			argv[2] = nvram_safe_get("skynet_entry");
		else if (command >= 6) {
			argv[1] = "feed";
			argv[2] = command == 6 ? "add" : "remove";
			argv[3] = nvram_safe_get("skynet_feed_url");
		}
		if (command == 2 && *nvram_safe_get("skynet_rule_seconds") && !nvram_match("skynet_rule_seconds", "0"))
			argv[3] = nvram_safe_get("skynet_rule_seconds");
		_eval(argv, NULL, 0, &pid);
		return 1;
	}
	return 0;
}