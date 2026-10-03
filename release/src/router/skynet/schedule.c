#define _GNU_SOURCE
#include "skynet.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <bcmnvram.h>

int skynet_watch(void)
{
	int lock;
	pid_t child;
	pid_t result;
	int status;
	int saved_errno;
	unsigned int tick;
	unsigned int grace;
	struct timespec delay = { 0, 100000000 };
	const char *enabled;

	lock = open("/tmp/skynet/watch.lock", O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (lock < 0)
		return -1;
	if (flock(lock, LOCK_EX | LOCK_NB)) {
		saved_errno = errno;
		close(lock);
		return saved_errno == EWOULDBLOCK ? 0 : -1;
	}
	while (!skynet_cancelled() && !skynet_stopping()) {
		enabled = nvram_get("skynet_enable");
		if (!enabled || strcmp(enabled, "1"))
			break;
		child = fork();
		if (child < 0) {
			close(lock);
			return -1;
		}
		if (!child) {
			execl("/usr/sbin/skynet", "skynet", "maintenance", (char *)NULL);
			_exit(127);
		}
		grace = 0;
		for (;;) {
			result = waitpid(child, &status, WNOHANG);
			if (result == child || (result < 0 && errno != EINTR))
				break;
			if (skynet_cancelled() || skynet_stopping())
				kill(child, grace++ < 40 ? SIGTERM : SIGKILL);
			nanosleep(&delay, NULL);
		}
		for (tick = 0; tick < 600 && !skynet_cancelled() && !skynet_stopping(); tick++)
			nanosleep(&delay, NULL);
	}
	close(lock);
	return 0;
}