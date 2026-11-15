#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "shared.h"
#include "login_budget.h"

#define LOGIN_BUDGET_FILE_LAN "/tmp/httpd/login-budget-lan"
#define LOGIN_BUDGET_FILE_WAN "/tmp/httpd/login-budget-wan"
#define LOGIN_BUDGET_FILE_UNKNOWN "/tmp/httpd/login-budget-unknown"
#define LOGIN_BUDGET_FILE_SSH "/tmp/httpd/login-budget-ssh"
#define LOGIN_BUDGET_MAGIC 0x484c4231
#define LOGIN_BUDGET_CAPACITY 5
#define LOGIN_BUDGET_REFILL_SECONDS 30

struct login_budget_state {
	unsigned int magic;
	unsigned int tokens;
	unsigned long last_refill;
};

static int login_budget_ensure_temp_dir(void)
{
	const char *directory = "/tmp/httpd";
	struct stat st;
	int created = 0;

	if (geteuid() != 0) {
		errno = EPERM;
		return -1;
	}
	if (mkdir(directory, 0700) == 0)
		created = 1;
	else if (errno != EEXIST)
		return -1;
	if (lstat(directory, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0) {
		errno = EPERM;
		return -1;
	}
	if (created && chmod(directory, 0700) != 0)
		return -1;
	if (lstat(directory, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != 0 ||
	    (st.st_mode & 0777) != 0700) {
		errno = EPERM;
		return -1;
	}
	return 0;
}

int
shared_login_attempt_admit(enum login_budget_scope scope, unsigned int *retry_after)
{
	struct login_budget_state state;
	struct stat st;
	const char *budget_file;
	unsigned long now = (unsigned long)uptime();
	unsigned long elapsed, refill;
	ssize_t count;
	int lock = -1, fd = -1, admitted = 0;

	if (retry_after)
		*retry_after = 0;
	switch (scope) {
	case LOGIN_BUDGET_LAN:
		budget_file = LOGIN_BUDGET_FILE_LAN;
		break;
	case LOGIN_BUDGET_WAN:
		budget_file = LOGIN_BUDGET_FILE_WAN;
		break;
	case LOGIN_BUDGET_UNKNOWN:
		budget_file = LOGIN_BUDGET_FILE_UNKNOWN;
		break;
	case LOGIN_BUDGET_SSH:
		budget_file = LOGIN_BUDGET_FILE_SSH;
		break;
	default:
		errno = EINVAL;
		goto denied;
	}
	lock = file_lock("httpd-login-budget");
	if (lock < 0)
		goto denied;
	if (login_budget_ensure_temp_dir() != 0)
		goto done;
	fd = open(budget_file, O_CREAT | O_RDWR | O_NOFOLLOW, 0600);
	if (fd < 0 || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) ||
	    st.st_uid != geteuid() || st.st_nlink != 1 || (st.st_mode & 077))
		goto done;

	memset(&state, 0, sizeof(state));
	if (st.st_size == 0) {
		state.magic = LOGIN_BUDGET_MAGIC;
		state.tokens = LOGIN_BUDGET_CAPACITY;
		state.last_refill = now;
	} else {
		count = read(fd, &state, sizeof(state));
		if (count != sizeof(state) || state.magic != LOGIN_BUDGET_MAGIC ||
		    state.tokens > LOGIN_BUDGET_CAPACITY) {
			state.magic = LOGIN_BUDGET_MAGIC;
			state.tokens = 0;
			state.last_refill = now;
		}
	}

	if (now < state.last_refill) {
		state.tokens = LOGIN_BUDGET_CAPACITY;
		state.last_refill = now;
	} else if (state.tokens < LOGIN_BUDGET_CAPACITY) {
		elapsed = now - state.last_refill;
		refill = elapsed / LOGIN_BUDGET_REFILL_SECONDS;
		if (refill) {
			if (refill >= LOGIN_BUDGET_CAPACITY - state.tokens)
				state.tokens = LOGIN_BUDGET_CAPACITY;
			else
				state.tokens += refill;
			state.last_refill += refill * LOGIN_BUDGET_REFILL_SECONDS;
		}
	}

	if (state.tokens) {
		--state.tokens;
		admitted = 1;
	} else if (retry_after) {
		*retry_after = LOGIN_BUDGET_REFILL_SECONDS -
			((now - state.last_refill) % LOGIN_BUDGET_REFILL_SECONDS);
	}

	if (lseek(fd, 0, SEEK_SET) < 0 || ftruncate(fd, 0) < 0 ||
	    write(fd, &state, sizeof(state)) != sizeof(state)) {
		admitted = 0;
		if (retry_after)
			*retry_after = LOGIN_BUDGET_REFILL_SECONDS;
	}

done:
	if (fd >= 0)
		close(fd);
	file_unlock(lock);
	if (admitted)
		return 1;
denied:
	if (retry_after && !*retry_after)
		*retry_after = LOGIN_BUDGET_REFILL_SECONDS;
	return 0;
}
