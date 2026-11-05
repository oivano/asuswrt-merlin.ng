
#define _GNU_SOURCE
#include <stdarg.h>
#include <time.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <sys/timeb.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "log.h"

#define BUFSIZE		4096

#ifdef _WIN32
#define snprintf	_snprintf
#endif

FILE *logFile = NULL;
int logLevel = 20;

const char *logTime()
{
	static char buf[128];
	char *p = 0;
	time_t lTime;
	struct tm *tm1;

	time(&lTime);	
	tm1 = localtime(&lTime);	
	strcpy(buf, asctime(tm1));
	p = strchr(buf, '\n');

	if (p) *p = '\0';
    return buf;
}

void log_open(const char *file, int level)
{
	struct stat st;
	int descriptor;

	logLevel = level;

	if (logFile)
		log_close();

	if (file && *file) {
		descriptor = open(file, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0600);
		if (descriptor >= 0) {
			if (fstat(descriptor, &st) < 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
			    st.st_nlink != 1 || fchmod(descriptor, 0600) < 0 ||
			    fchown(descriptor, 0, 0) < 0 || fchmod(descriptor, 0600) < 0 ||
			    fstat(descriptor, &st) < 0 ||
			    !S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_gid != 0 ||
			    st.st_nlink != 1 || (st.st_mode & 0777) != 0600) {
				close(descriptor);
			} else {
				logFile = fdopen(descriptor, "a");
				if (!logFile)
					close(descriptor);
			}
		}
	}
	if (!logFile) 
	{
		logFile = stderr;
		if (file && *file)
			LOG(1) ("Error open log file: %s\n", file);
	}
	//for test only!!!
	//logFile = stderr;
}

void log_close()
{
	if (logFile && logFile != stderr) {
		fclose(logFile);
		logFile = NULL;
	}
}

void log_print(const char *fmt, ...)
{
	char buf[BUFSIZE];
	
	va_list args;
	va_start(args, fmt);

	snprintf(buf, sizeof(buf), "%s| %s", logTime(), fmt);
  if(logFile) {
    vfprintf(logFile, buf, args);
    fflush(logFile);
  }

	va_end(args);
}
