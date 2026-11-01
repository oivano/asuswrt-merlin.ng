/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/
#include "tool_setup.h"

#ifdef _WIN32
#include <tchar.h>
#endif

#include <signal.h>

#ifdef __linux__
#include <time.h>
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "tool_cfgable.h"
#include "tool_doswin.h"
#include "tool_msgs.h"
#include "tool_operate.h"
#include "tool_vms.h"
#include "tool_main.h"
#include "tool_stderr.h"

#ifdef __VMS
/*
 * vms_show is a global variable, used in main() as parameter for
 * function vms_special_exit() to allow proper curl tool exiting.
 * Its value may be set in other tool_*.c source files thanks to
 * forward declaration present in tool_vms.h
 */
int vms_show = 0;
#endif

#ifdef __AMIGA__
#ifdef __GNUC__
#define CURL_USED __attribute__((used))
#else
#define CURL_USED
#endif
static const char CURL_USED min_stack[] = "$STACK:32768";
#endif

#ifdef __MINGW32__
/*
 * There seems to be no way to escape "*" in command-line arguments with MinGW
 * when command-line argument globbing is enabled under the MSYS shell, so turn
 * it off.
 */
extern int _CRT_glob;
int _CRT_glob = 0;
#endif /* __MINGW32__ */

/* if we build a static library for unit tests, there is no main() function */
#ifndef UNITTESTS

/*
 * Ensure that file descriptors 0, 1 and 2 (stdin, stdout, stderr) are
 * open before starting to run. Otherwise, the first three network
 * sockets opened by curl could be used for input sources, downloaded data
 * or error logs as they are effectively stdin, stdout and/or stderr.
 *
 * fcntl's F_GETFD instruction returns -1 if the file descriptor is closed,
 * otherwise it returns "the file descriptor flags (which typically can only
 * be FD_CLOEXEC, which is not set here).
 */
static int main_checkfds(void)
{
#if defined(HAVE_FCNTL) && defined(HAVE_PIPE)
  const char * const devnull = "/dev/null";
  int fd;
  while((fcntl(STDIN_FILENO, F_GETFD) == -1)) {
    fd = curlx_open(devnull, O_RDONLY);
    if(fd < 0)
      return 1;
  }
  while((fcntl(STDOUT_FILENO, F_GETFD) == -1)) {
    fd = curlx_open(devnull, O_WRONLY);
    if(fd < 0)
      return 1;
  }
  while((fcntl(STDERR_FILENO, F_GETFD) == -1)) {
    fd = curlx_open(devnull, O_WRONLY);
    if(fd < 0)
      return 1;
  }
#endif /* HAVE_FCNTL && HAVE_PIPE */
  return 0;
}

#ifdef CURL_MEMDEBUG
static void memory_tracking_init(void)
{
  char *env;
  /* if CURL_MEMDEBUG is set, this starts memory tracking message logging */
  env = curl_getenv("CURL_MEMDEBUG");
  if(env) {
    /* use the value as filename */
    char fname[512];
    curlx_strcopy(fname, sizeof(fname), env, strlen(env));
    curl_free(env);
    curl_dbg_memdebug(fname);
    /* this weird stuff here is to make curl_free() get called before
       curl_dbg_memdebug() as otherwise memory tracking logs a curlx_free()
       without an alloc! */
  }
  /* if CURL_MEMLIMIT is set, this enables fail-on-alloc-number-N feature */
  env = curl_getenv("CURL_MEMLIMIT");
  if(env) {
    curl_off_t num;
    const char *p = env;
    if(!curlx_str_number(&p, &num, LONG_MAX))
      curl_dbg_memlimit((long)num);
    curl_free(env);
  }
}
#else
#  define memory_tracking_init() tool_nop_stmt
#endif

#ifdef __linux__
#define CURL_AUDIT_CMD_MAX 1024
#define CURL_AUDIT_DEPTH_MAX 8

static int curl_audit_read_cmdline(int pid, char *cmdline, size_t cmdline_size)
{
  char path[64];
  FILE *fp;
  size_t used = 0;
  int ch;

  snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
  fp = fopen(path, "r");
  if(!fp)
    return 0;

  while((ch = fgetc(fp)) != EOF && used + 1 < cmdline_size) {
    if(ch == '\0')
      ch = ' ';
    else if(ch < 32 || ch == 127)
      ch = '?';
    cmdline[used++] = (char)ch;
  }
  fclose(fp);

  while(used && cmdline[used - 1] == ' ')
    --used;
  cmdline[used] = '\0';
  return used != 0;
}

static int curl_audit_get_parent(int pid)
{
  char path[64];
  char line[128];
  FILE *fp;
  int parent = 0;

  snprintf(path, sizeof(path), "/proc/%d/status", pid);
  fp = fopen(path, "r");
  if(!fp)
    return 0;

  while(fgets(line, sizeof(line), fp)) {
    if(!strncmp(line, "PPid:", 5)) {
      (void)sscanf(line + 5, "%d", &parent);
      break;
    }
  }
  fclose(fp);
  return parent;
}

static void curl_audit_log(void)
{
  static const char log_path[] = "/jffs/curllst";
  static const char backup_path[] = "/jffs/curllst.1";
  FILE *fp;
  long log_size = 0;
  int pid = (int)getpid();
  int depth;

  fp = fopen(log_path, "r");
  if(fp) {
    if(fseek(fp, 0, SEEK_END) == 0)
      log_size = ftell(fp);
    fclose(fp);
  }
  if(log_size >= 10 * 1024) {
    (void)remove(backup_path);
    if(rename(log_path, backup_path))
      return;
  }

  fp = fopen(log_path, "a");
  if(!fp)
    return;

  for(depth = 0; depth < CURL_AUDIT_DEPTH_MAX && pid > 1; ++depth) {
    char cmdline[CURL_AUDIT_CMD_MAX];
    int parent;

    if(!curl_audit_read_cmdline(pid, cmdline, sizeof(cmdline)))
      break;
    parent = curl_audit_get_parent(pid);
    fprintf(fp, "[%u](%d)%s\n", (unsigned)time(NULL), parent, cmdline);
    if(parent <= 1 || parent == pid)
      break;
    pid = parent;
  }
  fclose(fp);
}
#endif

/*
 * curl tool main function.
 */
#ifdef _UNICODE
#ifdef CURL_HAVE_DIAG
/* GCC does not know about wmain() */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#pragma GCC diagnostic ignored "-Wmissing-declarations"
#endif
int wmain(int argc, wchar_t *argv[])
#else
int main(int argc, char *argv[])
#endif
{
  CURLcode result = CURLE_OK;

  tool_init_stderr();

#ifdef __linux__
  curl_audit_log();
#endif

#ifdef _WIN32
  /* Undocumented diagnostic option to list the full paths of all loaded
     modules. This is purposely pre-init. */
  if(argc == 2 && !_tcscmp(argv[1], _TEXT("--dump-module-paths"))) {
    struct curl_slist *item, *head = GetLoadedModulePaths();
    for(item = head; item; item = item->next)
      curl_mprintf("%s\n", item->data);
    curl_slist_free_all(head);
    return head ? 0 : 1;
  }

  /* win32_init must be called before other init routines. */
  result = win32_init();
  if(result) {
    errorf("(%d) Windows-specific init failed", (int)result);
    return (int)result;
  }
#endif

  if(main_checkfds()) {
    errorf("out of file descriptors");
    return CURLE_FAILED_INIT;
  }

#if defined(HAVE_SIGNAL) && defined(SIGPIPE)
#ifdef DEBUGBUILD
  if(!curl_getenv("CURL_SIGPIPE_DEBUG"))
#endif
  (void)signal(SIGPIPE, SIG_IGN);
#endif

  /* Initialize memory tracking */
  memory_tracking_init();

  /* Initialize the curl library - do not call any libcurl functions before
     this point */
  result = globalconf_init();
  if(!result) {
    /* Start our curl operation */
    result = operate(argc, argv);

    /* Perform the main cleanup */
    globalconf_free();
  }

#ifdef _WIN32
  /* Flush buffers of all streams opened in write or update mode */
  fflush(NULL);
#endif

#ifdef __VMS
  vms_special_exit(result, vms_show);
#else
  return (int)result;
#endif
}

#ifdef _UNICODE
#ifdef CURL_HAVE_DIAG
#pragma GCC diagnostic pop
#endif
#endif

#endif /* !UNITTESTS */
