/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * Copyright 2012, ASUSTeK Inc.
 * All Rights Reserved.
 * 
 * THIS SOFTWARE IS OFFERED "AS IS", AND ASUS GRANTS NO WARRANTIES OF ANY
 * KIND, EXPRESS OR IMPLIED, BY STATUTE, COMMUNICATION OR OTHERWISE. BROADCOM
 * SPECIFICALLY DISCLAIMS ANY IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A SPECIFIC PURPOSE OR NONINFRINGEMENT CONCERNING THIS SOFTWARE.
 *
 */

#include "rc.h"
#include "netool.h"
#include <sys/wait.h>

#define MyDBG(fmt,args...) \
	if(f_exists(NETOOL_DEBUG) > 0) { \
		dbg("[Netool][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args); \
	}
#define ErrorMsg(fmt,args...) \
	dbg("[Netool][%s:(%d)]"fmt, __FUNCTION__, __LINE__, ##args);

#ifdef RTCONFIG_TRACEROUTE
#define TRACEROUTE    "/usr/sbin/traceroute"
#else
#define TRACEROUTE    "traceroute"
#endif

#define MUTEX pthread_mutex_t
#define MUTEXINIT(m) pthread_mutex_init(m, NULL)
#define MUTEXLOCK(m) pthread_mutex_lock(m)
#define MUTEXTRYLOCK(m) pthread_mutex_trylock(m)
#define MUTEXUNLOCK(m) pthread_mutex_unlock(m)
#define MUTEXDESTROY(m) pthread_mutex_destroy(m)

static void start_req_thread(void *rInfo, int type);
static int terminated = 1;
static MUTEX task_list_lock;
struct list *task_list=NULL;

#ifndef NON_P_THREAD
static int IN_EXEC = 0;
#endif

/* --------------------------------------------- *
 *           vpopen/vpclose Function Begin       *
 * --------------------------------------------- */
static FILE *vpopen(char *const argv[], pid_t *child)
{
	int pfd[2];
	FILE *fp;
	pid_t pid;
	int status;

	if (pipe(pfd) != 0)
		return NULL;
	fcntl(pfd[0], F_SETFD, FD_CLOEXEC);
	fcntl(pfd[1], F_SETFD, FD_CLOEXEC);
	pid = fork();
	if (pid == 0) {
		close(pfd[0]);
		if (dup2(pfd[1], STDOUT_FILENO) < 0 ||
		    dup2(pfd[1], STDERR_FILENO) < 0)
			_exit(127);
		if (pfd[1] != STDOUT_FILENO && pfd[1] != STDERR_FILENO)
			close(pfd[1]);
		execvp(argv[0], argv);
		_exit(127);
	}
	close(pfd[1]);
	if (pid < 0) {
		close(pfd[0]);
		return NULL;
	}
	fp = fdopen(pfd[0], "r");
	if (!fp) {
		close(pfd[0]);
		while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
			;
		return NULL;
	}
	*child = pid;
	return fp;
}

static int vpclose(FILE *fp, pid_t child)
{
	int status;
	fclose(fp);
	while (waitpid(child, &status, 0) < 0)
		if (errno != EINTR)
			return -1;
	return status;
}

static void probe_argv(REQUEST_INFO_T *req, char **argv, char numbers[3][16], int normal)
{
	int count = 0;
	int ping = req->type == REQ_PING_MODE || req->type == REQ_PING_NORMAL_MODE;
	int ipv6 = !strcmp(req->ver, "v6");

	snprintf(numbers[0], 16, "%d", ping ? req->ping_cnt : req->hops);
	snprintf(numbers[1], 16, "%d", req->response);
	if (ping) {
		argv[count++] = ipv6 ? "ping6" : "ping";
	} else {
#ifdef RTCONFIG_TRACEROUTE
		argv[count++] = TRACEROUTE;
		argv[count++] = ipv6 ? "-6" : "-4";
#else
		argv[count++] = ipv6 ? "traceroute6" : TRACEROUTE;
#endif
	}
	if (*req->interface) {
		argv[count++] = ping ? "-I" : "-i";
		argv[count++] = req->interface;
	}
	argv[count++] = ping ? "-c" : "-m";
	argv[count++] = numbers[0];
	argv[count++] = ping && normal ? "-W" : "-w";
	argv[count++] = numbers[1];
	if (!normal)
		argv[count++] = ping ? "-q" : "-n";
	argv[count++] = req->target;
	argv[count] = NULL;
}

static int log_tool(char *const argv[], const char *name, int always_marker)
{
	char result_path[128];
	char buffer[1024];
	size_t length;
	FILE *output, *input;
	pid_t child;
	int status;

	snprintf(result_path, sizeof(result_path), NETOOL_RESULT_DIR"/%s", name);
	unlink(result_path);
	output = fopen(result_path, "w");
	if (!output)
		return -1;
	fcntl(fileno(output), F_SETFD, FD_CLOEXEC);
	input = vpopen(argv, &child);
	if (!input) {
		fclose(output);
		return -1;
	}
	while ((length = fread(buffer, 1, sizeof(buffer), input)) > 0)
		fwrite(buffer, 1, length, output);
	status = vpclose(input, child);
	if (always_marker || status == 0)
		fputs("XU6J03M6\n", output);
	fclose(output);
	return status;
}
/* --------------------------------------------- *
 *           vpopen/vpclose Function End         *
 * --------------------------------------------- */
static int do_ping(void *rInfo)
{
	FILE *fp, *fp_w;
	char *argv[16];
	char numbers[3][16];
	pid_t child;
	char buf[256]={0};
	char result_path[sizeof(NETOOL_RESULT_DIR) + 128];
	char jitter_tmp[64]={0};
	char *pk_loss;
	char *ping, *p, *end;
	int  len;
	int  loop;
	
	REQUEST_INFO_T *req = rInfo;
	
	snprintf(result_path, sizeof(result_path), NETOOL_RESULT_DIR"/%s", req->target);
	
	probe_argv(req, argv, numbers, 0);
	
	loop = req->exec_cnt;
	
	fp = NULL;
	
	if ((fp_w = fopen(result_path, "w")) != NULL) {
		if (!strcmp(req->target, "")) {
			fprintf(fp_w, "[{\"loss\":\"\", \"ping\":\"\", \"jitter\":\"\"}]");
			fclose(fp_w);
			return -1;
		}
		
		len = strlen("min/avg/max = ");
		
		fprintf(fp_w, "[");
		
		while (loop > 0) {
			if ((fp = vpopen(argv, &child)) != NULL) {
				while(fgets(buf, sizeof(buf), fp)) {
					pk_loss = strstr(buf, "received,");
					if (pk_loss != NULL) {
						end = strrchr(buf, '%');
						*end  = '\0';
						MyDBG("Packet Loss:%s\n", pk_loss+strlen("received,"));
						fprintf(fp_w, "{\"loss\":\"%d\", ", atoi(pk_loss+strlen("received,")));
						if( atoi(pk_loss+strlen("received,")) == 100) {
							fprintf(fp_w, "\"ping\":\"\", \"jitter\":\"\"}");
						}
					}
					ping = strstr(buf, "min/avg/max");
					if (ping != NULL) {
						p = strrchr(buf, '=');
						while (*p != '/') {
							p++;
						}
						*p = '\0';
						MyDBG("Ping: [%s], Jitter: [%3.3f]\n", ping+len, atof(ping+len) - atof(jitter_tmp));
						fprintf(fp_w, "\"ping\":\"%s\", \"jitter\":\"%3.3f\"}", ping+len, atof(ping+len) - atof(jitter_tmp));
						snprintf(jitter_tmp, sizeof(jitter_tmp), "%s", ping+len);
					}
				}
				
			} else {
				ErrorMsg("fp = %p\n", fp); 
				perror(argv[0]);
			}
			loop--;
			
			if (loop > 0) 
				fprintf(fp_w, ",");
				
			if (fp)
				vpclose(fp, child);
		}
		
		fprintf(fp_w, "]");
		fclose(fp_w);
	}
	return 0;
	
}

static int do_ping_normal(void *rInfo)
{
	char *argv[16];
	char numbers[3][16];
	REQUEST_INFO_T *req = rInfo;
	probe_argv(req, argv, numbers, 1);
	return log_tool(argv, NETOOL_RESULT_PING_NORMAL_LOG, 1);
}

static int do_traceroute_normal(void *rInfo)
{
	char *argv[16];
	char numbers[3][16];
	REQUEST_INFO_T *req = rInfo;
	probe_argv(req, argv, numbers, 1);
	return log_tool(argv, NETOOL_RESULT_TRACERT_NORMAL_LOG, 0);
}

static int do_nslookup(void *rInfo)
{
	REQUEST_INFO_T *req = rInfo;
	char *argv[] = { "nslookup", req->target, NULL };
	return log_tool(argv, NETOOL_RESULT_NSLOOKUP_LOG, 0);
}

static char *get_netstat_option(const int opt)
{
	static char Info[16];
	int  i, x;
	
	x = 0;
	memset(&Info, 0, sizeof(Info));
	
	for(i = 0; i < MAX_NETSTAT_OPTIONS_NUM; i++) {
		if ((opt & (1 << i)) && !x) {
			snprintf(Info, sizeof(Info), "%s", netstInfo[i].option);
			x = 1;
			continue;
		}
		if ((opt & (1 << i)) && x) {
			snprintf(Info + strlen(Info), sizeof(Info) - strlen(Info), "%s", netstInfo[i].option);
		}
	}
	return Info;
	
}

static char *get_netstat_nat_option(const int opt)
{
	static char Info[16];
	int  i, x;
	
	x = 0;
	memset(&Info, 0, sizeof(Info));
	
	if (!opt)
		return "";

	for(i = 0; i < MAX_NETSTAT_NAT_OPTIONS_NUM; i++) {
		if ((opt & (1 << i)) && !x) {
			snprintf(Info, sizeof(Info), "-%s", netst_natInfo[i].option);
			x = 1;
			continue;
		}
		if ((opt & (1 << i)) && x) {
			snprintf(Info + strlen(Info), sizeof(Info) - strlen(Info), "%s", netst_natInfo[i].option);
		}
	}
	return Info;
	
}

static int do_netstat(void *rInfo)
{
	char options[16];
	REQUEST_INFO_T *req = rInfo;
	char *argv[] = { "netstat", options, NULL };
	snprintf(options, sizeof(options), "-W%s", get_netstat_option(req->netst));
	return log_tool(argv, NETOOL_RESULT_NETSTAT_LOG, 0);
}

static int do_netstat_nat(void *rInfo)
{
	char options[16];
	char *argv[12];
	int count = 0;
	REQUEST_INFO_T *req = rInfo;
	argv[count++] = "netstat-nat";
	snprintf(options, sizeof(options), "%s", get_netstat_nat_option(req->netst));
	if (*options)
		argv[count++] = options;
	if (*req->sort) {
		argv[count++] = "-r";
		argv[count++] = req->sort;
	}
	if (*req->proto) {
		argv[count++] = "-p";
		argv[count++] = req->proto;
	}
	if (*req->srchost) {
		argv[count++] = "-s";
		argv[count++] = req->srchost;
	}
	if (*req->dsthost) {
		argv[count++] = "-d";
		argv[count++] = req->dsthost;
	}
	argv[count] = NULL;
	return log_tool(argv, NETOOL_RESULT_NETSTAT_NAT_LOG, 0);
}

static double get_last_tracert(char *xxx)
{
	const char * const delim = " ";
	char * const dupstr = strdup(xxx);
	char *saveptr = NULL;
	char *substr = NULL;
	int count = 0;
	double ping = 0;
	char buf[128] = {0};
	int i = 0;
	
	dupstr[strlen(dupstr)-1] = '\0';
	//MyDBG("Input String:[%s]\n", dupstr);
	substr = strtok_r(dupstr, delim, &saveptr);
	
	do {
		MyDBG("[#%d] sub string: %s\n", count, substr);
		count++;
		substr = strtok_r(NULL, delim, &saveptr);
		if (!strcmp(substr, "ms")) {
			ping += atof(buf);
			MyDBG("Ping%d:[%3.3f]\n", i, ping);
			i++;
			if (i == 3) 
				break;
		}
		snprintf(buf, sizeof(buf), "%s", substr);
	
	} while (substr);
	
	free(dupstr);
	
	return ping/3;
}

static int do_traceroute(void *rInfo)
{
	FILE *fp, *fp_w;
	char *argv[16];
	char numbers[3][16];
	pid_t child;
	char buf[256]={0};
	char result_path[sizeof(NETOOL_RESULT_DIR) + 128];
	char lastpingbuf[128] = {0};
	char *unping;
	int i = 0;
	int ln = 0;
	
	REQUEST_INFO_T *req = rInfo;
	
	snprintf(result_path, sizeof(result_path), NETOOL_RESULT_DIR"/%s", req->target);
	
	probe_argv(req, argv, numbers, 0);
	
	fp_w = fopen(result_path, "w");
	
	if (fp_w != NULL) {
		if (!strcmp(req->target, "")) {
			fprintf(fp_w, "[{\"ping\":\"\"}]");
			fclose(fp_w);
			return -1;
		}
		
		fprintf(fp_w, "[");
		
		if ((fp = vpopen(argv, &child)) != NULL) {
			while(fgets(buf, sizeof(buf), fp)) {
				printf("%s", buf);
				unping = strstr(buf, "*");
				if (unping != NULL) {
					i++;
				} else {
					ln++;
					snprintf(lastpingbuf, sizeof(lastpingbuf), "%s", buf);
				}
				if (i == 2) 
					break;
			}
			MyDBG("Lastping:%s\n", lastpingbuf);
		} else {
			ErrorMsg("fp = %p\n", fp); 
			perror(argv[0]);
		}
		if (fp)
			vpclose(fp, child);
		
		if (strlen(lastpingbuf) && strstr(lastpingbuf, "ms") != NULL) {
			//MyDBG("Last ping Avg: [%3.3f]\n", get_last_tracert((ln > 10) ? lastpingbuf : lastpingbuf+1));
			fprintf(fp_w, "{\"ping\":\"%3.3f\"}",get_last_tracert((ln > 10) ? lastpingbuf : lastpingbuf+1));
		} else {
			fprintf(fp_w, "{\"ping\":\"\"}");
		}
		fprintf(fp_w, "]");
		fclose(fp_w);
	}

#ifndef NON_P_THREAD
		REQUEST_INFO_T *req_task;
		struct listnode *lt;
		int del = 0;
		
		if (f_exists(NETOOL_QUEUE) > 0) {
			/* Search Target and drop it in task list */
			MUTEXLOCK(&task_list_lock);
			LIST_LOOP(task_list,req_task,lt)
			{
				if (!strcmp(req_task->target, req->target)) {
					del = 1;
					MyDBG("[Trget: %s Task Finished. REMOVE it in task list]\n", req_task->target)
					break;
				}
			}
			
			if (del) {
				listnode_delete(task_list, req_task);
				free(req_task);
			}
			MUTEXUNLOCK(&task_list_lock);
		}
		IN_EXEC = 0;
#endif
	return 0;
}

REQUEST_INFO_T *task_listcreate(REQUEST_INFO_T input)
{
	REQUEST_INFO_T *new=malloc(sizeof(*new));
	
	if (new)
		memcpy(new,&input,sizeof(*new));
	return new;
}

static int valid_token(const char *value, size_t size, const char *extra)
{
	const unsigned char *cursor = (const unsigned char *)value;
	if (!memchr(value, '\0', size) || *value == '-' ||
	    !strcmp(value, ".") || !strcmp(value, ".."))
		return 0;
	while (*cursor) {
		if (!((*cursor >= 'a' && *cursor <= 'z') ||
		      (*cursor >= 'A' && *cursor <= 'Z') ||
		      (*cursor >= '0' && *cursor <= '9') || strchr(extra, *cursor)))
			return 0;
		cursor++;
	}
	return 1;
}

static int valid_request(REQUEST_INFO_T *req)
{
	if (req->type <= REQ_GET_RESULT || req->type >= REQ_MODE_TOTAL ||
	    !valid_token(req->ver, sizeof(req->ver), "") ||
	    !valid_token(req->sort, sizeof(req->sort), "-") ||
	    !valid_token(req->proto, sizeof(req->proto), "") ||
	    !valid_token(req->srchost, sizeof(req->srchost), ".-:_") ||
	    !valid_token(req->dsthost, sizeof(req->dsthost), ".-:_") ||
	    !valid_token(req->interface, sizeof(req->interface), ".-:_") ||
	    !valid_token(req->target, sizeof(req->target), ".-:_%"))
		return 0;
	if ((*req->ver && strcmp(req->ver, "v4") && strcmp(req->ver, "v6")) ||
	    (*req->sort && strcmp(req->sort, "src") && strcmp(req->sort, "dst") &&
	     strcmp(req->sort, "src-port") && strcmp(req->sort, "dst-port") &&
	     strcmp(req->sort, "state")) ||
	    (*req->proto && strcmp(req->proto, "tcp") && strcmp(req->proto, "udp") &&
	     strcmp(req->proto, "icmp") && strcmp(req->proto, "igmp")))
		return 0;
	if (req->type <= REQ_NSLOOKUP_MODE && !*req->target)
		return 0;
	if (req->type <= REQ_TRACEROUTE_NORMAL_MODE &&
	    (req->response < 1 || req->response > 60))
		return 0;
	if ((req->type == REQ_PING_MODE || req->type == REQ_PING_NORMAL_MODE) &&
	    req->ping_cnt < 1)
		return 0;
	if (req->type == REQ_PING_MODE && req->exec_cnt < 1)
		return 0;
	if ((req->type == REQ_TRACEROUTE_MODE || req->type == REQ_TRACEROUTE_NORMAL_MODE) &&
	    (req->hops < 1 || req->hops > 64))
		return 0;
	if ((req->type == REQ_NETSTAT_MODE || req->type == REQ_NETSTAT_NAT_MODE) &&
	    (req->netst < 0 || (req->netst & ~0xff)))
		return 0;
	return 1;
}

void rcv_socket(int newsockfd)
{
	int    n;
	struct { pid_t pid; uid_t uid; gid_t gid; } peer;
	socklen_t peer_len = sizeof(peer);
	struct timeval timeout = { 2, 0 };
	time_t now;
	char   date[30];
	
	REQUEST_INFO_T req_t;
	if (getsockopt(newsockfd, SOL_SOCKET, SO_PEERCRED, &peer, &peer_len) < 0 ||
	    peer_len != sizeof(peer) || peer.uid != 0)
		return;
	
	bzero(&req_t,sizeof(REQUEST_INFO_T));
	
	if (setsockopt(newsockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
		return;
	n = recv(newsockfd, &req_t, sizeof(req_t), MSG_WAITALL);
	if (n != sizeof(req_t) || !valid_request(&req_t))
	{
		MyDBG("ERROR reading from socket.\n");
		return;
	}
	
	req_t.tstamp = time(&now);
	StampToDate(req_t.tstamp, date);
	
	MyDBG("[%s] REQ_TYPE[%d] PING_CNT:[%d] HOPS:[%d] RESPONSE_T:[%d] EXEC_CNT:[%d] \n \
	      \t\t\tVER:[%s] NETST:[0x%x] SORT:[%s] PROTO:[%s] SRC:[%s] DST:[%s] Interface:[%s] TARGET:[%s]\n", 
	      date, req_t.type, req_t.ping_cnt, req_t.hops, req_t.response, req_t.exec_cnt, 
	      req_t.ver, req_t.netst, req_t.sort, req_t.proto, req_t.srchost, req_t.dsthost, req_t.interface, req_t.target);
	
	/* Limit the maximum upper limit */
	if (req_t.type == REQ_PING_MODE) {
		if (req_t.ping_cnt > 10) 
			req_t.ping_cnt = 10;
		if (req_t.exec_cnt > 60)
			req_t.exec_cnt = 60;
	} else if (req_t.type == REQ_PING_NORMAL_MODE) {
		if (req_t.ping_cnt > 100) 
			req_t.ping_cnt = 100;
	}
	
	
#ifndef NON_P_THREAD
	
	REQUEST_INFO_T *sreq_t;
	
	if (f_exists(NETOOL_QUEUE) > 0) {
		if ( req_t.type == REQ_TRACEROUTE_MODE ) { /* Only queue traceroute request task */
		
			MUTEXLOCK(&task_list_lock);
			if(task_list) {
				sreq_t=NULL;
				sreq_t=task_listcreate(req_t);
				if(sreq_t)
					listnode_add(task_list,(void*)sreq_t);
			
			}
			MUTEXUNLOCK(&task_list_lock);
			return;
		}
	}
#endif 
	start_req_thread((void *)&req_t, req_t.type);
	
}
static int start_local_socket(void)
{
	struct sockaddr_un addr;
	int sockfd, newsockfd;
	int bind_result;
	mode_t old_umask;
	
	if ( (sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		ErrorMsg("socket error\n");
		perror("socket error");
		exit(-1);
	}
	fcntl(sockfd, F_SETFD, FD_CLOEXEC);
	
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, NETOOL_SOCKET_PATH, sizeof(addr.sun_path)-1);
	
	unlink(NETOOL_SOCKET_PATH);
	
	old_umask = umask(077);
	bind_result = bind(sockfd, (struct sockaddr*)&addr, sizeof(addr));
	umask(old_umask);
	if (bind_result == -1 || chmod(NETOOL_SOCKET_PATH, 0600) == -1) {
		ErrorMsg("socket bind error\n");
		perror("socket bind error");
		exit(-1);
	}
	
	if (listen(sockfd, MAX_SOCKET_CLIENT) == -1) {
		ErrorMsg("listen error\n");
		perror("listen error");
		exit(-1);
	}
	
	while (1) {
		if ( (newsockfd = accept(sockfd, NULL, NULL)) == -1) {
			ErrorMsg("accept error\n");
			perror("accept error");
			continue;
		}
		fcntl(newsockfd, F_SETFD, FD_CLOEXEC);
		
		rcv_socket(newsockfd);
		close(newsockfd);
	}
}

static void *request_worker(void *rInfo)
{
	REQUEST_INFO_T *req = rInfo;
	switch (req->type) {
	case REQ_PING_MODE:
		do_ping(req);
		break;
	case REQ_TRACEROUTE_MODE:
		do_traceroute(req);
		break;
	case REQ_PING_NORMAL_MODE:
		do_ping_normal(req);
		break;
	case REQ_TRACEROUTE_NORMAL_MODE:
		do_traceroute_normal(req);
		break;
	case REQ_NSLOOKUP_MODE:
		do_nslookup(req);
		break;
	case REQ_NETSTAT_MODE:
		do_netstat(req);
		break;
	case REQ_NETSTAT_NAT_MODE:
		do_netstat_nat(req);
		break;
	}
	free(req);
	return NULL;
}

static void start_req_thread(void *rInfo, int type)
{
	REQUEST_INFO_T *request = task_listcreate(*(REQUEST_INFO_T *)rInfo);
	if (!request)
		return;
#ifdef NON_P_THREAD
	
	int status;
	pid_t pid, w;
 
	pid = fork();
	
	if (pid == -1) {
		free(request);
		ErrorMsg("fork error\n");
		return;
	}
	if (pid == 0) {
		request_worker(request);
		_exit(0);
	} else {
		free(request);
		w = waitpid(pid, &status, WUNTRACED | WCONTINUED);
		if (w == -1) {
			ErrorMsg("waitpid error\n");
			exit(EXIT_FAILURE);
		}
	}
#else
	pthread_t thread;
	pthread_attr_t attr;
	int ret = 0;
	
	ret = pthread_attr_init(&attr);
	if (ret != 0) {
		free(request);
		return;
	}
	ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if (type == REQ_TRACEROUTE_MODE)
		IN_EXEC = 1;
	if (ret == 0)
		ret = pthread_create(&thread, &attr, request_worker, request);
	
	if (ret != 0) {
		free(request);
		if (type == REQ_TRACEROUTE_MODE)
			IN_EXEC = 0;
		ErrorMsg("Error %d %s\n", ret, strerror(errno))
		perror("Thread create failed\n");
	}
	
	pthread_attr_destroy(&attr);
#endif
}

static void local_socket_thread(void)
{
	pthread_t thread;
	pthread_attr_t attr;
	
	MyDBG("Start unix socket thread.\n");
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	pthread_create(&thread,NULL,(void *)&start_local_socket,NULL);
	pthread_attr_destroy(&attr);
}

#ifndef NON_P_THREAD
static void process_task(void)
{
	REQUEST_INFO_T *req_task;
	struct listnode *ln;
	
	MUTEXLOCK(&task_list_lock);
	LIST_LOOP(task_list,req_task,ln)
	{
		if (!IN_EXEC) {
			start_req_thread((void *)req_task, req_task->type);
			break;
		}
	}
	
	MUTEXUNLOCK(&task_list_lock);
	
}
#endif


static void handlesignal(int signum)
{
	if (signum == SIGUSR1) {
		;
	} else if (signum == SIGUSR2) {
		;
	} else if (signum == SIGTERM) {
		remove("/var/run/netool.pid");
		terminated = 0;
	} else
		MyDBG("Unknown SIGNAL\n");
	
}

static void signal_register(void) {
	
	struct sigaction sa;
	
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler =  &handlesignal;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);    
}

int netool_main (int argc, char *argv[])
{

	char pid[8];
	
	MyDBG("[Start NetTool]\n");
	
	/* Write pid */
	snprintf(pid, sizeof(pid), "%d", getpid());
	f_write_string("/var/run/netool.pid", pid, 0, 0);
	
	/* mkdir */
	mkdir_if_none(NETOOL_RESULT_DIR);
	
	/* Signal */
	signal_register();
	
	/* Init task list info*/
	task_list=list_new();
	
	/* Init mutex lock switch */
	MUTEXINIT(&task_list_lock);
	
	/* start unix socket */
	local_socket_thread();
	
	while(terminated) {
#ifndef NON_P_THREAD
		if (f_exists(NETOOL_QUEUE) > 0) {
			process_task();
		}
#endif
		pause();
	}
	
	/* Free memory */
	MUTEXDESTROY(&task_list_lock);
	
	return 0;
}

