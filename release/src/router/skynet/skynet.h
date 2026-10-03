#ifndef SKYNET_H
#define SKYNET_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define SKYNET_SCHEMA_VERSION 2
#define SKYNET_ENTRY_SIZE 19
#define SKYNET_URL_SIZE 1024
#define SKYNET_DEFAULT_LIMIT 65536
#define SKYNET_MAX_LIMIT 131072
#define SKYNET_DOWNLOAD_LIMIT (8 * 1024 * 1024)

struct sqlite3;
struct skynet {
	struct sqlite3 *database;
	char directory[4096];
	char interface[64];
	char blocked[32];
	char allowed[32];
	unsigned int limit;
	int lock;
	int inbound;
	int outbound;
	int enabled;
	int error;
	int dirty;
	int lock_held;
	int time_ready;
	int64_t now;
};

int skynet_parse_entry(const char *text, char *canonical, size_t size);
int skynet_validate_url(const char *url);
int skynet_parse_limit(const char *text, unsigned int *limit);
int skynet_parse_seconds(const char *text, unsigned int *seconds);
int skynet_emit_set_entry(FILE *stream, const char *name, const char *entry, unsigned int seconds);
int skynet_render_firewall(struct skynet *context, FILE *stream);
int skynet_store_open(struct skynet *context);
void skynet_store_close(struct skynet *context);
int skynet_store_exec(struct skynet *context, const char *sql);
int skynet_store_limit(struct skynet *context);
int skynet_rule(struct skynet *context, const char *action, const char *entry);
int skynet_temporary_ban(struct skynet *context, const char *entry, unsigned int seconds);
int skynet_prune_rules(struct skynet *context);
int skynet_refresh_due(struct skynet *context, unsigned int hours);
int skynet_feed(struct skynet *context, const char *action, const char *url);
int skynet_refresh(struct skynet *context);
int skynet_apply(struct skynet *context);
int skynet_stop(struct skynet *context);
int skynet_status(struct skynet *context, int output);
int skynet_storage(struct skynet *context, const char *mountpoint);
int skynet_swap_ready(void);
int skynet_lock(struct skynet *context);
int skynet_cancelled(void);
int skynet_stopping(void);
int skynet_watch(void);

#endif