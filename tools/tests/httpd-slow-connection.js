const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.c'), 'utf8');
const mssl = fs.readFileSync(path.join(root, 'release/src/router/mssl/mssl.c'), 'utf8');

assert(source.includes('#define HTTPD_REQUEST_TIMEOUT 3'));
assert(source.includes('#define MAX_CONN_PER_SOURCE 8'));
assert(source.includes('#define HTTPD_SLOW_SOURCE_BLOCK 60'));
assert(source.includes('IN6_IS_ADDR_V4MAPPED'));
assert(source.includes('memcmp(left_address, right_address, address_length)'));
assert(source.includes('entry->blocked_until = now + HTTPD_SLOW_SOURCE_BLOCK;'));
assert.match(source, /if \(request_deadline_active\) \{\s*request_deadline_expired = 1;\s*alarm\(20\);\s*return;/);

const acceptStart = source.indexOf('while ((item->fd = accept(');
const sourceScan = source.indexOf('TAILQ_FOREACH(queued, &pool.head, entry)', acceptStart);
const poolInsert = source.indexOf('TAILQ_INSERT_TAIL(&pool.head, item, entry);', sourceScan);
const acceptGuard = source.slice(acceptStart, poolInsert);
assert(acceptStart >= 0 && sourceScan > acceptStart && poolInsert > sourceScan);
const blockedCheck = source.indexOf('if (httpd_slow_source_blocked(&item->usa))', acceptStart);
assert(blockedCheck > acceptStart && blockedCheck < sourceScan);
assert.match(acceptGuard, /httpd_same_peer\(&queued->usa, &item->usa\).*MAX_CONN_PER_SOURCE/);
assert.match(acceptGuard, /if \(source_count >= MAX_CONN_PER_SOURCE\) \{\s*shutdown\(item->fd, SHUT_RDWR\);\s*close\(item->fd\);\s*free\(item\);\s*continue;/);

const deadlineStart = source.indexOf('httpd_request_deadline_start(void)');
const deadlineEnd = source.indexOf('void httpd_exit', deadlineStart);
const deadlineHelpers = source.slice(deadlineStart, deadlineEnd);
assert(deadlineStart >= 0 && deadlineEnd > deadlineStart);
assert.match(deadlineHelpers, /request_previous_alarm = alarm\(HTTPD_REQUEST_TIMEOUT\);\s*request_deadline_active = 1;/);
assert.match(deadlineHelpers, /if \(!request_deadline_active\)\s*return request_deadline_timed_out;/);
assert.match(deadlineHelpers, /request_deadline_timed_out = expired;/);
assert.match(deadlineHelpers, /if \(expired\) \{\s*httpd_slow_source_block\(&request_peer\);\s*alarm\(20\);\s*\} else \{\s*remaining = alarm\(0\);/);
assert.match(deadlineHelpers, /alarm\(request_previous_alarm - elapsed\);/);

const handlerStart = source.indexOf('handle_request(void)');
const firstRead = source.indexOf('if (fgets(line, sizeof(line), conn_fp)', handlerStart);
const headerRead = source.indexOf('while (!request_deadline_expired && fgets(', firstRead);
const deadlineCheck = source.indexOf('if (httpd_request_deadline_stop())', headerRead);
const slowlorisCheck = source.indexOf('slowloris_check();', deadlineCheck);
assert(handlerStart >= 0 && firstRead > handlerStart);
assert.match(source.slice(firstRead, firstRead + 120), /request_deadline_expired/);
assert(headerRead > firstRead && deadlineCheck > headerRead && slowlorisCheck > deadlineCheck);

const mainStart = source.indexOf('int main(int argc, char **argv)');
const processStart = source.indexOf('httpd_request_deadline_start();', mainStart);
const handshake = source.indexOf('ssl_server_fopen(item->fd)', processStart);
const requestDispatch = source.indexOf('handle_request();', handshake);
const stop = source.indexOf('httpd_request_deadline_stop();', requestDispatch);
assert(processStart > mainStart && handshake > processStart);
assert(blockedCheck < handshake);
const dequeueBlockedCheck = source.indexOf('if (httpd_slow_source_blocked(&item->usa))', blockedCheck + 1);
assert(dequeueBlockedCheck > blockedCheck && dequeueBlockedCheck < handshake);
assert(requestDispatch > handshake && stop > requestDispatch);
assert.match(source.slice(processStart, requestDispatch), /if \(!request_deadline_expired\) \{\s*http_login_cache\(&item->usa\);/);
const timedOutClose = source.indexOf('if (request_timed_out)', requestDispatch);
const shutdown = source.indexOf('shutdown(item->fd, SHUT_RDWR);', timedOutClose);
const streamClose = source.indexOf('fclose(conn_fp);', shutdown);
assert(timedOutClose > requestDispatch && shutdown > timedOutClose && streamClose > shutdown);

const sslError = mssl.indexOf('ERROR:');
const sslErrorClose = mssl.indexOf('mssl_close(kuki);', sslError);
assert(sslError >= 0 && sslErrorClose > sslError);
assert.match(mssl.slice(sslError, sslErrorClose), /if \(!client && kuki->ssl\)\s*SSL_set_quiet_shutdown\(kuki->ssl, 1\);/);

console.log('httpd per-source cap and TLS/header deadline checks passed');