const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'release/src/router/httpd/httpd.c'), 'utf8');
const mssl = fs.readFileSync(path.join(root, 'release/src/router/mssl/mssl.c'), 'utf8');

assert(source.includes('#define HTTPD_REQUEST_TIMEOUT 3'));
assert(source.includes('#define MAX_CONN_PER_SOURCE 8'));
assert(source.includes('#define HTTPD_SLOW_SOURCE_BLOCK 60'));
assert(source.includes('#define HTTPD_BODY_TIMEOUT_GRACE 5'));
assert(source.includes('#define HTTPD_BODY_MIN_RATE 32768'));
assert(source.includes('#define HTTPD_BODY_TIMEOUT_MAX 180'));
assert(source.includes('#define HTTPD_RESPONSE_TIMEOUT_GRACE 5'));
assert(source.includes('#define HTTPD_RESPONSE_MIN_RATE 32768'));
assert(source.includes('#define HTTPD_RESPONSE_TIMEOUT_MAX 180'));
assert(source.includes('IN6_IS_ADDR_V4MAPPED'));
assert(source.includes('memcmp(left_address, right_address, address_length)'));
assert(source.includes('entry->blocked_until = now + HTTPD_SLOW_SOURCE_BLOCK;'));
assert.match(source, /if \(request_deadline_active\) \{\s*request_deadline_expired = 1;\s*if \(request_deadline_fd >= 0\)\s*shutdown\(request_deadline_fd, SHUT_RDWR\);\s*alarm\(20\);\s*return;/);

const acceptStart = source.indexOf('while ((item->fd = accept(');
const sourceScan = source.indexOf('TAILQ_FOREACH(queued, &pool.head, entry)', acceptStart);
const poolInsert = source.indexOf('TAILQ_INSERT_TAIL(&pool.head, item, entry);', sourceScan);
const acceptGuard = source.slice(acceptStart, poolInsert);
assert(acceptStart >= 0 && sourceScan > acceptStart && poolInsert > sourceScan);
const blockedCheck = source.indexOf('if (httpd_slow_source_blocked(&item->usa) ||', acceptStart);
assert(blockedCheck > acceptStart && blockedCheck < sourceScan);
assert.match(acceptGuard, /httpd_same_peer\(&queued->usa, &item->usa\).*MAX_CONN_PER_SOURCE/);
assert.match(acceptGuard, /if \(source_count >= MAX_CONN_PER_SOURCE\) \{\s*shutdown\(item->fd, SHUT_RDWR\);\s*close\(item->fd\);\s*free\(item\);\s*continue;/);

const deadlineStart = source.indexOf('httpd_request_deadline_start(unsigned int timeout, int body_phase, int fd)');
const deadlineEnd = source.indexOf('void httpd_exit', deadlineStart);
const deadlineHelpers = source.slice(deadlineStart, deadlineEnd);
assert(deadlineStart >= 0 && deadlineEnd > deadlineStart);
assert.match(deadlineHelpers, /request_deadline_seconds = timeout;\s*request_deadline_body = body_phase;\s*request_deadline_fd = fd;[\s\S]*request_previous_alarm = alarm\(timeout\);\s*request_deadline_active = 1;/);
assert.match(deadlineHelpers, /request_deadline_active = 0;\s*request_deadline_fd = -1;/);
assert.match(deadlineHelpers, /if \(!request_deadline_active\)\s*return request_deadline_timed_out;/);
assert.match(deadlineHelpers, /request_deadline_timed_out = expired;/);
assert.match(deadlineHelpers, /if \(expired\) \{\s*httpd_slow_source_block\(&request_peer\);\s*if \(!request_headers_complete \|\| request_deadline_body\)\s*httpd_slowloris_record_timeout\(&request_peer\);\s*alarm\(20\);\s*\} else \{\s*remaining = alarm\(0\);/);
assert.match(deadlineHelpers, /elapsed = remaining < request_deadline_seconds \? request_deadline_seconds - remaining : 0;/);
assert.match(deadlineHelpers, /alarm\(request_previous_alarm - elapsed\);/);

const bodyTimeoutStart = source.indexOf('httpd_request_body_timeout(int content_length)');
const bodyTimeoutEnd = source.indexOf('static void\nhandle_request(void)', bodyTimeoutStart);
const bodyTimeout = source.slice(bodyTimeoutStart, bodyTimeoutEnd);
assert(bodyTimeoutStart >= 0 && bodyTimeoutEnd > bodyTimeoutStart);
assert.match(bodyTimeout, /content_length \+ HTTPD_BODY_MIN_RATE - 1\) \/ HTTPD_BODY_MIN_RATE/);
assert.match(bodyTimeout, /if \(timeout > HTTPD_BODY_TIMEOUT_MAX\)\s*timeout = HTTPD_BODY_TIMEOUT_MAX;/);
function calculateBodyTimeout(length) {
    return Math.min(5 + Math.ceil(Math.max(0, length) / 32768), 180);
}
assert.equal(calculateBodyTimeout(65534), 7);
assert.equal(calculateBodyTimeout(64 * 1024 * 1024), 180);
function calculateResponseTimeout(length) {
    return length < 0 ? 180 : Math.min(5 + Math.ceil(length / 32768), 180);
}
assert.equal(calculateResponseTimeout(1428043), 49);
assert.equal(calculateResponseTimeout(64 * 1024 * 1024), 180);
assert.equal(calculateResponseTimeout(-1), 180);

const fileSizeStart = source.indexOf('static int httpd_web_file_size(');
const fileSizeEnd = source.indexOf('#if 0 //defined(GTAX6000)', fileSizeStart);
const fileSizeHelper = source.slice(fileSizeStart, fileSizeEnd);
assert(fileSizeStart >= 0 && fileSizeEnd > fileSizeStart);
assert.match(fileSizeHelper, /fstat\(fd, &st\) < 0 \|\| !S_ISREG\(st.st_mode\)/);
assert.match(fileSizeHelper, /\*size = st.st_size;/);
assert.match(source, /handler->output == do_file && !httpd_web_file_size\(file, &httpd_response_size\)/);
assert.match(source, /HTTPD_RESPONSE_TIMEOUT_GRACE \+\s*\(\(unsigned long\)httpd_response_size \+ HTTPD_RESPONSE_MIN_RATE - 1\) \/\s*HTTPD_RESPONSE_MIN_RATE;\s*if \(timeout > HTTPD_RESPONSE_TIMEOUT_MAX\)\s*timeout = HTTPD_RESPONSE_TIMEOUT_MAX;/);
const responseStart = source.indexOf('httpd_response_deadline_start(void)');
const responseEnd = source.indexOf('static void\nsend_headers(', responseStart);
const responseHelper = source.slice(responseStart, responseEnd);
assert(responseStart >= 0 && responseEnd > responseStart);
assert.match(responseHelper, /clearerr\(conn_fp\);\s*httpd_request_deadline_start\(timeout, 0, fileno\(conn_fp\)\);\s*request_headers_complete = 1;\s*httpd_response_size = -1;/);
assert.match(source, /send_headers\( int status, char\* title, char\* extra_header, char\* mime_type, int fromapp\)\s*\{[\s\S]*?httpd_response_deadline_start\(\);/);
assert.match(source, /send_token_headers\( int status, char\* title, char\* extra_header, char\* mime_type, int fromapp\)\s*\{[\s\S]*?httpd_response_deadline_start\(\);/);
assert.match(source, /errno = 0;\s*fflush\(conn_fp\);\s*if \(ferror\(conn_fp\)\)\s*httpd_slow_source_block\(&request_peer\);\s*request_timed_out = httpd_request_deadline_stop\(\);/);
assert.match(source, /if \(r == 0 && request_deadline_expired\)\s*return -1;/);

const handlerStart = source.indexOf('handle_request(void)');
const firstRead = source.indexOf('if (fgets(line, sizeof(line), conn_fp)', handlerStart);
const headerRead = source.indexOf('while (!request_deadline_expired && fgets(', firstRead);
const deadlineCheck = source.indexOf('if (httpd_request_deadline_stop())', headerRead);
assert(handlerStart >= 0 && firstRead > handlerStart);
assert.match(source.slice(firstRead, firstRead + 120), /request_deadline_expired/);
assert(headerRead > firstRead && deadlineCheck > headerRead);

const mainStart = source.indexOf('int main(int argc, char **argv)');
const processStart = source.indexOf('httpd_request_deadline_start(HTTPD_REQUEST_TIMEOUT, 0, item->fd);', mainStart);
const handshake = source.indexOf('ssl_server_fopen(item->fd)', processStart);
const requestDispatch = source.indexOf('handle_request();', handshake);
const stop = source.indexOf('httpd_request_deadline_stop();', requestDispatch);
assert(processStart > mainStart && handshake > processStart);
assert(blockedCheck < handshake);
const dequeueBlockedCheck = source.indexOf('if (httpd_slow_source_blocked(&item->usa))', blockedCheck + 1);
assert(dequeueBlockedCheck > blockedCheck && dequeueBlockedCheck < handshake);
assert(requestDispatch > handshake && stop > requestDispatch);
assert.match(source.slice(processStart, requestDispatch), /if \(!request_deadline_expired\) \{\s*http_login_cache\(&item->usa\);/);
const inputDispatch = source.indexOf('handler->input(file, conn_fp, cl, boundary);');
const bodyStop = source.indexOf('if (cl > 0 && httpd_request_deadline_stop())', inputDispatch);
assert(inputDispatch > handlerStart && inputDispatch < mainStart && bodyStop > inputDispatch);
assert.match(source.slice(inputDispatch - 120, inputDispatch), /httpd_request_deadline_start\(httpd_request_body_timeout\(cl\), 1, fileno\(conn_fp\)\);/);
assert.match(source.slice(bodyStop, bodyStop + 100), /return;/);
const timedOutClose = source.indexOf('if (request_timed_out)', requestDispatch);
const shutdown = source.indexOf('shutdown(item->fd, SHUT_RDWR);', timedOutClose);
const streamClose = source.indexOf('fclose(conn_fp);', shutdown);
assert(timedOutClose > requestDispatch && shutdown > timedOutClose && streamClose > shutdown);

const sslError = mssl.indexOf('ERROR:');
const sslErrorClose = mssl.indexOf('mssl_close(kuki);', sslError);
assert(sslError >= 0 && sslErrorClose > sslError);
assert.match(mssl.slice(sslError, sslErrorClose), /if \(!client && kuki->ssl\)\s*SSL_set_quiet_shutdown\(kuki->ssl, 1\);/);
const writeStart = mssl.indexOf('static ssize_t mssl_write(');
const writeEnd = mssl.indexOf('static int mssl_seek(', writeStart);
const writeBody = mssl.slice(writeStart, writeEnd);
assert(writeStart >= 0 && writeEnd > writeStart);
assert.match(writeBody, /case SSL_ERROR_WANT_WRITE:\s*case SSL_ERROR_WANT_READ:\s*SSL_set_quiet_shutdown\(kuki->ssl, 1\);\s*errno = EAGAIN;[\s\S]*goto OUT;/);
assert.doesNotMatch(writeBody, /case SSL_ERROR_WANT_WRITE:\s*case SSL_ERROR_WANT_READ:\s*break;/);
assert.match(mssl, /#if defined\(SSL_OP_NO_RENEGOTIATION\)\s*SSL_CTX_set_options\(ctx, SSL_OP_NO_RENEGOTIATION\);\s*#elif OPENSSL_VERSION_NUMBER < 0x10100000L && defined\(SSL3_FLAGS_NO_RENEGOTIATE_CIPHERS\)\s*SSL_CTX_set_info_callback\(ctx, ssl_info_cb\);\s*#else\s*#error "TLS server requires support for disabling renegotiation"/);
assert.doesNotMatch(mssl, /SSL_OP_NO_RENGOTIATION/);

console.log('httpd per-source cap and TLS/header deadline checks passed');