/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2022 David Woodhouse <dwmw2@infradead.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#include <config.h>

#include "openconnect-internal.h"

#ifndef HAVE_HPKE_SUPPORT
int handle_external_browser(struct openconnect_info *vpninfo)
{
	return -EINVAL;
}
#else

#include <ctype.h>

#define HPKE_TAG_PUBKEY		1
#define HPKE_TAG_AEAD_TAG	2
#define HPKE_TAG_CIPHERTEXT	3
#define HPKE_TAG_IV		4
/*
 * Hard-coded HTTP responses
 */
static const char response_404[] =
	"HTTP/1.1 404 Not Found\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"Content-Length: 0\r\n\r\n";

static const char response_302[] =
	"HTTP/1.1 302 Found\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"Content-Length: 0\r\n"
	"Location: %s\r\n\r\n";

static const char response_200[] =
	"HTTP/1.1 200 OK\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n\r\n"
	"<html><title>Success</title><body>Success</body></html>\r\n";

#ifdef HAVE_POSIX_SPAWN
static int spawn_browser(struct openconnect_info *vpninfo)
{
	vpn_progress(vpninfo, PRG_TRACE, _("Spawning external browser '%s'\n"),
		     vpninfo->external_browser);

	int ret = 0;
	pid_t pid = 0;
	char *browser_argv[3] = { (char *)vpninfo->external_browser, vpninfo->sso_login, NULL };
	posix_spawn_file_actions_t file_actions, *factp = NULL;

	if (!posix_spawn_file_actions_init(&file_actions)) {
		factp = &file_actions;
		posix_spawn_file_actions_adddup2(&file_actions, STDERR_FILENO, STDOUT_FILENO);
	}

	if (posix_spawn(&pid, vpninfo->external_browser, factp, NULL, browser_argv, environ)) {
		ret = -errno;
		vpn_perror(vpninfo, _("Spawn browser"));
	}
	if (factp)
		posix_spawn_file_actions_destroy(factp);

	return ret;
}
#elif defined(_WIN32)
static int spawn_browser(struct openconnect_info *vpninfo)
{
	HINSTANCE rv;
	char *errstr;

	vpn_progress(vpninfo, PRG_TRACE, _("Spawning external browser '%s'\n"),
		     vpninfo->external_browser);

	rv = ShellExecute(NULL, vpninfo->external_browser, vpninfo->sso_login,
			  NULL, NULL, SW_SHOWNORMAL);

	if ((intptr_t)rv > 32)
		return 0;

	errstr = openconnect__win32_strerror(GetLastError());
	vpn_progress(vpninfo, PRG_ERR, "Failed to spawn browser: %s\n",
		     errstr);
	free(errstr);
	return -EIO;
}
#endif

/*
 * If we use an external browser where we can't just snoop for cookies
 * or completion... how do we get the results back? Cisco's answer:
 * We run an HTTP server on http://localhost:29786/ and listen for
 * a GET request to /api/sso/<base64 blob>?return=<finalurl>. It
 * returns a redirect to that final URL, which is a pretty 'success'
 * page. And decodes the base64 blob to obtain the SSO token, qv.
 */
int handle_external_browser(struct openconnect_info *vpninfo)
{
	int ret = 0;
	struct sockaddr_in6 sin6 = { };
	sin6.sin6_family = AF_INET6;
	sin6.sin6_port = htons(29786);
	sin6.sin6_addr = in6addr_loopback;

	int listen_fd;
#ifdef SOCK_CLOEXEC
	listen_fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
	if (listen_fd < 0)
#endif
	listen_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (listen_fd < 0) {
		char *errstr;
	sockerr:
#ifdef _WIN32
		errstr = openconnect__win32_strerror(WSAGetLastError());
#else
		errstr = strerror(errno);
#endif

		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to listen on local port 29786: %s\n"),
			     errstr);
#ifdef _WIN32
		free(errstr);
#endif
		if (listen_fd >= 0)
			closesocket(listen_fd);
		return -EIO;
	}

	int optval = 1;
	(void)setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval, sizeof(optval));

	if (bind(listen_fd, (void *)&sin6, sizeof(sin6)) < 0)
		goto sockerr;

	if (listen(listen_fd, 1))
		goto sockerr;

	if (set_sock_nonblock(listen_fd))
		goto sockerr;

	/* Now that we are listening on the socket, we can spawn the browser */
	if (vpninfo->open_ext_browser) {
		ret = vpninfo->open_ext_browser(vpninfo, vpninfo->sso_login, vpninfo->cbdata);
#if defined(HAVE_POSIX_SPAWN) || defined(_WIN32)
	} else if (vpninfo->external_browser) {
		ret = spawn_browser(vpninfo);
#endif
	} else {
		ret = -EINVAL;
	}
	if (ret)
		vpn_progress(vpninfo, PRG_ERR,
			     _("Failed to spawn external browser for %s\n"),
			     vpninfo->sso_login);

	char *returl = NULL;
	struct oc_text_buf *b64_buf = NULL;

	/* There may be other stray connections. Repeat until we have one
	 * that looks like the actual auth attempt from the browser. */
	while (1) {
		int accept_fd = cancellable_accept(vpninfo, listen_fd);
		if (accept_fd < 0) {
			ret = accept_fd;
			goto out;
		}
		vpn_progress(vpninfo, PRG_TRACE,
			     _("Accepted incoming external-browser connection on port 29786\n"));

		char line[4096];
		ret = cancellable_gets(vpninfo, accept_fd, line, sizeof(line));
		if (ret < 15 || strncmp(line, "GET /", 5) ||
		    strncmp(line + ret - 9, " HTTP/1.", 8)) {
			vpn_progress(vpninfo, PRG_TRACE,
				     _("Invalid incoming external-browser request\n"));
			closesocket(accept_fd);
			continue;
		}
		if (strncmp(line, "GET /api/sso/", 13)) {
		give_404:
			cancellable_send(vpninfo, accept_fd, response_404, sizeof(response_404) - 1);
			closesocket(accept_fd);
			continue;
		}

		/*
		 * OK, now we have a "GET /api/sso/… HTTP/1.x" that looks sane.
		 * Kill the " HTTP/1.x" at the end.
		 * */
		line[ret - 9] = 0;

		/* Scan for ?return= (and other params that shouldn't be there) */
		char *b64 = line + 13;
		char *q = strchr(b64, '?');
		while (q) {
			*q = 0;
			q++;
			if (!strncmp(q, "return=", 7))
				returl = q + 7;
			q = strchr(q, '&');
		}

		/* Attempt to decode the base64 */
		urldecode_inplace(b64);
		b64_buf = buf_alloc();
		if (!b64_buf) {
			ret = -ENOMEM;
			closesocket(accept_fd);
			goto out;
		}

		b64_buf->data = openconnect_base64_decode(&ret, b64);
		if (ret < 0) {
			/* If the final part of the URL after /api/sso/ is not
			 * valid base64, give a 404 and wait for a valid req. */
			buf_free(b64_buf);
			b64_buf = NULL;
			goto give_404;
		}
		b64_buf->pos = b64_buf->buf_len = ret;

		/* Decode and store the returl (since we'll reuse the line buf) */
		if (returl) {
			urldecode_inplace(returl);
			returl = strdup(returl);
		}

		/* Now consume the rest of the HTTP request lines */
		while (cancellable_gets(vpninfo, accept_fd, line, sizeof(line)) > 0) {
			vpn_progress(vpninfo, PRG_DEBUG,
				     "< %s\n", line);
		}

		/* Finally, send the response to redirect to the success page */
		if (returl) {
			line[sizeof(line) - 1] = 0;
			ret = snprintf(line, sizeof(line) - 1, response_302, returl);
			ret = cancellable_send(vpninfo, accept_fd, line, ret);
			free(returl);
			returl = NULL;
		} else {
			ret = cancellable_send(vpninfo, accept_fd, response_200, sizeof(response_200) - 1);
		}
		closesocket(accept_fd);
		if (ret < 0)
			goto out_b64;

		break;
	}

	vpn_progress(vpninfo, PRG_DEBUG, _("Got encrypted SSO token of %d bytes\n"),
		     b64_buf->pos);

	/* Example encrypted token:
	   < 0000:  00 01 00 01 00 5b 30 59  30 13 06 07 2a 86 48 ce  |.....[0Y0...*.H.|
	   < 0010:  3d 02 01 06 08 2a 86 48  ce 3d 03 01 07 03 42 00  |=....*.H.=....B.|
	   < 0020:  04 fa 42 63 40 b6 f4 a6  02 9a dd 57 f5 8c 74 3e  |..Bc@......W..t>|
	   < 0030:  11 82 18 8d 78 c4 b5 13  d0 c7 c0 d7 f9 79 6c 16  |....x........yl.|
	   < 0040:  e9 bc 30 fa f0 ea 09 8d  17 d1 84 e4 08 55 31 28  |..0..........U1(|
	   < 0050:  a6 62 e4 6d c5 7c be 19  d9 14 41 37 20 6e 4c ce  |.b.m.|....A7 nL.|
	   < 0060:  2c 00 02 00 0c ac 81 ce  79 56 6e 4c 00 cc 9b e3  |,.......yVnL....|
	   < 0070:  d0 00 03 00 17 bb 4d 2e  57 61 c0 90 58 86 86 79  |......M.Wa..X..y|
	   < 0080:  64 05 28 0c c9 f2 c8 c2  2a 2e fb 5c 00 04 00 0c  |d.(.....*..\....|
	   < 0090:  2c 03 5f 13 3c b7 27 7e  36 fe 5a b8              |,._.<.'~6.Z.|

	   This contains the server's DH pubkey (type 1) at 0x0008,
	   the AEAD tag (type 2) at 0x0065, the ciphertext (type 3) at 0x0075
	   and the IV (type 4) at 0x0090.
	*/

	/* tagdata[0] is unused because I can't be doing with all that
	 * (HPKE_TAG_IV-1) nonsense. */
	struct {
		void *p;
		int len;
	} tagdata[HPKE_TAG_IV + 1];

	memset(tagdata, 0, sizeof(tagdata));

	int pos = 0;
	ret = 0;
	while (pos < b64_buf->buf_len) {
		uint16_t tag, len;
		if (pos + 4 > b64_buf->pos) {
			ret = -EINVAL;
			break;
		}

		tag = load_be16(b64_buf->data + pos);
		len = load_be16(b64_buf->data + pos + 2);

		/* Special case, first word must be 0x0001 before the TLVs start */
		if (!pos) {
			if (tag != 0x0001) {
				ret = -EINVAL;
				break;
			}
			pos += 2;
			continue;
		}

		if (tag < HPKE_TAG_PUBKEY || tag > HPKE_TAG_IV ||
		    tagdata[tag].p || pos + 4 + len > b64_buf->pos) {
			ret = -EINVAL;
			break;
		}

		tagdata[tag].p = b64_buf->data + pos + 4;
		tagdata[tag].len = len;
		pos += len + 4;
	}

	if (!tagdata[HPKE_TAG_PUBKEY].p || !tagdata[HPKE_TAG_CIPHERTEXT].p ||
	    !tagdata[HPKE_TAG_AEAD_TAG].p || tagdata[HPKE_TAG_AEAD_TAG].len != 12 ||
	    !tagdata[HPKE_TAG_IV].p || tagdata[HPKE_TAG_IV].len != 12)
		ret = -EINVAL;

	if (ret) {
		vpn_progress(vpninfo, PRG_ERR, _("Failed to decode SSO token at %d:\n"),
			     pos);
		dump_buf_hex(vpninfo, PRG_ERR, '<', (void *)b64_buf->data, b64_buf->pos);
		goto out_b64;
	}

	unsigned char secret[32];
	ret = ecdh_compute_secp256r1(vpninfo, tagdata[HPKE_TAG_PUBKEY].p,
				     tagdata[HPKE_TAG_PUBKEY].len, secret);
	if (ret)
		goto out_b64;

	const unsigned char info[] = "AC_ECIES";
	ret = hkdf_sha256_extract_expand(vpninfo, secret, info, 8);
	if (ret)
		goto out_b64;

	unsigned char *token = tagdata[HPKE_TAG_CIPHERTEXT].p;
	int token_len = tagdata[HPKE_TAG_CIPHERTEXT].len;
	ret = aes_256_gcm_decrypt(vpninfo, secret, token, token_len,
				  tagdata[HPKE_TAG_IV].p, tagdata[HPKE_TAG_AEAD_TAG].p);
	if (ret)
		goto out_b64;

	int i;
	for (i = 0; i < token_len; i++) {
		if (!isalnum(token[i])) {
			vpn_progress(vpninfo, PRG_ERR,
				     _("SSO token not alphanumeric\n"));
			ret = -EINVAL;
			goto out_b64;
		}
	}

	vpninfo->sso_cookie_value = strndup((char *)token, token_len);
	if (!vpninfo->sso_cookie_value)
		ret = -ENOMEM;

 out_b64:
	buf_free(b64_buf);
 out:
	closesocket(listen_fd);
	return ret;
}
#endif /* HAVE_HPKE_SUPPORT */
