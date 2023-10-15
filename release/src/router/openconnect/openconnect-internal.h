/*
 * OpenConnect (SSL + DTLS) VPN client
 *
 * Copyright © 2008-2015 Intel Corporation.
 * Copyright © 2008 Nick Andrew <nick@nick-andrew.net>
 * Copyright © 2013 John Morrissey <jwm@horde.net>
 *
 * Author: David Woodhouse <dwmw2@infradead.org>
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

#ifndef __OPENCONNECT_INTERNAL_H__
#define __OPENCONNECT_INTERNAL_H__

#define __OPENCONNECT_PRIVATE__

/*
 * We need to include <winsock2.h> or <winsock.h> before openconnect.h.
 * Indeed openconnect.h is specifically intended not to be self-sufficient,
 * so that end-users can choose between <winsock.h> and <winsock2.h>.
 */
#ifdef _WIN32
#include <winsock2.h>
#endif

#include "openconnect.h"

#include "json.h"

#if defined(OPENCONNECT_OPENSSL)
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#if defined(OPENCONNECT_GNUTLS)
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/x509.h>
#include <gnutls/crypto.h>
#endif

#ifdef HAVE_ICONV
#include <langinfo.h>
#include <iconv.h>
#endif

#ifdef LIBPROXY_HDR
#include LIBPROXY_HDR
#endif

#ifdef HAVE_LIBSTOKEN
#include <stoken.h>
#endif

#ifdef HAVE_GSSAPI
#include GSSAPI_HDR
#endif

#ifdef HAVE_LIBPSKC
#include <pskc/pskc.h>
#endif

#ifdef HAVE_LIBP11
#include <libp11.h>
#endif

#ifdef HAVE_EPOLL
#include <sys/epoll.h>
#endif

#ifdef ENABLE_NLS
#include <libintl.h>
#define _(s) dgettext("openconnect", s)
#else
#define _(s) ((char *)(s))
#endif
#define N_(s) s

#include <libxml/tree.h>
#include <zlib.h>

#ifdef _WIN32
#ifndef _Out_cap_c_
#define _Out_cap_c_(sz)
#endif
#ifndef _Ret_bytecount_
#define _Ret_bytecount_(sz)
#endif
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunknown-pragmas"
#include "wintun.h"
#pragma GCC diagnostic pop

#include <ws2tcpip.h>
#ifndef SECURITY_WIN32
#define SECURITY_WIN32 1
#endif
#include <security.h>
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#endif

#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>

#include <stdint.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_POSIX_SPAWN
#if defined(__APPLE__)
#include <crt_externs.h>
#define environ (*_NSGetEnviron())
#else
/*
 * POSIX.1-2017 says that environ must be declared by the user if it is to be used directly:
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/exec.html
 */
extern char **environ;
#endif
#include <spawn.h>
#endif

/* Equivalent of "/dev/null" on Windows.
 * See https://stackoverflow.com/a/44163934
 */
#ifdef _WIN32
#define DEVNULL "NUL:"
#else
#define DEVNULL "/dev/null"
#endif

#define SHA512_SIZE 64
#define SHA384_SIZE 48
#define SHA256_SIZE 32
#define SHA1_SIZE 20
#define MD5_SIZE 16

/* FreeBSD provides this in <sys/param.h>  */
#ifndef MAX
#define MAX(x,y) (((x)>(y))?(x):(y))
#endif
#ifndef MIN
#define MIN(x,y) (((x)<(y))?(x):(y))
#endif

/* At least MinGW headers seem not to provide IPPROTO_IPIP */
#ifndef IPPROTO_IPIP
#define IPPROTO_IPIP 0x04
#endif

#ifdef HAVE_VHOST
#include <linux/virtio_net.h>
#include <linux/vhost.h>

struct oc_vring {
	struct vring_desc *desc;
	struct vring_avail *avail;
	struct vring_used *used;
	uint16_t seen_used;
};

#endif

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))


/****************************************************************************/

struct pkt {
	int alloc_len;
	int len;
	struct pkt *next;
	union {
		struct {
			uint32_t spi;
			uint32_t seq;
			unsigned char iv[16];
		} esp;
		struct {
			unsigned char pad[2];
			unsigned char rec[2];
			unsigned char kmp[20];
		} oncp;
		struct {
			unsigned char pad[16];
			unsigned char hdr[8];
		} cstp;
		struct {
			unsigned char pad[8];
			unsigned char hdr[16];
		} gpst;
		struct {
			unsigned char pad[8];
			uint32_t vendor;
			uint32_t type;
			uint32_t len;
			uint32_t ident;
		} pulse;
		struct {
			uint32_t hlen; /* variable-length */
			uint16_t proto;
			unsigned char hdr[18];
		} ppp;
#ifdef HAVE_VHOST
		struct {
			unsigned char pad[12];
			struct virtio_net_hdr_mrg_rxbuf h;
		} virtio;
#endif
	};
	unsigned char data[];
};

#define pkt_offset(field) ((intptr_t)&((struct pkt *)NULL)->field)
#define pkt_from_hdr(addr, field) ((struct pkt *) ((intptr_t)(addr) - pkt_offset(field) ))

#define REKEY_NONE      0
#define REKEY_TUNNEL    1
#define REKEY_SSL       2

#define KA_NONE		0
#define KA_DPD		1
#define KA_DPD_DEAD	2
#define KA_KEEPALIVE	3
#define KA_REKEY	4

#define DTLS_NOSECRET	0	/* Random secret has not been generated yet */
#define DTLS_SECRET	1	/* Secret is present, ready to attempt DTLS */
#define DTLS_DISABLED	2	/* DTLS was disabled on the *client* side */
#define DTLS_SLEEPING	3	/* For ESP, sometimes sending probes */
#define DTLS_CONNECTING	4	/* DTLS (re)handshaking. Not used for ESP */
#define DTLS_CONNECTED	5	/* Transport connected but not yet enabled */
#define DTLS_ESTABLISHED 6	/* Data path fully established */

/* Not to be confused with MULTICERT_PROTO_xxx flags which are library-visible */
#define PROTO_ANYCONNECT	0
#define PROTO_NC		1
#define PROTO_GPST		2
#define PROTO_PULSE		3
#define PROTO_F5		4
#define PROTO_FORTINET		5
#define PROTO_NULLPPP		6
#define PROTO_ARRAY		7

/* All supported PPP packet framings/encapsulations */
#define PPP_ENCAP_RFC1661	1	/* Plain/synchronous/pre-framed PPP (RFC1661) */
#define PPP_ENCAP_RFC1662_HDLC	2	/* PPP with HDLC-like framing (RFC1662) */
#define PPP_ENCAP_F5		3	/* F5 BigIP no HDLC */
#define PPP_ENCAP_F5_HDLC	4	/* F5 BigIP HDLC */
#define PPP_ENCAP_FORTINET	5	/* Fortinet no HDLC */
#define PPP_ENCAP_MAX		PPP_ENCAP_FORTINET

#define COMPR_DEFLATE	(1<<0)
#define COMPR_LZS	(1<<1)
#define COMPR_LZ4	(1<<2)
#define COMPR_LZO	(1<<3)
#define COMPR_MAX	COMPR_LZO

#ifdef HAVE_LZ4
#define COMPR_STATELESS	(COMPR_LZS | COMPR_LZ4 | COMPR_LZO)
#else
#define COMPR_STATELESS	(COMPR_LZS)
#endif
#define COMPR_ALL	(COMPR_STATELESS | COMPR_DEFLATE)

#define DTLS_APP_ID_EXT 48018

struct keepalive_info {
	int dpd;
	int keepalive;
	int rekey;
	int rekey_method;
	time_t last_rekey;
	time_t last_tx;
	time_t last_rx;
	time_t last_dpd;
};

struct pin_cache {
	struct pin_cache *next;
	char *token;
	char *pin;
};

struct oc_text_buf {
	char *data;
	int pos;
	int buf_len;
	int error;
};

#define TLS_MASTER_KEY_SIZE 48

#define RECONNECT_INTERVAL_MIN	10
#define RECONNECT_INTERVAL_MAX	100

#define HTTP_NO_FLAGS		0
#define HTTP_REDIRECT		1
#define HTTP_REDIRECT_TO_GET	2
#define HTTP_BODY_ON_ERROR	4

#define REDIR_TYPE_NONE		0
#define REDIR_TYPE_NEWHOST	1
#define REDIR_TYPE_LOCAL	2

#define AUTH_TYPE_GSSAPI	0
#define AUTH_TYPE_NTLM		1
#define AUTH_TYPE_DIGEST	2
#define AUTH_TYPE_BASIC		3
#define AUTH_TYPE_BEARER	4

#define MAX_AUTH_TYPES		5

#define AUTH_DEFAULT_DISABLED	-3
#define AUTH_DISABLED		-2
#define AUTH_FAILED		-1	/* Failed */
#define AUTH_UNSEEN		0	/* Server has not offered it */
#define AUTH_AVAILABLE		1	/* Server has offered it, we have not tried it */
	/* Individual auth types may use 2 onwards for their own state */
#define AUTH_IN_PROGRESS	2	/* In-progress attempt */

struct http_auth_state {
	int state;
	char *challenge;
	union {
#ifdef HAVE_GSSAPI
		struct {
			gss_name_t gss_target_name;
			gss_ctx_id_t gss_context;
		};
#endif
#ifdef _WIN32
		struct {
			CredHandle ntlm_sspi_cred;
			CtxtHandle ntlm_sspi_ctx;
		};
		struct {
			CredHandle sspi_cred;
			CtxtHandle sspi_ctx;
			SEC_WCHAR *sspi_target_name;
		};
#else
		struct {
			int ntlm_helper_fd;
		};
#endif
	};
};

#define TLS_OVERHEAD 5 /* packet + header */
#define DTLS_OVERHEAD (1 /* packet + header */ + 13 /* DTLS header */ + \
	 20 /* biggest supported MAC (SHA1) */ +  32 /* biggest supported IV (AES-256) */ + \
	 16 /* max padding */)

struct esp {
#if defined(OPENCONNECT_GNUTLS)
	gnutls_cipher_hd_t cipher;
	gnutls_hmac_hd_t hmac;
#elif defined(OPENCONNECT_OPENSSL)
	HMAC_CTX *hmac;
	EVP_CIPHER_CTX *cipher;
#endif
	uint64_t seq_backlog;
	uint64_t seq;
	uint32_t spi; /* Stored network-endian */
	unsigned char enc_key[0x40]; /* Encryption key */
	unsigned char hmac_key[0x40]; /* HMAC key */
	unsigned char iv[16];
};

struct oc_pcsc_ctx;
struct oc_tpm1_ctx;
struct oc_tpm2_ctx;

struct openconnect_info;

struct cert_info {
	struct openconnect_info *vpninfo;
	char *cert;
	char *key;
	char *password;

	void *priv_info;
#if defined(OPENCONNECT_GNUTLS) && defined(HAVE_TROUSERS)
	struct oc_tpm1_ctx *tpm1;
#endif
#if defined(OPENCONNECT_GNUTLS) && defined (HAVE_TSS2)
	struct oc_tpm2_ctx *tpm2;
#endif
};

struct pkt_q {
	struct pkt *head;
	struct pkt **tail;
	int count;
};

struct vpn_proto;

struct openconnect_info {
	const struct vpn_proto *proto;

#ifdef HAVE_ICONV
	iconv_t ic_legacy_to_utf8;
	iconv_t ic_utf8_to_legacy;
#endif
	char *redirect_url;
	int redirect_type;

	unsigned char esp_hmac;
	unsigned char esp_enc;
	unsigned char esp_compr;
	uint32_t esp_replay_protect;
	uint32_t esp_lifetime_bytes;
	uint32_t esp_lifetime_seconds;
	uint32_t esp_ssl_fallback;
	int current_esp_in;
	int old_esp_maxseq;
	struct esp esp_in[2];
	struct esp esp_out;
	int enc_key_len;
	int hmac_key_len;
	int hmac_out_len;

	int esp_magic_af;
	unsigned char esp_magic[16]; /* GlobalProtect magic ping address (network-endian) */

	int pulse_esp_unstupid;      /* See pulse.c and esp.c for the stupid protocol-layering malpractice
				      * that Pulse requires, unless this flag is set by the server. */

	struct oc_ppp *ppp;
	struct oc_text_buf *ppp_tls_connect_req;
	struct oc_text_buf *ppp_dtls_connect_req;

	int tncc_fd; /* For Juniper TNCC */
	char *platname;
	char *mobile_platform_version;
	char *mobile_device_type;
	char *mobile_device_uniqueid;
	char *csd_token;
	char *csd_ticket;
	char *csd_stuburl;
	char *csd_starturl;
	char *csd_waiturl;
	char *csd_preurl;

	char *csd_scriptname;
	xmlNode *opaque_srvdata;

	char *profile_url;
	char *profile_sha1;

#ifdef LIBPROXY_HDR
	pxProxyFactory *proxy_factory;
#endif
	char *proxy_type;
	char *proxy;
	int proxy_port;
	int proxy_fd;
	char *proxy_user;
	char *proxy_pass;
	char *bearer_token;
	int proxy_close_during_auth;
	int retry_on_auth_fail;
	int try_http_auth;
	struct http_auth_state http_auth[MAX_AUTH_TYPES];
	struct http_auth_state proxy_auth[MAX_AUTH_TYPES];
	int no_external_auth;
	const char *external_browser;

	char *localname;

	char *hostname; /* This is the original hostname (or IP address)
			 * we were asked to connect to */

	char *unique_hostname; /* This is the IP address of the actual host
				* that we connected to; the result of the
				* DNS lookup. We do this so that we can be
				* sure we reconnect to the same server we
				* authenticated to. */

	int port;
	char *urlpath;

	char *sni; /* This is the hostname that we present as the TLS
		    * Server Name Indication, unencrypted in the TLS handshake,
		    * in place of the true/original hostname. This is useful
		    * for Domain Fronting, by which some filtered or censored
		    * Internet connections can be bypassed.
		    */

	/* The application might ask us to recreate a connection URL,
	 * and we own the string so cache it for later freeing. */
	struct oc_text_buf *connect_urlbuf;

	int cert_expire_warning;

	struct cert_info certinfo[2];

	char *cafile;
	unsigned no_system_trust;
	const char *xmlconfig;
	char xmlsha1[(SHA1_SIZE * 2) + 1];
	char *authgroup;
	int nopasswd;
	int xmlpost;
	char *dtls_ciphers;
	char *dtls12_ciphers;
	char *csd_wrapper;
	int trojan_interval;
	time_t last_trojan;
	int no_http_keepalive;
	int dump_http_traffic;

	int token_mode;
	int token_bypassed;
	int token_tries;
	time_t token_time;
#ifdef HAVE_LIBSTOKEN
	struct stoken_ctx *stoken_ctx;
	char *stoken_pin;
	int stoken_concat_pin;
	int stoken_interval;
#endif
#ifdef HAVE_LIBPSKC
	pskc_t *pskc;
	pskc_key_t *pskc_key;
#endif
	char *oath_secret;
	size_t oath_secret_len;
	enum {
		OATH_ALG_HMAC_SHA1 = 0,
		OATH_ALG_HMAC_SHA256,
		OATH_ALG_HMAC_SHA512,
	} oath_hmac_alg;
	enum {
		HOTP_SECRET_BASE32 = 1,
		HOTP_SECRET_RAW,
		HOTP_SECRET_HEX,
		HOTP_SECRET_PSKC,
	} hotp_secret_format; /* We need to give it back in the same form */

#ifdef HAVE_LIBPCSCLITE
	struct oc_pcsc_ctx *pcsc;
	unsigned char yubikey_pwhash[16];
#endif
	openconnect_lock_token_vfn lock_token;
	openconnect_unlock_token_vfn unlock_token;
	void *tok_cbdata;

	void *peer_cert;
	/* The SHA1 and SHA256 hashes of the peer's public key */
	uint8_t peer_cert_sha1_raw[SHA1_SIZE];
	uint8_t peer_cert_sha256_raw[SHA256_SIZE];
	/* this value is cache for openconnect_get_peer_cert_hash */
	char *peer_cert_hash;
	void *cert_list_handle;
	int cert_list_size;

	char *cookie; /* Pointer to within cookies list */
	struct oc_vpn_option *cookies;
	struct oc_vpn_option *cstp_options;
	struct oc_vpn_option *dtls_options;

	struct oc_vpn_option *script_env;
	struct oc_vpn_option *csd_env;

	unsigned pfs;
	unsigned no_tls13;
	unsigned allow_insecure_crypto;        /* Allow 3DES and RC4 (known-insecure, but the best that some ancient servers can do) */
#if defined(OPENCONNECT_OPENSSL)
#ifdef HAVE_LIBP11
	PKCS11_CTX *pkcs11_ctx;
	PKCS11_SLOT *pkcs11_slot_list;
	unsigned int pkcs11_slot_count;
	PKCS11_SLOT *pkcs11_cert_slot;
	unsigned char *pkcs11_cert_id;
	size_t pkcs11_cert_id_len;
 #endif
	X509 *cert_x509;
	SSL_CTX *https_ctx;
	SSL *https_ssl;
	BIO_METHOD *ttls_bio_meth;
	EC_KEY *strap_key;
	EC_KEY *strap_dh_key;
#elif defined(OPENCONNECT_GNUTLS)
	gnutls_session_t https_sess;
	gnutls_session_t eap_ttls_sess;
	gnutls_certificate_credentials_t https_cred;
	gnutls_psk_client_credentials_t psk_cred;
	char local_cert_md5[MD5_SIZE * 2 + 1]; /* For CSD */
	gnutls_privkey_t strap_key;
	gnutls_privkey_t strap_dh_key;
	unsigned char finished[64];
	int finished_len;
#endif /* OPENCONNECT_GNUTLS */
	char *strap_pubkey;
	char *strap_dh_pubkey;
	char *ciphersuite_config;
	struct oc_text_buf *ttls_pushbuf;
	uint8_t ttls_eap_ident;
	unsigned char *ttls_recvbuf;
	int ttls_recvpos;
	int ttls_recvlen;
	uint32_t ttls_msgleft;

	struct pin_cache *pin_cache;
	struct keepalive_info ssl_times;
	int owe_ssl_dpd_response;

	int deflate_pkt_size;			/* It may need to be larger than MTU */
	struct pkt *deflate_pkt;		/* For compressing outbound packets into */
	struct pkt *pending_deflated_pkt;	/* The original packet associated with above */
	struct pkt *current_ssl_pkt;		/* Partially sent SSL packet */
	int partial_rec_size;			/* For tracking partially-received packets */
	/* Packet buffers for receiving into */
	struct pkt *cstp_pkt;
	struct pkt *dtls_pkt;
	struct pkt *tun_pkt;
	int pkt_trailer; /* How many bytes after payload for encryption (ESP HMAC) */

	z_stream inflate_strm;
	uint32_t inflate_adler32;
	z_stream deflate_strm;
	uint32_t deflate_adler32;

	int disable_ipv6;
	int reconnect_timeout;
	int reconnect_interval;
	int dtls_attempt_period;
	int udp_probes_sent;
	time_t auth_expiration;
	time_t new_dtls_started;
#if defined(OPENCONNECT_OPENSSL)
	SSL_CTX *dtls_ctx;
	SSL *dtls_ssl;
#elif defined(OPENCONNECT_GNUTLS)
	/* Call this dtls_ssl rather than dtls_sess because it's just a
	   pointer, and generic code in dtls.c wants to check if it's
	   NULL or not or pass it to DTLS_SEND/DTLS_RECV. This way we
	   have fewer ifdefs and accessor macros for it. */
	gnutls_session_t dtls_ssl;
#endif
	char *cstp_cipher; /* library-dependent description of TLS cipher */
	char *dtls_cipher_desc; /* library-dependent description of DTLS cipher, cached for openconnect_get_dtls_cipher() */

	int dtls_state;
	int dtls_need_reconnect;

	int tcp_blocked_for_udp; /* Some protocols explicitly *tell* the server
				  * over the TCP channel to switch to UDP. */

	struct keepalive_info dtls_times;
	unsigned char dtls_session_id[32];
	unsigned char dtls_secret[TLS_MASTER_KEY_SIZE];
	unsigned char dtls_app_id[32];
	unsigned dtls_app_id_size;

	uint32_t ift_seq;

	int dtls12; /* For PPP protocols with anonymous DTLS, this being zero indicates that
		     * the server *cannot* handle DTLSv1.2 and we mustn't even try to negotiate
		     * it (e.g. F5 BIG-IP v15 and lower). If it's 1, we can try anything;
		     * even DTLSv1.3.
		     *
		     * For AnyConnect, it means the Cisco server sent the X-DTLS12-CipherSuite
		     * header, rather than X-DTLS-CipherSuite which indicates their DTLSv0.9.
		     */

	char *dtls_cipher; /* Only set for AnyConnect. Defines the session to be "resumed"
			    * ("PSK-NEGOTIATE", or an OpenSSL cipher name). */

	char *vpnc_script;
#ifndef _WIN32
	int uid_csd_given;
	uid_t uid_csd;
	gid_t gid_csd;
	uid_t uid;
	gid_t gid;
#endif
	int use_tun_script;
	int script_tun;
	char *ifname;
	char *cmd_ifname;

	int reqmtu, basemtu; /* Local static configured values */
	const char *banner;

	struct oc_ip_info ip_info;
	int cstp_basemtu; /* Returned by server */
	int idle_timeout; /* Returned by server */

#ifdef _WIN32
	long dtls_monitored, ssl_monitored, cmd_monitored, tun_monitored;
	HANDLE dtls_event, ssl_event, cmd_event;
#else
	int _select_nfds;
	fd_set _select_rfds;
	fd_set _select_wfds;
	fd_set _select_efds;
#ifdef HAVE_EPOLL
	int epoll_fd;
	int epoll_update;
	uint32_t tun_epoll, ssl_epoll, dtls_epoll, cmd_epoll;
#ifdef HAVE_VHOST
	uint32_t vhost_call_epoll;
#endif
#endif
#endif

#ifdef __sun__
	int ip_fd;
	int ip6_fd;
#endif
#ifdef HAVE_VHOST
	int vhost_ring_size;
	int vhost_fd, vhost_call_fd, vhost_kick_fd;
	struct oc_vring tx_vring, rx_vring;
	#endif
#ifdef _WIN32
	HMODULE wintun;
	wchar_t *ifname_w;
	WINTUN_ADAPTER_HANDLE wintun_adapter;
	WINTUN_SESSION_HANDLE wintun_session;

	HANDLE tun_fh;
	OVERLAPPED tun_rd_overlap, tun_wr_overlap;
	int tun_idx, tun_rd_pending;
#else
	int tun_fd;
#endif
	int ssl_fd;
	int dtls_fd;

	int dtls_tos_current;
	int dtls_pass_tos;
	int dtls_tos_proto, dtls_tos_optname;

	/* An optimisation for the case where our own code is the only
	 * thing that *could* write to the cmd_fd, to avoid constantly
	 * polling on it while we're busy shovelling packets. */
	int need_poll_cmd_fd;
	int cmd_fd_internal;

	int cmd_fd;
	int cmd_fd_write;
	int got_cancel_cmd;
	int got_pause_cmd;
	char cancel_type;

	struct pkt_q free_queue;
	struct pkt_q incoming_queue;
	struct pkt_q outgoing_queue;
	struct pkt_q tcp_control_queue;		/* Control packets to be sent via TCP */
	int max_qlen;
	struct oc_stats stats;
	openconnect_stats_vfn stats_handler;

	socklen_t peer_addrlen;
	struct sockaddr *peer_addr;
	struct sockaddr *dtls_addr;

	int dtls_local_port;

	int req_compr; /* What we requested */
	int cstp_compr; /* Accepted for CSTP */
	int dtls_compr; /* Accepted for DTLS */

	int is_dyndns; /* Attempt to redo DNS lookup on each CSTP reconnect */
	char *useragent;
	char *version_string;

	const char *quit_reason;
	const char *delay_tunnel_reason;        /* If non-null, provides a reason why protocol is not yet ready for tunnel setup */
	enum {
		NO_DELAY_CLOSE = 0,
		DELAY_CLOSE_WAIT,
		DELAY_CLOSE_IMMEDIATE_CALLBACK,
	} delay_close;                          /* Delay close of mainloop */

	char *sso_login;
	char *sso_login_final;
	char *sso_username;
	char *sso_token_cookie;
	char *sso_error_cookie;
	char *sso_cookie_value;
	char *sso_browser_mode;

	int verbose;
	void *cbdata;
	openconnect_validate_peer_cert_vfn validate_peer_cert;
	openconnect_write_new_config_vfn write_new_config;
	openconnect_open_webview_vfn open_webview;
	openconnect_open_webview_vfn open_ext_browser;
	openconnect_process_auth_form_vfn process_auth_form;
	openconnect_progress_vfn progress;
	openconnect_protect_socket_vfn protect_socket;
	openconnect_getaddrinfo_vfn getaddrinfo_override;
	openconnect_setup_tun_vfn setup_tun;
	openconnect_reconnected_vfn reconnected;

	int (*ssl_read)(struct openconnect_info *vpninfo, char *buf, size_t len);
	int (*ssl_gets)(struct openconnect_info *vpninfo, char *buf, size_t len);
	int (*ssl_write)(struct openconnect_info *vpninfo, char *buf, size_t len);
};

struct vpn_proto {
	const char *name;
	const char *pretty_name;
	const char *description;
	const char *secure_cookie;
	const char *udp_protocol;
	int proto;
	unsigned int flags;
	int (*vpn_close_session)(struct openconnect_info *vpninfo, const char *reason);

	/* This does the full authentication, calling back as appropriate */
	int (*obtain_cookie)(struct openconnect_info *vpninfo);

	/* This checks if SSO authentication is complete */
	int (*sso_detect_done)(struct openconnect_info *vpninfo, const struct oc_webview_result *result);

	/* Establish the TCP connection (and obtain configuration) */
	int (*tcp_connect)(struct openconnect_info *vpninfo);

	int (*tcp_mainloop)(struct openconnect_info *vpninfo, int *timeout, int readable);

	/* Add headers common to each HTTP request */
	void (*add_http_headers)(struct openconnect_info *vpninfo, struct oc_text_buf *buf);

	/* Set up the UDP (DTLS) connection. Doesn't actually *start* it. */
	int (*udp_setup)(struct openconnect_info *vpninfo);

	/* This will actually complete the UDP connection setup/handshake on the wire,
	   as well as transporting packets */
	int (*udp_mainloop)(struct openconnect_info *vpninfo, int *timeout, int readable);

	/* Close the connection but leave the session setup so it restarts */
	void (*udp_close)(struct openconnect_info *vpninfo);

	/* Close and destroy the (UDP) session */
	void (*udp_shutdown)(struct openconnect_info *vpninfo);

	/* Send probe packets to start or maintain the (UDP) session */
	int (*udp_send_probes)(struct openconnect_info *vpninfo);

	/* Catch probe packet confirming the (UDP) session */
	int (*udp_catch_probe)(struct openconnect_info *vpninfo, struct pkt *p);
};

static inline struct pkt *dequeue_packet(struct pkt_q *q)
{
	struct pkt *ret = q->head;

	if (ret) {
		struct pkt *next = ret->next;
		if (!--q->count)
			q->tail = &q->head;
		q->head = next;
	}
	return ret;
}

static inline void requeue_packet(struct pkt_q *q, struct pkt *p)
{
	p->next = q->head;
	q->head = p;
	if (!q->count++)
		q->tail = &p->next;
}

static inline int queue_packet(struct pkt_q *q, struct pkt *p)
{
	*(q->tail) = p;
	p->next = NULL;
	q->tail = &p->next;
	return ++q->count;
}

static inline void init_pkt_queue(struct pkt_q *q)
{
	q->tail = &q->head;
}

static inline struct pkt *alloc_pkt(struct openconnect_info *vpninfo, int len)
{
	int alloc_len = sizeof(struct pkt) + len;

	if (vpninfo->free_queue.head &&
	    vpninfo->free_queue.head->alloc_len >= alloc_len)
		return dequeue_packet(&vpninfo->free_queue);

	if (alloc_len < 2048)
		alloc_len = 2048;

	struct pkt *pkt = malloc(alloc_len);
	if (pkt)
		pkt->alloc_len = alloc_len;
	return pkt;
}

static inline void free_pkt(struct openconnect_info *vpninfo, struct pkt *pkt)
{
	if (!pkt)
		return;

	if (vpninfo->free_queue.count < vpninfo->max_qlen * 2)
		requeue_packet(&vpninfo->free_queue, pkt);
	else
		free(pkt);
}

#define vpn_progress(_v, lvl, ...) do {				\
	if ((_v)->verbose >= (lvl))				\
		(_v)->progress((_v)->cbdata, lvl, __VA_ARGS__);	\
	} while(0)
#define vpn_perror(vpninfo, msg) vpn_progress((vpninfo), PRG_ERR, "%s: %s\n", (msg), strerror(errno))

#ifdef _WIN32
#define monitor_read_fd(_v, _n) (_v->_n##_monitored |= FD_READ)
#define monitor_write_fd(_v, _n) (_v->_n##_monitored |= FD_WRITE)
#define monitor_except_fd(_v, _n) (_v->_n##_monitored |= FD_CLOSE)
#define unmonitor_read_fd(_v, _n) (_v->_n##_monitored &= ~FD_READ)
#define unmonitor_write_fd(_v, _n) (_v->_n##_monitored &= ~FD_WRITE)
#define unmonitor_except_fd(_v, _n) (_v->_n##_monitored &= ~FD_CLOSE)

#define monitor_fd_new(_v, _n) do { if (!_v->_n##_event) _v->_n##_event = CreateEvent(NULL, FALSE, FALSE, NULL); } while (0)
#define read_fd_monitored(_v, _n) (_v->_n##_monitored & FD_READ)

#define __unmonitor_fd(_v, _n) do { CloseHandle(_v->_n##_event); \
		_v->_n##_event = (HANDLE)0;			 \
	} while(0)

#else

#ifdef HAVE_EPOLL
static inline void __sync_epoll_fd(struct openconnect_info *vpninfo, int fd, uint32_t *fd_evts)
{
	if (vpninfo->epoll_fd >= 0 && fd >= 0) {
		struct epoll_event ev = { 0 };
		ev.data.fd = fd;
		if (FD_ISSET(fd, &vpninfo->_select_rfds))
			ev.events |= EPOLLIN;
		if (FD_ISSET(fd, &vpninfo->_select_wfds))
			ev.events |= EPOLLOUT;
		if (ev.events != *fd_evts) {
			if (epoll_ctl(vpninfo->epoll_fd, EPOLL_CTL_MOD, fd, &ev)) {
				vpn_perror(vpninfo, "EPOLL_CTL_MOD");
				close(vpninfo->epoll_fd);
				vpninfo->epoll_fd = -1;
			}
			*fd_evts = ev.events;
		}
	}
}
#define update_epoll_fd(_v, _n) __sync_epoll_fd(_v, _v->_n##_fd, &_v->_n##_epoll)

static inline void __remove_epoll_fd(struct openconnect_info *vpninfo, int fd)
{
	struct epoll_event ev = { 0 };
	if (vpninfo->epoll_fd >= 0 &&
	    epoll_ctl(vpninfo->epoll_fd, EPOLL_CTL_DEL, fd, &ev) < 0 &&
	    errno != ENOENT)
		vpn_perror(vpninfo, "EPOLL_CTL_DEL");
	/* No other action on error; if it truly matters we'll bail later
	 * and fall back to select(). We also explicitly ignore ENOENT
	 * because openconnect_close_https() will always unmonitor the
	 * ssl_fd even when we never got to the point of using it in the
	 * main loop and actually monitoring it. */
}

#define __unmonitor_fd(_v, _n) do {		    \
		__remove_epoll_fd(_v, _v->_n##_fd); \
		_v->_n##_epoll = 0; } while(0)

#else /* !HAVE_POLL */
#define __unmonitor_fd(_v, _n) do { } while(0)
#endif

static inline void __monitor_fd_event(struct openconnect_info *vpninfo,
				      int fd, fd_set *set)
{
	if (fd < 0 || FD_ISSET(fd, set))
		return;

	FD_SET(fd, set);
#ifdef HAVE_EPOLL
	vpninfo->epoll_update = 1;
#endif
}

static inline void __unmonitor_fd_event(struct openconnect_info *vpninfo,
					int fd, fd_set *set)
{
	if (fd < 0 || !FD_ISSET(fd, set))
		return;

	FD_CLR(fd, set);
#ifdef HAVE_EPOLL
	vpninfo->epoll_update = 1;
#endif
}

#define monitor_read_fd(_v, _n) __monitor_fd_event(_v, _v->_n##_fd, &_v->_select_rfds)
#define unmonitor_read_fd(_v, _n) __unmonitor_fd_event(_v, _v->_n##_fd, &_v->_select_rfds)
#define monitor_write_fd(_v, _n) __monitor_fd_event(_v, _v->_n##_fd, &_v->_select_wfds)
#define unmonitor_write_fd(_v, _n) __unmonitor_fd_event(_v, _v->_n##_fd, &_v->_select_wfds)
#define monitor_except_fd(_v, _n) __monitor_fd_event(_v, _v->_n##_fd, &_v->_select_efds)
#define unmonitor_except_fd(_v, _n) __unmonitor_fd_event(_v, _v->_n##_fd, &_v->_select_efds)

static inline void __monitor_fd_new(struct openconnect_info *vpninfo,
				    int fd)
{
	if (vpninfo->_select_nfds <= fd)
		vpninfo->_select_nfds = fd + 1;
#ifdef HAVE_EPOLL
	if (vpninfo->epoll_fd >= 0) {
		struct epoll_event ev = { 0 };
		ev.data.fd = fd;
		if (epoll_ctl(vpninfo->epoll_fd, EPOLL_CTL_ADD, fd, &ev)) {
			vpn_perror(vpninfo, "EPOLL_CTL_ADD");
			close(vpninfo->epoll_fd);
			vpninfo->epoll_fd = -1;
		}
	}
#endif
}

#define monitor_fd_new(_v, _n) __monitor_fd_new(_v, _v->_n##_fd)
#define read_fd_monitored(_v, _n) FD_ISSET(_v->_n##_fd, &_v->_select_rfds)
#endif /* !WIN32 */

/* This is for all platforms */
#define unmonitor_fd(_v, _n) do {		\
		unmonitor_read_fd(_v, _n);	\
		unmonitor_write_fd(_v, _n);	\
		unmonitor_except_fd(_v, _n);	\
		__unmonitor_fd(_v, _n);		\
	} while(0)

/* Key material for DTLS-PSK */
#define PSK_LABEL "EXPORTER-openconnect-psk"
#define PSK_LABEL_SIZE (sizeof(PSK_LABEL) - 1)
#define PSK_KEY_SIZE 32

/* Packet types */

#define AC_PKT_DATA		0	/* Uncompressed data */
#define AC_PKT_DPD_OUT		3	/* Dead Peer Detection */
#define AC_PKT_DPD_RESP		4	/* DPD response */
#define AC_PKT_DISCONN		5	/* Client disconnection notice */
#define AC_PKT_KEEPALIVE	7	/* Keepalive */
#define AC_PKT_COMPRESSED	8	/* Compressed data */
#define AC_PKT_TERM_SERVER	9	/* Server kick */

/* Encryption and HMAC algorithms (matching Juniper/Pulse binary encoding) */
#define ENC_AES_128_CBC		2
#define ENC_AES_256_CBC		5

#define HMAC_MD5		1
#define HMAC_SHA1		2
#define HMAC_SHA256		3

#define MAX_HMAC_SIZE		32	/* SHA256 */
#define MAX_IV_SIZE		16
#define MAX_ESP_PAD		17	/* Including the next-header field */

/****************************************************************************/
/* Oh Solaris how we hate thee! */
#ifdef HAVE_SUNOS_BROKEN_TIME
#define time(x) openconnect__time(x)
time_t openconnect__time(time_t *t);
#endif
#ifndef HAVE_VASPRINTF
#define vasprintf openconnect__vasprintf
int openconnect__vasprintf(char **strp, const char *fmt, va_list ap);
#endif
#ifndef HAVE_ASPRINTF
#define asprintf openconnect__asprintf
int openconnect__asprintf(char **strp, const char *fmt, ...);
#endif
#ifndef HAVE_GETLINE
#define getline openconnect__getline
ssize_t openconnect__getline(char **lineptr, size_t *n, FILE *stream);
#endif
#ifndef HAVE_STRCASESTR
#define strcasestr openconnect__strcasestr
char *openconnect__strcasestr(const char *haystack, const char *needle);
#endif
#ifndef HAVE_STRNDUP
#undef strndup
#define strndup openconnect__strndup
char *openconnect__strndup(const char *s, size_t n);
#endif
#ifndef HAVE_STRCHRNUL
#undef strchrnul
#define strchrnul openconnect__strchrnul
const char *openconnect__strchrnul(const char *s, int c);
#endif

#ifndef HAVE_INET_ATON
#define inet_aton openconnect__inet_aton
int openconnect__inet_aton(const char *cp, struct in_addr *addr);
#endif

static inline int set_sock_nonblock(int fd)
{
#ifdef _WIN32
	unsigned long mode = 1;
	return ioctlsocket(fd, FIONBIO, &mode);
#else
	return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
#endif
}
static inline int set_fd_cloexec(int fd)
{
#ifdef _WIN32
	return 0; /* Windows has O_INHERIT but... */
#else
	int ret = fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
	/*
	 * Coverity gets really sad if we don't check the error here.
	 * But really, we're doing this to be a 'good citizen' when
	 * running as a library, and we aren't even going to bother
	 * printing a debug message if it fails. We just don't care.
	 */
	if (ret)
		return ret;
	return 0;
#endif
}
static inline int tun_is_up(struct openconnect_info *vpninfo)
{
#ifdef _WIN32
	return vpninfo->tun_fh != NULL;
#else
	return vpninfo->tun_fd != -1;
#endif
}

#ifdef _WIN32
#define pipe(fds) _pipe(fds, 4096, O_BINARY)
int openconnect__win32_sock_init(void);
char *openconnect__win32_strerror(DWORD err);
#undef setenv
#define setenv openconnect__win32_setenv
int openconnect__win32_setenv(const char *name, const char *value, int overwrite);
#undef inet_pton
#define inet_pton openconnect__win32_inet_pton
int openconnect__win32_inet_pton(int af, const char *src, void *dst);
#define OPENCONNECT_CMD_SOCKET SOCKET
int dumb_socketpair(OPENCONNECT_CMD_SOCKET socks[2], int make_overlapped);
#else
#define closesocket close
#define OPENCONNECT_CMD_SOCKET int
#ifndef O_BINARY
#define O_BINARY 0
#endif
#endif

/* For systems that don't support O_CLOEXEC, just don't bother.
   We don't keep files open for long anyway. */
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* I always coded as if it worked like this. Now it does. */
#define realloc_inplace(p, size) do {			\
	void *__realloc_old = p;			\
	size_t sz = size;				\
	p = realloc(p, sz);				\
	if (sz && !p)					\
		free(__realloc_old);			\
    } while (0)

/****************************************************************************/
typedef enum {
	MULTICERT_COMPAT = (1<<0),
} cert_flag_t;

typedef enum {
	CERT_FORMAT_ASN1 = 0,
	CERT_FORMAT_PEM = 1,
} cert_format_t;

typedef enum {
	OPENCONNECT_HASH_UNKNOWN = 0,
#define OPENCONNECT_HASH_NONE OPENCONNECT_HASH_NONE
	OPENCONNECT_HASH_SHA256 = 1,
#define OPENCONNECT_HASH_SHA256 OPENCONNECT_HASH_SHA256
	OPENCONNECT_HASH_SHA384 = 2,
#define OPENCONNECT_HASH_SHA384 OPENCONNECT_HASH_SHA384
	OPENCONNECT_HASH_SHA512 = 3,
#define OPENCONNECT_HASH_SHA512 OPENCONNECT_HASH_SHA512
	OPENCONNECT_HASH_MAX = OPENCONNECT_HASH_SHA512
} openconnect_hash_type;

int load_certificate(struct openconnect_info *, struct cert_info *, int flags);
void unload_certificate(struct cert_info *, int final);
int export_certificate_pkcs7(struct openconnect_info *, struct cert_info *, cert_format_t format, struct oc_text_buf **);

/* multiple certificate authentication */
#define MULTICERT_HASH_FLAG(v)	((v)?(1<<((v)-1)):0)

int multicert_sign_data(struct openconnect_info *, struct cert_info *certinfo, unsigned int hashes,
			const void *data, size_t datalen, struct oc_text_buf **signature);

const char *multicert_hash_get_name(int id);
openconnect_hash_type multicert_hash_get_id(const char *name);

/* iconv.c */
#ifdef HAVE_ICONV
char *openconnect_utf8_to_legacy(struct openconnect_info *vpninfo, const char *utf8);
char *openconnect_legacy_to_utf8(struct openconnect_info *vpninfo, const char *legacy);
#else
#define openconnect_utf8_to_legacy(v, str) ((char *)str)
#define openconnect_legacy_to_utf8(v, str) ((char *)str)
#endif

/* script.c */
unsigned char unhex(const char *data);
int script_setenv(struct openconnect_info *vpninfo, const char *opt, const char *val, int trunc, int append);
int script_setenv_int(struct openconnect_info *vpninfo, const char *opt, int value);
void prepare_script_env(struct openconnect_info *vpninfo);
int script_config_tun(struct openconnect_info *vpninfo, const char *reason);
int apply_script_env(struct oc_vpn_option *envs);
void free_split_routes(struct oc_ip_info *ip_info);
int install_vpn_opts(struct openconnect_info *vpninfo, struct oc_vpn_option *opt,
		     struct oc_ip_info *ip_info);

/* vhost.h */
int setup_vhost(struct openconnect_info *vpninfo, int tun_fd);
void shutdown_vhost(struct openconnect_info *vpninfo);
int vhost_tun_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable, int did_work);

/* tun.c / tun-win32.c */
void os_shutdown_tun(struct openconnect_info *vpninfo);
int os_read_tun(struct openconnect_info *vpninfo, struct pkt *pkt);
int os_write_tun(struct openconnect_info *vpninfo, struct pkt *pkt);
intptr_t os_setup_tun(struct openconnect_info *vpninfo);

#ifdef _WIN32
#define OPEN_TUN_SOFTFAIL 0
#define OPEN_TUN_HARDFAIL -1

/* wintun.c */
void os_shutdown_wintun(struct openconnect_info *vpninfo);
int os_read_wintun(struct openconnect_info *vpninfo, struct pkt *pkt);
int os_write_wintun(struct openconnect_info *vpninfo, struct pkt *pkt);
intptr_t os_setup_wintun(struct openconnect_info *vpninfo);
int setup_wintun_fd(struct openconnect_info *vpninfo, intptr_t tun_fd);
intptr_t open_wintun(struct openconnect_info *vpninfo, char *guid, wchar_t *wname);
int create_wintun(struct openconnect_info *vpninfo);
#endif

/* {gnutls,openssl}-dtls.c */
int start_dtls_handshake(struct openconnect_info *vpninfo, int dtls_fd);
int dtls_try_handshake(struct openconnect_info *vpninfo, int *timeout);
unsigned dtls_set_mtu(struct openconnect_info *vpninfo, unsigned mtu);
void dtls_ssl_free(struct openconnect_info *vpninfo);

void *establish_eap_ttls(struct openconnect_info *vpninfo);
void destroy_eap_ttls(struct openconnect_info *vpninfo, void *sess);

/* dtls.c */
int dtls_setup(struct openconnect_info *vpninfo);
int dtls_reconnect(struct openconnect_info *vpninfo, int *timeout);
int udp_tos_update(struct openconnect_info *vpninfo, struct pkt *pkt);
int dtls_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable);
void dtls_close(struct openconnect_info *vpninfo);
void dtls_shutdown(struct openconnect_info *vpninfo);
void gather_dtls_ciphers(struct openconnect_info *vpninfo, struct oc_text_buf *buf, struct oc_text_buf *buf12);
void dtls_detect_mtu(struct openconnect_info *vpninfo);
int openconnect_dtls_read(struct openconnect_info *vpninfo, void *buf, size_t len, unsigned ms);
int openconnect_dtls_write(struct openconnect_info *vpninfo, void *buf, size_t len);
char *openconnect_bin2hex(const char *prefix, const uint8_t *data, unsigned len);
char *openconnect_bin2base64(const char *prefix, const uint8_t *data, unsigned len);

/* mtucalc.c */

int calculate_mtu(struct openconnect_info *vpninfo, int is_udp, int unpadded_overhead, int padded_overhead, int block_size);

/* cstp.c */
void cstp_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf);
int cstp_connect(struct openconnect_info *vpninfo);
int cstp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable);
int cstp_bye(struct openconnect_info *vpninfo, const char *reason);
int decompress_and_queue_packet(struct openconnect_info *vpninfo, int compr_type,
				unsigned char *buf, int len);
int compress_packet(struct openconnect_info *vpninfo, int compr_type, struct pkt *this);
int cstp_sso_detect_done(struct openconnect_info *vpninfo, const struct oc_webview_result *result);

/* auth-html.c */
xmlNodePtr htmlnode_next(xmlNodePtr top, xmlNodePtr node);
xmlNodePtr htmlnode_dive(xmlNodePtr top, xmlNodePtr node);
xmlNodePtr find_form_node(xmlDocPtr doc);
int parse_input_node(struct openconnect_info *vpninfo, struct oc_auth_form *form,
		     xmlNodePtr node, const char *submit_button,
		     int (*can_gen_tokencode)(struct openconnect_info *vpninfo, struct oc_auth_form *form, struct oc_form_opt *opt));
int parse_select_node(struct openconnect_info *vpninfo, struct oc_auth_form *form,
		      xmlNodePtr node);
struct oc_auth_form *parse_form_node(struct openconnect_info *vpninfo,
				     xmlNodePtr node, const char *submit_button,
				     int (*can_gen_tokencode)(struct openconnect_info *vpninfo, struct oc_auth_form *form, struct oc_form_opt *opt));

/* auth-juniper.c */
int oncp_obtain_cookie(struct openconnect_info *vpninfo);
int oncp_send_tncc_command(struct openconnect_info *vpninfo, int first);
void oncp_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf);

/* oncp.c */
int oncp_connect(struct openconnect_info *vpninfo);
int oncp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable);
int oncp_bye(struct openconnect_info *vpninfo, const char *reason);
void oncp_esp_close(struct openconnect_info *vpninfo);
int oncp_esp_send_probes(struct openconnect_info *vpninfo);
int oncp_esp_catch_probe(struct openconnect_info *vpninfo, struct pkt *pkt);

/* pulse.c */
int pulse_obtain_cookie(struct openconnect_info *vpninfo);
void pulse_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf);
int pulse_connect(struct openconnect_info *vpninfo);
int pulse_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable);
int pulse_bye(struct openconnect_info *vpninfo, const char *reason);
int pulse_eap_ttls_send(struct openconnect_info *vpninfo, const void *data, int len);
int pulse_eap_ttls_recv(struct openconnect_info *vpninfo, void *data, int len);

/* nullppp.c */
int nullppp_obtain_cookie(struct openconnect_info *vpninfo);
int nullppp_connect(struct openconnect_info *vpninfo);
int nullppp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable);

/* f5.c */
int f5_obtain_cookie(struct openconnect_info *vpninfo);
int f5_connect(struct openconnect_info *vpninfo);
int f5_bye(struct openconnect_info *vpninfo, const char *reason);
int f5_dtls_catch_probe(struct openconnect_info *vpninfo, struct pkt *pkt);

/* fortinet.c */
void fortinet_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf);
int fortinet_obtain_cookie(struct openconnect_info *vpninfo);
int fortinet_connect(struct openconnect_info *vpninfo);
int fortinet_bye(struct openconnect_info *vpninfo, const char *reason);
int fortinet_dtls_catch_svrhello(struct openconnect_info *vpninfo, struct pkt *pkt);

/* ppp.c */
struct oc_ppp;
void buf_append_ppphdlc(struct oc_text_buf *buf, const unsigned char *bytes, int len, uint32_t asyncmap);
void buf_append_ppp_hdr(struct oc_text_buf *buf, struct oc_ppp *ppp, uint16_t proto, uint8_t code, uint8_t id);
int ppp_negotiate_config(struct openconnect_info *vpninfo);
int ppp_tcp_should_connect(struct openconnect_info *vpninfo);
int ppp_start_tcp_mainloop(struct openconnect_info *vpninfo);
int ppp_tcp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable);
int ppp_udp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable);
int openconnect_ppp_new(struct openconnect_info *vpninfo, int encap, int want_ipv4, int want_ipv6);
int ppp_reset(struct openconnect_info *vpninfo);
int check_http_status(const char *buf, int len);

/* array.c */
int array_obtain_cookie(struct openconnect_info *vpninfo);
int array_connect(struct openconnect_info *vpninfo);
int array_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable);
int array_dtls_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable);
int array_bye(struct openconnect_info *vpninfo, const char *reason);

/* auth-globalprotect.c */
int gpst_obtain_cookie(struct openconnect_info *vpninfo);
void gpst_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf);
int gpst_bye(struct openconnect_info *vpninfo, const char *reason);
const char *gpst_os_name(struct openconnect_info *vpninfo);

/* gpst.c */
int gpst_xml_or_error(struct openconnect_info *vpninfo, char *response,
					  int (*xml_cb)(struct openconnect_info *, xmlNode *xml_node, void *cb_data),
					  int (*challenge_cb)(struct openconnect_info *, char *prompt, char *inputStr, void *cb_data),
					  void *cb_data);
int gpst_setup(struct openconnect_info *vpninfo);
int gpst_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable);
int gpst_esp_send_probes(struct openconnect_info *vpninfo);
int gpst_esp_catch_probe(struct openconnect_info *vpninfo, struct pkt *pkt);
int gpst_sso_detect_done(struct openconnect_info *vpninfo, const struct oc_webview_result *result);

/* lzs.c */
int lzs_decompress(unsigned char *dst, int dstlen, const unsigned char *src, int srclen);
int lzs_compress(unsigned char *dst, int dstlen, const unsigned char *src, int srclen);

/* ssl.c */
unsigned string_is_hostname(const char *str);
int connect_https_socket(struct openconnect_info *vpninfo);
int __attribute__ ((format(printf, 4, 5)))
    request_passphrase(struct openconnect_info *vpninfo, const char *label,
		       char **response, const char *fmt, ...);
int  __attribute__ ((format (printf, 2, 3)))
    openconnect_SSL_printf(struct openconnect_info *vpninfo, const char *fmt, ...);
int openconnect_print_err_cb(const char *str, size_t len, void *ptr);
#define openconnect_report_ssl_errors(v) ERR_print_errors_cb(openconnect_print_err_cb, (v))
#if defined(FAKE_ANDROID_KEYSTORE) || defined(__ANDROID__)
#define ANDROID_KEYSTORE
#endif
#ifdef ANDROID_KEYSTORE
const char *keystore_strerror(int err);
int keystore_fetch(const char *key, unsigned char **result);
#endif
void cmd_fd_set(struct openconnect_info *vpninfo, fd_set *fds, int *maxfd);
void check_cmd_fd(struct openconnect_info *vpninfo, fd_set *fds);
int is_cancel_pending(struct openconnect_info *vpninfo, fd_set *fds);
void poll_cmd_fd(struct openconnect_info *vpninfo, int timeout);
int openconnect_open_utf8(struct openconnect_info *vpninfo,
			  const char *fname, int mode);
FILE *openconnect_fopen_utf8(struct openconnect_info *vpninfo,
			     const char *fname, const char *mode);
ssize_t openconnect_read_file(struct openconnect_info *vpninfo, const char *fname,
			      char **ptr);
int udp_sockaddr(struct openconnect_info *vpninfo, int port);
int udp_connect(struct openconnect_info *vpninfo);
int ssl_reconnect(struct openconnect_info *vpninfo);
void openconnect_clear_cookies(struct openconnect_info *vpninfo);
int cancellable_gets(struct openconnect_info *vpninfo, int fd,
		     char *buf, size_t len);

int cancellable_send(struct openconnect_info *vpninfo, int fd,
		     const char *buf, size_t len);
int cancellable_recv(struct openconnect_info *vpninfo, int fd,
		     char *buf, size_t len);
int cancellable_accept(struct openconnect_info *vpninfo, int fd);

#if defined(OPENCONNECT_OPENSSL)
/* openssl-pkcs11.c */
int load_pkcs11_key(struct openconnect_info *vpninfo, struct cert_info *certinfo, EVP_PKEY **keyp);
int load_pkcs11_certificate(struct openconnect_info *vpninfo, struct cert_info *certinfo, X509 **certp);
#endif

/* esp.c */
int verify_packet_seqno(struct openconnect_info *vpninfo,
			struct esp *esp, uint32_t seq);
int esp_setup(struct openconnect_info *vpninfo);
int esp_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable);
void esp_close(struct openconnect_info *vpninfo);
void esp_shutdown(struct openconnect_info *vpninfo);
int print_esp_keys(struct openconnect_info *vpninfo, const char *name, struct esp *esp);
int openconnect_setup_esp_keys(struct openconnect_info *vpninfo, int new_keys);
int construct_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt, uint8_t next_hdr);

/* {gnutls,openssl}-esp.c */
void destroy_esp_ciphers(struct esp *esp);
int init_esp_ciphers(struct openconnect_info *vpninfo, struct esp *out, struct esp *in);
int decrypt_esp_packet(struct openconnect_info *vpninfo, struct esp *esp, struct pkt *pkt);
int encrypt_esp_packet(struct openconnect_info *vpninfo, struct pkt *pkt, int crypt_len);

/* {gnutls,openssl}.c */
const char *openconnect_get_tls_library_version(void);
int can_enable_insecure_crypto(void);
int ssl_nonblock_read(struct openconnect_info *vpninfo, int dtls, void *buf, int maxlen);
int ssl_nonblock_write(struct openconnect_info *vpninfo, int dtls, void *buf, int buflen);
int openconnect_open_https(struct openconnect_info *vpninfo);
void openconnect_close_https(struct openconnect_info *vpninfo, int final);
int cstp_handshake(struct openconnect_info *vpninfo, unsigned init);
int get_cert_md5_fingerprint(struct openconnect_info *vpninfo, void *cert,
			     char *buf);
int openconnect_sha1(unsigned char *result, void *data, int len);
int openconnect_sha256(unsigned char *result, void *data, int len);
int openconnect_md5(unsigned char *result, void *data, int len);
int openconnect_random(void *bytes, int len);
int openconnect_local_cert_md5(struct openconnect_info *vpninfo,
			       char *buf);
int openconnect_yubikey_chalresp(struct openconnect_info *vpninfo,
				 const void *challenge, int chall_len, void *result);
int openconnect_hash_yubikey_password(struct openconnect_info *vpninfo,
				      const char *password, int pwlen,
				      const void *ident, int id_len);
int hotp_hmac(struct openconnect_info *vpninfo, const void *challenge);
#if defined(OPENCONNECT_OPENSSL)
#define openconnect_https_connected(_v) ((_v)->https_ssl)
#elif defined (OPENCONNECT_GNUTLS)
#define openconnect_https_connected(_v) ((_v)->https_sess)
#endif
#ifdef OPENCONNECT_OPENSSL
int openconnect_install_ctx_verify(struct openconnect_info *vpninfo,
				   SSL_CTX *ctx);
#endif
void free_strap_keys(struct openconnect_info *vpninfo);
int generate_strap_keys(struct openconnect_info *vpninfo);
int ecdh_compute_secp256r1(struct openconnect_info *vpninfo, const unsigned char *pubkey,
			   int pubkey_len, unsigned char *secret);
int hkdf_sha256_extract_expand(struct openconnect_info *vpninfo, unsigned char *buf,
			       const unsigned char *info, int infolen);
int aes_256_gcm_decrypt(struct openconnect_info *vpninfo, unsigned char *key,
			unsigned char *data, int len,
			unsigned char *iv, unsigned char *tag);
void append_strap_verify(struct openconnect_info *vpninfo, struct oc_text_buf *buf, int rekey);
void append_strap_privkey(struct openconnect_info *vpninfo, struct oc_text_buf *buf);
int ingest_strap_privkey(struct openconnect_info *vpninfo, unsigned char *der, int len);

/* mainloop.c */
int tun_mainloop(struct openconnect_info *vpninfo, int *timeout, int readable, int did_work);
int queue_new_packet(struct openconnect_info *vpninfo,
		     struct pkt_q *q, void *buf, int len);
int keepalive_action(struct keepalive_info *ka, int *timeout);
int ka_stalled_action(struct keepalive_info *ka, int *timeout);
int ka_check_deadline(int *timeout, time_t now, time_t due);
int trojan_check_deadline(struct openconnect_info *vpninfo, int *timeout);

/* xml.c */
int config_lookup_host(struct openconnect_info *vpninfo, const char *host);

/* oath.c */
int set_oath_mode(struct openconnect_info *vpninfo, const char *token_str,
		  oc_token_mode_t token_mode);
int can_gen_totp_code(struct openconnect_info *vpninfo,
		      struct oc_auth_form *form,
		      struct oc_form_opt *opt);
int can_gen_hotp_code(struct openconnect_info *vpninfo,
		      struct oc_auth_form *form,
		      struct oc_form_opt *opt);
int do_gen_totp_code(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form,
		     struct oc_form_opt *opt);
int do_gen_hotp_code(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form,
		     struct oc_form_opt *opt);

int set_oidc_token(struct openconnect_info *vpninfo,
		     const char *token_str);

/* stoken.c */
int prepare_stoken(struct openconnect_info *vpninfo);
int set_libstoken_mode(struct openconnect_info *vpninfo, const char *token_str);
int can_gen_stoken_code(struct openconnect_info *vpninfo,
			struct oc_auth_form *form,
			struct oc_form_opt *opt);
int do_gen_stoken_code(struct openconnect_info *vpninfo,
		       struct oc_auth_form *form,
		       struct oc_form_opt *opt);

/* yubikey.c */
int set_yubikey_mode(struct openconnect_info *vpninfo, const char *token_str);
int can_gen_yubikey_code(struct openconnect_info *vpninfo,
			 struct oc_auth_form *form,
			 struct oc_form_opt *opt);
int do_gen_yubikey_code(struct openconnect_info *vpninfo,
			struct oc_auth_form *form,
			struct oc_form_opt *opt);
void release_pcsc_ctx(struct openconnect_info *info);

/* auth.c */
int cstp_obtain_cookie(struct openconnect_info *vpninfo);
int set_csd_user(struct openconnect_info *vpninfo);

/* auth-common.c */
int xmlnode_is_named(xmlNode *xml_node, const char *name);
int xmlnode_get_val(xmlNode *xml_node, const char *name, char **var);
int xmlnode_get_prop(xmlNode *xml_node, const char *name, char **var);
int xmlnode_match_prop(xmlNode *xml_node, const char *name, const char *match);
int xmlnode_get_trimmed_val(xmlNode *xml_node, const char *name, char **var);
int xmlnode_bool_or_int_value(xmlNode *node);
int append_opt(struct oc_text_buf *body, const char *opt, const char *name);
int append_form_opts(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form, struct oc_text_buf *body);
void clear_mem(void *p, size_t s);
void free_pass(char **p);
void free_opt(struct oc_form_opt *opt);
void free_auth_form(struct oc_auth_form *form);
int do_gen_tokencode(struct openconnect_info *vpninfo,
		     struct oc_auth_form *form);
int can_gen_tokencode(struct openconnect_info *vpninfo,
		      struct oc_auth_form *form,
		      struct oc_form_opt *opt);

/* textbuf,c */
struct oc_text_buf *buf_alloc(void);
int buf_error(struct oc_text_buf *buf);
int buf_free(struct oc_text_buf *buf);
void buf_truncate(struct oc_text_buf *buf);
int buf_ensure_space(struct oc_text_buf *buf, int len);
void buf_append_bytes(struct oc_text_buf *buf, const void *bytes, int len);
void  __attribute__ ((format (printf, 2, 3)))
	buf_append(struct oc_text_buf *buf, const char *fmt, ...);
void buf_append_urlencoded(struct oc_text_buf *buf, const char *str);
void buf_append_xmlescaped(struct oc_text_buf *buf, const char *str);
void buf_append_be16(struct oc_text_buf *buf, uint16_t val);
void buf_append_be32(struct oc_text_buf *buf, uint32_t val);
void buf_append_le16(struct oc_text_buf *buf, uint16_t val);
void buf_append_hex(struct oc_text_buf *buf, const void *str, unsigned len);
int buf_append_utf16le(struct oc_text_buf *buf, const char *utf8);
int get_utf8char(const char **utf8);
void buf_append_from_utf16le(struct oc_text_buf *buf, const void *utf16);
void buf_append_base64(struct oc_text_buf *buf, const void *bytes, int len, int line_len);

/* http.c */
void do_dump_buf(struct openconnect_info *vpninfo, char prefix, char *buf);
void do_dump_buf_hex(struct openconnect_info *vpninfo, int loglevel, char prefix, unsigned char *buf, int len);
char *openconnect_create_useragent(const char *base);
int process_proxy(struct openconnect_info *vpninfo, int ssl_sock);
int internal_parse_url(const char *url, char **res_proto, char **res_host,
		       int *res_port, char **res_path, int default_port);
char *internal_get_url(struct openconnect_info *vpninfo);
int do_https_request(struct openconnect_info *vpninfo, const char *method, const char *request_body_type,
		     struct oc_text_buf *request_body, char **form_buf,
		     int (*header_cb)(struct openconnect_info *, char *, char *), int flags);
int http_add_cookie(struct openconnect_info *vpninfo, const char *option,
		    const char *value, int replace);
const char *http_get_cookie(struct openconnect_info *vpninfo, const char *name);
int internal_split_cookies(struct openconnect_info *vpninfo, int replace, const char *def_cookie);
int urldecode_inplace(char *p);
int process_http_response(struct openconnect_info *vpninfo, int connect,
			  int (*header_cb)(struct openconnect_info *, char *, char *),
			  struct oc_text_buf *body);
int handle_redirect(struct openconnect_info *vpninfo);
void http_common_headers(struct openconnect_info *vpninfo, struct oc_text_buf *buf);
#define dump_buf(vpninfo, prefix, buf) do {			\
		if ((vpninfo)->verbose >= PRG_DEBUG) {		\
			do_dump_buf(vpninfo, prefix, buf);	\
		}						\
	} while(0)
#define dump_buf_hex(vpninfo, loglevel, prefix, buf, len) do {			\
		if ((vpninfo)->verbose >= (loglevel)) {				\
			do_dump_buf_hex(vpninfo, loglevel, prefix, buf, len);	\
		}								\
	} while(0)

/* http-auth.c */
void *openconnect_base64_decode(int *len, const char *in);
void clear_auth_states(struct openconnect_info *vpninfo,
		       struct http_auth_state *auth_states, int reset);
int proxy_auth_hdrs(struct openconnect_info *vpninfo, char *hdr, char *val);
int http_auth_hdrs(struct openconnect_info *vpninfo, char *hdr, char *val);
int gen_authorization_hdr(struct openconnect_info *vpninfo, int proxy,
			  struct oc_text_buf *buf);
/* ntlm.c */
int ntlm_authorization(struct openconnect_info *vpninfo, int proxy, struct http_auth_state *auth_state, struct oc_text_buf *buf);
void cleanup_ntlm_auth(struct openconnect_info *vpninfo, struct http_auth_state *auth_state);

/* gssapi.c */
int gssapi_authorization(struct openconnect_info *vpninfo, int proxy, struct http_auth_state *auth_state, struct oc_text_buf *buf);
void cleanup_gssapi_auth(struct openconnect_info *vpninfo, struct http_auth_state *auth_state);
int socks_gssapi_auth(struct openconnect_info *vpninfo);

/* digest.c */
int digest_authorization(struct openconnect_info *vpninfo, int proxy, struct http_auth_state *auth_state, struct oc_text_buf *buf);

/* jsondump.c */
void dump_json(struct openconnect_info *vpninfo, int lvl, json_value *value);

/* library.c */
void nuke_opt_values(struct oc_form_opt *opt);
const char *add_option_dup(struct oc_vpn_option **list, const char *opt, const char *val, int val_len);
const char *add_option_steal(struct oc_vpn_option **list, const char *opt, char **val);
const char *add_option_ipaddr(struct oc_vpn_option **list, const char *opt, int af, void *addr);
void free_optlist(struct oc_vpn_option *opt);
int process_auth_form(struct openconnect_info *vpninfo, struct oc_auth_form *form);
/* This is private for now since we haven't yet worked out what the API will be */
void openconnect_set_juniper(struct openconnect_info *vpninfo);

/* hpke.c */
int handle_external_browser(struct openconnect_info *vpninfo);

/* version.c */
extern const char openconnect_version_str[];


static inline int certinfo_is_primary(struct cert_info *certinfo)
{
	return certinfo == &certinfo->vpninfo->certinfo[0];
}
static inline int certinfo_is_secondary(struct cert_info *certinfo)
{
	return certinfo == &certinfo->vpninfo->certinfo[1];
}
#define certinfo_string(ci, strA, strB) (certinfo_is_primary(ci) ? (strA) : (strB))

/* strncasecmp() just checks that the first n characters match. This
   function ensures that the first n characters of the left-hand side
   are a *precise* match for the right-hand side. */
static inline int strprefix_match(const char *str, int len, const char *match)
{
	return len == strlen(match) && !strncasecmp(str, match, len);
}

#define STRDUP(res, arg) \
	do {								\
		if (res != arg) {					\
			free(res);					\
			if (arg) {					\
				res = strdup(arg);			\
				if (res == NULL) return -ENOMEM;	\
			} else res = NULL;				\
		}							\
	} while(0)

#define UTF8CHECK(arg) \
	do {								\
		if ((arg) && buf_append_utf16le(NULL, (arg))) {		\
			vpn_progress(vpninfo, PRG_ERR,			\
			             _("ERROR: %s() called with invalid UTF-8 for '%s' argument\n"),\
			             __func__, #arg);			\
			return -EILSEQ;					\
		}							\
	} while(0)

#define UTF8CHECK_VOID(arg) \
	do {								\
		if ((arg) && buf_append_utf16le(NULL, (arg))) {		\
			vpn_progress(vpninfo, PRG_ERR,			\
			             _("ERROR: %s() called with invalid UTF-8 for '%s' argument\n"),\
			             __func__, #arg);			\
			return;						\
		}							\
	} while(0)

/* Let's stop open-coding big-endian and little-endian loads/stores.
 *
 * Start with a packed structure so that we can let the compiler
 * decide whether the target CPU can cope with unaligned load/stores
 * or not. Then there are three cases to handle:
 *  - For big-endian loads/stores, just use htons() et al.
 *  - For little-endian when we *know* the CPU is LE, just load/store
 *  - For little-endian otherwise, do the data access byte-wise
 */
struct oc_packed_uint32_t {
	uint32_t d;
} __attribute__((packed));
struct oc_packed_uint16_t {
	uint16_t d;
} __attribute__((packed));

static inline uint32_t load_be32(const void *_p)
{
	const struct oc_packed_uint32_t *p = _p;
	return ntohl(p->d);
}

static inline uint16_t load_be16(const void *_p)
{
	const struct oc_packed_uint16_t *p = _p;
	return ntohs(p->d);
}

static inline void store_be32(void *_p, uint32_t d)
{
	struct oc_packed_uint32_t *p = _p;
	p->d = htonl(d);
}

static inline void store_be16(void *_p, uint16_t d)
{
	struct oc_packed_uint16_t *p = _p;
	p->d = htons(d);
}

/* It doesn't matter if we don't find one. It'll default to the
 * "not known to be little-endian" case, and do the bytewise
 * load/store. Modern compilers might even spot the pattern and
 * optimise it (see GCC PR#55177 around comment 15). */
#ifdef ENDIAN_HDR
#include ENDIAN_HDR
#endif

#if defined(_WIN32) ||							       \
   (defined(_LITTLE_ENDIAN) && !defined(_BIG_ENDIAN)) /* Solaris */ ||	       \
   (defined(__LITTLE_ENDIAN) && defined(__BIG_ENDIAN) && defined(__BYTE_ORDER) \
    && __BYTE_ORDER == __LITTLE_ENDIAN) /* Linux */ ||			       \
   (defined(LITTLE_ENDIAN) && defined(BIG_ENDIAN) && defined(BYTE_ORDER)       \
    && BYTE_ORDER == LITTLE_ENDIAN) /* *BSD */
static inline uint32_t load_le32(const void *_p)
{
	const struct oc_packed_uint32_t *p = _p;
	return p->d;
}

static inline uint16_t load_le16(const void *_p)
{
	const struct oc_packed_uint16_t *p = _p;
	return p->d;
}

static inline void store_le32(void *_p, uint32_t d)
{
	struct oc_packed_uint32_t *p = _p;
	p->d = d;
}

static inline void store_le16(void *_p, uint16_t d)
{
	struct oc_packed_uint16_t *p = _p;
	p->d = d;
}
#else
static inline uint32_t load_le32(const void *_p)
{
	const unsigned char *p = _p;
	return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}

static inline uint16_t load_le16(const void *_p)
{
	const unsigned char *p = _p;
	return p[0] | (p[1] << 8);
}

static inline void store_le16(void *_p, uint16_t d)
{
	unsigned char *p = _p;
	p[0] = d;
	p[1] = d >> 8;
}

static inline void store_le32(void *_p, uint32_t d)
{
	unsigned char *p = _p;
	p[0] = d;
	p[1] = d >> 8;
	p[2] = d >> 16;
	p[3] = d >> 24;
}
#endif /* !Not known to be little-endian */

#endif /* __OPENCONNECT_INTERNAL_H__ */
