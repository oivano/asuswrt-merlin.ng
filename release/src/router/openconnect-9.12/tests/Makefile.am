
certsdir=$(srcdir)/certs

USER_KEYS = \
	$(certsdir)/user-key-pkcs1.pem $(certsdir)/user-key-pkcs1.der \
	$(certsdir)/user-key-pkcs1-aes128.pem \
	$(certsdir)/user-key-pkcs8.pem $(certsdir)/user-key-pkcs8.der \
	$(certsdir)/user-key-pkcs8-pbes1-sha1-3des.pem $(certsdir)/user-key-pkcs8-pbes1-sha1-3des.der \
	$(certsdir)/user-key-pkcs8-pbes2-sha1.pem $(certsdir)/user-key-pkcs8-pbes2-sha1.der \
	$(certsdir)/user-key-sha1-3des-sha1.p12 $(certsdir)/user-key-sha1-3des-sha256.p12 \
	$(certsdir)/user-key-aes256-cbc-sha256.p12

# We know GnuTLS doesn't support these for now. https://bugzilla.redhat.com/1369484
OSSL_KEYS = \
	$(certsdir)/user-key-md5-des-sha1.p12 $(certsdir)/user-key-aes256-cbc-md5-des-sha256.p12 \
	$(certsdir)/user-key-pkcs8-pbes2-sha256.pem $(certsdir)/user-key-pkcs8-pbes2-sha256.der \
	$(certsdir)/user-key-pkcs8-pbes1-md5-des.pem $(certsdir)/user-key-pkcs8-pbes1-md5-des.der
if OPENCONNECT_OPENSSL
USER_KEYS += $(OSSL_KEYS)
endif

DSA_KEYS = \
	$(certsdir)/dsa-key-pkcs1.pem $(certsdir)/dsa-key-pkcs1.der \
	$(certsdir)/dsa-key-pkcs1-aes128.pem \
	$(certsdir)/dsa-key-pkcs8.pem $(certsdir)/dsa-key-pkcs8.der \
	$(certsdir)/dsa-key-pkcs8-pbes2-sha1.pem $(certsdir)/dsa-key-pkcs8-pbes2-sha1.der \
	$(certsdir)/dsa-key-aes256-cbc-sha256.p12
if TEST_DSA
USER_KEYS += $(DSA_KEYS)
endif

USER_KEYS += $(certsdir)/ec-key-pkcs1.pem $(certsdir)/ec-key-pkcs1.der \
	$(certsdir)/ec-key-pkcs1-aes128.pem \
	$(certsdir)/ec-key-pkcs8.pem $(certsdir)/ec-key-pkcs8.der \
	$(certsdir)/ec-key-pkcs8-pbes2-sha1.pem $(certsdir)/ec-key-pkcs8-pbes2-sha1.der \
	$(certsdir)/ec-key-aes256-cbc-sha256.p12

SWTPM_KEYS = $(certsdir)/ec-key-swtpm.pem $(certsdir)/swtpm-rsa-key-tpm.pem \
	$(certsdir)/swtpm-ec-key-tpm.pem $(certsdir)/swtpm-ec-p384-key-tpm.pem

SWTPM_CERTS = $(certsdir)/swtpm-ec-cert.pem $(certsdir)/swtpm-rsa-cert.pem \
	$(certsdir)/swtpm-ec-p384-cert.pem

HWTPM_KEYS =
HWTPM_CERTS =

# Importing the existing EC key (not DSA since it's ancient and not RSA because
# the TPM probably can't cope with 2432-bit keys).
if TEST_TPM2_IMPORT
HWTPM_KEYS += ec-key-hwtpm.pem
endif

# Creating new keys in TPM.
if TEST_TPM2_CREATE
HWTPM_KEYS += hwtpm-ec-key-tpm.pem hwtpm-rsa-key-tpm.pem
HWTPM_CERTS += hwtpm-ec-cert.pem hwtpm-rsa-cert.pem
endif

USER_CERTS = $(certsdir)/user-cert.pem $(certsdir)/dsa-cert.pem $(certsdir)/ec-cert.pem

EXTRA_DIST = certs/ca.pem certs/ca-key.pem certs/user-cert.pem $(USER_KEYS) $(USER_CERTS) \
	$(OSSL_KEYS) $(DSA_KEYS) $(certsdir)/user-key-nonascii-password.p12 \
	pass-UTF-8 pass-ISO8859-2 $(SWTPM_KEYS) $(SWTPM_CERTS) swtpm-perm.state \
	certs/server-cert.pem certs/server-key.pem configs/test1.passwd \
	common.sh configs/test-user-cert.config.in \
	configs/test-user-pass.config.in \
	configs/test-obsolete-server-crypto.config \
	configs/user-cert.prm configs/server-cert.prm \
	softhsm2.conf.in softhsm ns.sh configs/test-dtls-psk.config \
	scripts/vpnc-script scripts/vpnc-script-detect-disconnect \
	suppressions.lsan fake-fortinet-server.py fake-f5-server.py fake-juniper-server.py \
	fake-juniper-sso-server.py fake-tncc.py fake-gp-server.py fake-cisco-server.py

dist_check_SCRIPTS = autocompletion symbols
TESTS = autocompletion symbols

dist_check_SCRIPTS += dtls-psk sigterm
if HAVE_NETNS
TESTS += dtls-psk sigterm
endif

dist_check_SCRIPTS += ppp-over-tls ppp-over-tls-sync
if TEST_PPP
TESTS += ppp-over-tls ppp-over-tls-sync
endif

dist_check_SCRIPTS += auth-username-pass auth-certificate auth-nonascii cert-fingerprint \
	id-test obsolete-server-crypto pfs auth-swtpm auth-hwtpm fortinet-auth-and-config \
	f5-auth-and-config juniper-auth juniper-sso-auth gp-auth-and-config auth-pkcs11 \
	auth-multicert

if HAVE_CWRAP
TESTS += auth-username-pass auth-certificate auth-nonascii cert-fingerprint id-test \
	obsolete-server-crypto pfs

if TEST_SWTPM
TESTS += auth-swtpm
# The rules for swtpm-perm.state are not invoked during normal builds since
# the files are already present in git.
auth-swtpm: swtpm-perm.state
endif

if TEST_HWTPM
# This is only invoked *manually* with 'make TESTS=auth-hwtpm check'.
TESTS += auth-hwtpm
# These files are generated locally against the real TPM.
auth-hwtpm: $(HWTPM_CERTS) $(HWTPM_KEYS)
endif

if HAVE_PYTHON36_FLASK
TESTS += juniper-sso-auth auth-multicert
if HAVE_PYTHON37_DATACLASSES
TESTS += juniper-auth gp-auth-and-config f5-auth-and-config fortinet-auth-and-config
endif
endif

if TEST_PKCS11
TESTS += auth-pkcs11

PKCS11_TOKENS = openconnect-test openconnect-test1

PKCS11_KEYS = object=RSA id=%01
# Neither GnuTLS or libp11 support this
#PKCS11_KEYS += object=DSA id=%02
PKCS11_KEYS += object=EC id=%03

if OPENCONNECT_GNUTLS
# We fail test2 because PKCS11_enumerate_certs() still doesn't seem to return
# the certs after we log in. Perhaps it's cached the results?
PKCS11_TOKENS += openconnect-test2
endif # OPENCONNECT_GNUTLS
if OPENCONNECT_OPENSSL
# GnuTLS build fails this one: https://gitlab.com/gnutls/gnutls/-/issues/977
PKCS11_TOKENS += openconnect-test3
endif # OPENCONNECT_OPENSSL
endif # TEST_PKCS11
endif # HAVE_CWRAP

TESTS_ENVIRONMENT = srcdir="$(srcdir)" \
	top_srcdir="$(top_srcdir)" \
	top_builddir="$(top_builddir)" \
	key_list="$(USER_KEYS)" \
	swtpm_list="$(SWTPM_KEYS)" \
	hwtpm_list="$(HWTPM_KEYS)" \
	SWTPM="$(SWTPM)" \
	SWTPM_IOCTL="$(SWTPM_IOCTL)" \
	pkcs11_keys="$(PKCS11_KEYS)" \
	pkcs11_tokens="$(PKCS11_TOKENS)" \
	EXEEXT=$(EXEEXT) \
	LSAN_OPTIONS=$(srcdir)/suppressions=suppressions.lsan

C_TESTS = lzstest seqtest buftest

if OPENCONNECT_WIN32
C_TESTS += list-taps
endif

if CHECK_DTLS
C_TESTS += bad_dtls_test
bad_dtls_test_SOURCES = bad_dtls_test.c
bad_dtls_test_CFLAGS = $(OPENSSL_CFLAGS)
bad_dtls_test_LDADD = $(OPENSSL_LIBS)

if DTLS_XFAIL
XFAIL_TESTS = bad_dtls_test
endif
endif

TESTS += $(C_TESTS)

noinst_PROGRAMS = $(C_TESTS) serverhash

serverhash_SOURCES = serverhash.c
serverhash_LDADD = ../libopenconnect.la $(SSL_LIBS)

# Nothing actually *depends* on the cert files; they are created manually
# and considered part of the sources, committed to the git tree. But for
# reference, the commands used to generate them are here...

keyfiles: $(USER_KEYS) $(USER_CERTS) $(certsdir)/server-cert.pem

OPENSSL = openssl
OSSLARGS = -in $(firstword $|) -out $@ -passout pass:password
OSSLARGSP12 = -inkey $(firstword $|) -out $@ -in $${KEYFILE%-key-pkcs8.pem}-cert.pem -passout pass:$${PASSWORD:-password}

# Strictly speaking this is only PKCS#1 for RSA. For EC it's probably
# best described as RFC5915§4, and no idea what defines it for DSA.
$(certsdir)/user-key-pkcs1.pem:
	$(OPENSSL) genrsa -out $@ 2432

$(certsdir)/dsa-key-pkcs1.pem:
	$(OPENSSL) dsaparam -genkey 1024 -out $@

$(certsdir)/ec-key-pkcs1.pem:
	$(OPENSSL) ecparam -genkey -out $@ -name prime256v1

# Even in OpenSSL 1.1, this creates the old encrypted PEM format.
$(certsdir)/user-key-pkcs1-aes128.pem: | certs/user-key-pkcs1.pem
	$(OPENSSL) rsa $(OSSLARGS) -aes128

$(certsdir)/dsa-key-pkcs1-aes128.pem: | certs/dsa-key-pkcs1.pem
	$(OPENSSL) dsa $(OSSLARGS) -aes128

$(certsdir)/ec-key-pkcs1-aes128.pem: | certs/ec-key-pkcs1.pem
	$(OPENSSL) ec $(OSSLARGS) -aes128

# Plain unencrypted PKCS#8
%-key-pkcs8.pem: | %-key-pkcs1.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -nocrypt

%-key-pkcs8-pbes1-sha1-3des.pem: | %-key-pkcs8.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -v1 pbeWithSHA1And3-KeyTripleDES-CBC

# This is the default created by OpenSSL 1.0.2 with -topk8
%-key-pkcs8-pbes1-md5-des.pem: | %-key-pkcs8.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -v1 pbeWithMD5AndDES-CBC

%-key-pkcs8-pbes2-sha1.pem: | %-key-pkcs8.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -v2 aes256 -v2prf hmacWithSHA1

# This is the default created by OpenSSL 1.1 with -topk8
%-key-pkcs8-pbes2-sha256.pem: | %-key-pkcs8.pem
	$(OPENSSL) pkcs8 $(OSSLARGS) -topk8 -v2 aes256 -v2prf hmacWithSHA256

%-key-sha1-3des-sha1.p12: | %-key-pkcs8.pem %-cert.pem
	KEYFILE="$(firstword $|)"; $(OPENSSL) pkcs12 $(OSSLARGSP12) -export -macalg SHA1 \
		-certpbe pbeWithSHA1And3-KeyTripleDES-CBC -keypbe pbeWithSHA1And3-KeyTripleDES-CBC

%-key-sha1-3des-sha256.p12: | %-key-pkcs8.pem %-cert.pem
	KEYFILE="$(firstword $|)"; $(OPENSSL) pkcs12 $(OSSLARGSP12) -export -macalg SHA256 \
		-certpbe pbeWithSHA1And3-KeyTripleDES-CBC -keypbe pbeWithSHA1And3-KeyTripleDES-CBC

%-key-md5-des-sha1.p12: | %-key-pkcs8.pem %-cert.pem
	KEYFILE="$(firstword $|)"; $(OPENSSL) pkcs12 $(OSSLARGSP12) -export -macalg SHA1 \
		-certpbe pbeWithMD5AndDES-CBC -keypbe pbeWithMD5AndDES-CBC

%-key-aes256-cbc-sha256.p12: | %-key-pkcs8.pem %-cert.pem
	KEYFILE="$(firstword $|)"; $(OPENSSL) pkcs12 $(OSSLARGSP12) -export -macalg SHA256 \
		-certpbe AES-256-CBC -keypbe AES-256-CBC

# NB: Needs OpenSSL 1.1 or newer
%-key-nonascii-password.p12: | %-key-pkcs8.pem %-cert.pem
	LC_ALL=en_GB.UTF-8 PASSWORD="$$(cat $(srcdir)/pass-UTF-8)" KEYFILE="$(firstword $|)" ; \
	$(OPENSSL) pkcs12 $(OSSLARGSP12) -export -macalg SHA256 \
		-certpbe AES-256-CBC -keypbe AES-256-CBC

# This one makes GnuTLS behave strangely...
%-key-aes256-cbc-md5-des-sha256.p12: | %-key-pkcs8.pem %-cert.pem
	KEYFILE="$(firstword $|)"; $(OPENSSL) pkcs12 $(OSSLARGSP12) -export -macalg SHA256 \
		-certpbe AES-256-CBC -keypbe pbeWithMD5AndDES-CBC

%.der: | %.pem
	sed -e '0,/^-----BEGIN.*KEY-----/d' -e '/^-----END.*KEY-----/,$$d' $| | base64 -d > $@

$(certsdir)/server-cert.pem:
	$(OPENSSL) req -new -config $(srcdir)/configs/server-cert.prm -key $(certsdir)/server-key.pem -out $@.csr
	$(OPENSSL) x509 -days 10000 -CA $(certsdir)/ca.pem -CAkey $(certsdir)/ca-key.pem \
		-extfile $(srcdir)/configs/server-cert.prm -extensions req_EXT \
		-set_serial $(shell date +%s) -req -out $@ -in $@.csr

$(certsdir)/ca.pem: | $(certsdir)/ca-key.pem
	openssl req -new -x509 -days 10000 -key $| -out $@ -config $(srcdir)/configs/ca.prm -extensions x509v3 -set_serial 1

# Like most of the rules to generate keys/certs, the swtpm rules are
# dormant for most builds; they were used once to generate the state
# which is committed to git and used thereafter (just like the cert
# files and the SoftHSM state). The rules here are to ensure that
# what gets committed was reproducible, and to document how it was
# created. So for swtpm, we need to:
#
#   • Start a new swtpm
#   • Import/create the keys
#   • Generate CSRs from the created keys
#   • Extract the swtpm state to 'swtpm-perm.state'
#   • Shut down the swtpm
#
# These rules attempt to do that, keeping variants of the existing
# CSR/cert generation rules for the middle parts.

SWTPM_TMPDIR := $(shell echo swtpm.$$$$.tmp)
SWTPM_PRELOAD := LD_PRELOAD=libsocket_wrapper.so SOCKET_WRAPPER_DIR=$(SWTPM_TMPDIR) \
	TPM_INTERFACE_TYPE=socsim TPM2TSSENGINE_TCTI=swtpm

SWTPM_IOCTL_RUN = $(SWTPM_PRELOAD) $(SWTPM_IOCTL) --tcp 127.0.0.1:2322

# This isn't safe for parallel builds, as it is invoked in mulltiple
# places and has an obvious race condition.  However, this is only for
# the one-time setup of the persistent swtpm state, and I can remember
# not to use 'make -j' that one time. Fixing it to be a proper
# separate 'tpm-started' phony rule without *always* having that rule
# executed even when the certs/keys already exist is beyond me today.
START_SWTPM := \
	mkdir -p $(SWTPM_TMPDIR); \
	if ! $(SWTPM_IOCTL_RUN) -g; then \
		if [ -r $(srcdir)/swtpm-perm.state ]; then \
			$(SWTPM_PRELOAD) $(SWTPM) socket --tpm2 \
				--server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
				--tpmstate dir=`pwd`/$(SWTPM_TMPDIR) -d; \
			sleep 0.5; \
			$(SWTPM_IOCTL_RUN) --load permanent $(srcdir)/swtpm-perm.state; \
			$(SWTPM_IOCTL_RUN) -i; \
			$(SWTPM_IOCTL_RUN) -s; \
		fi; \
		$(SWTPM_PRELOAD) $(SWTPM) socket --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 \
			--tpmstate dir=`pwd`/$(SWTPM_TMPDIR) --flags not-need-init,startup-clear -d; \
	fi

swtpm-perm.state: | $(SWTPM_KEYS) $(SWTPM_CERTS)
	$(SWTPM_IOCTL_RUN) --save permanent $@
	$(SWTPM_IOCTL_RUN) -s
	rm -rf $(SWTPM_TMPDIR)

# This is an *import* of the normal ec key, hence having same prefix 'ec-'.
# Separate fileames for swtpm (which is shipped with OpenConnect sources)
# vs local real TPM. Like many of the key/cert rules here, the swtpm rule
# is dormant and should never really be invoked for normal users once the
# files are committed to git. Which is why it doesn't matter that it needs
# the swtpm to have been started manually.

$(certsdir)/ec-key-swtpm.pem: | certs/ec-key-pkcs8.pem
	$(START_SWTPM)
	$(SWTPM_PRELOAD) $(CREATE_TPM2_KEY) -w $| $@

ec-key-hwtpm.pem: | certs/ec-key-pkcs8.pem
	TPM_INTERFACE_TYPE=dev $(CREATE_TPM2_KEY) -w $| $@

# These are *different* keys generated inside the TPM, hence a different prefix.
$(certsdir)/swtpm-ec-key-tpm.pem:
	$(START_SWTPM)
	$(SWTPM_PRELOAD) $(TPM2TSS_GENKEY) -t swtpm -a ecdsa $@

$(certsdir)/swtpm-ec-p384-key-tpm.pem:
	$(START_SWTPM)
	$(SWTPM_PRELOAD) $(TPM2TSS_GENKEY) -t swtpm -c nist_p384 -a ecdsa $@

hwtpm-ec-key-tpm.pem:
	$(TPM2TSS_GENKEY) -t device -a ecdsa $@

$(certsdir)/swtpm-rsa-key-tpm.pem:
	$(START_SWTPM)
	$(SWTPM_PRELOAD) $(TPM2TSS_GENKEY) -t swtpm -a rsa -s 2048 $@

hwtpm-rsa-key-tpm.pem:
	$(TPM2TSS_GENKEY) -t device -a rsa -s 2048 $@

$(certsdir)/swtpm-%-cert.csr: | $(certsdir)/swtpm-%-key-tpm.pem
	$(START_SWTPM)
	$(SWTPM_PRELOAD) $(OPENSSL) req -new -config $(srcdir)/configs/user-cert.prm -engine tpm2tss -keyform ENGINE -key $| -out $@

hwtpm-%-cert.csr: | hwtpm-%-key-tpm.pem
	TPM2TSSENGINE_TCTI=device $(OPENSSL) req -new -config $(srcdir)/configs/user-cert.prm -engine tpm2tss -keyform ENGINE -key $| -out $@

%-cert.csr: | %-key-hwtpm.pem
	TPM2TSSENGINE_TCTI=device $(OPENSSL) req -new -config $(srcdir)/configs/user-cert.prm -engine tpm2tss -keyform ENGINE -key $| -out $@

%-cert.csr: | %-key-pkcs8.pem
	$(OPENSSL) req -new -config $(srcdir)/configs/user-cert.prm -key $| -out $@

%.pem: | %.csr
	$(OPENSSL) x509 -days 10000 -CA $(certsdir)/ca.pem -CAkey $(certsdir)/ca-key.pem \
		-set_serial $(shell date +%s) -req -out $@ -in $|

SHM2_UTIL=SOFTHSM2_CONF=softhsm2.conf softhsm2-util
P11TOOL=SOFTHSM2_CONF=softhsm2.conf p11tool

# Nice and simple: Certs visible without login, public keys present in token
softhsm-setup0:
	$(SHM2_UTIL) --show-slots
	$(SHM2_UTIL) --init-token --free --label openconnect-test \
		--so-pin 12345678 --pin 1234

	$(SHM2_UTIL) --token openconnect-test --pin 1234 --import $(certsdir)/user-key-pkcs8.pem \
		--label RSA --id 01
	$(P11TOOL) --load-certificate $(certsdir)/user-cert.pem --no-mark-private \
		   --label RSA --id 01 --set-pin 1234 --login \
		   --write "pkcs11:token=openconnect-test;pin-value=1234"

	$(SHM2_UTIL) --token openconnect-test --pin 1234 --import $(certsdir)/dsa-key-pkcs8.pem \
		--label DSA --id 02
	$(P11TOOL) --load-certificate $(certsdir)/dsa-cert.pem --no-mark-private \
		   --label DSA --id 02 --set-pin 1234 --login \
		   --write "pkcs11:token=openconnect-test;pin-value=1234"

	$(SHM2_UTIL) --token openconnect-test --pin 1234 --import $(certsdir)/ec-key-pkcs8.pem \
			--label EC --id 03
	$(P11TOOL) --load-certificate $(certsdir)/ec-cert.pem --no-mark-private \
		   --label EC --id 03 --set-pin 1234 --login \
		   --write "pkcs11:token=openconnect-test;pin-value=1234"

# Second test: Import keys with GnuTLS so public key is absent
softhsm-setup1:
	$(SHM2_UTIL) --show-slots
	$(SHM2_UTIL) --init-token --free --label openconnect-test1 \
		--so-pin 12345678 --pin 1234

	$(P11TOOL) --load-certificate $(certsdir)/user-cert.pem --no-mark-private \
		   --load-privkey $(certsdir)/user-key-pkcs8.pem \
		   --label RSA --id 01 --login \
		   --write "pkcs11:token=openconnect-test1;pin-value=1234"

	$(P11TOOL) --load-certificate $(certsdir)/dsa-cert.pem --no-mark-private \
		   --load-privkey $(certsdir)/dsa-key-pkcs8.pem \
		   --label DSA --id 02 --login \
		   --write "pkcs11:token=openconnect-test1;pin-value=1234"

	$(P11TOOL) --load-certificate $(certsdir)/ec-cert.pem --no-mark-private \
		   --load-privkey $(certsdir)/ec-key-pkcs8.pem \
		   --label EC --id 03 --login \
		   --write "pkcs11:token=openconnect-test1;pin-value=1234"

# Third test: CKA_PRIVATE on certificates
softhsm-setup2:
	$(SHM2_UTIL) --show-slots
	$(SHM2_UTIL) --init-token --free --label openconnect-test2 \
		--so-pin 12345678 --pin 1234

	$(P11TOOL) --load-certificate $(certsdir)/user-cert.pem \
		   --load-privkey $(certsdir)/user-key-pkcs8.pem \
		   --label RSA --id 01 --login \
		   --write "pkcs11:token=openconnect-test2;pin-value=1234"

	$(P11TOOL) --load-certificate $(certsdir)/dsa-cert.pem \
		   --load-privkey $(certsdir)/dsa-key-pkcs8.pem \
		   --label DSA --id 02 --login \
		   --write "pkcs11:token=openconnect-test2;pin-value=1234"

	$(P11TOOL) --load-certificate $(certsdir)/ec-cert.pem \
		   --load-privkey $(certsdir)/ec-key-pkcs8.pem \
		   --label EC --id 03 --login \
		   --write "pkcs11:token=openconnect-test2;pin-value=1234"

# Fourth test: token lacks CKF_LOGIN_REQUIRED (#123)
softhsm-setup3:
	$(SHM2_UTIL) --show-slots
	$(SHM2_UTIL) --init-token --free --label openconnect-test3 \
		--so-pin 12345678 --pin 1234

# Remove the CKF_LOGIN_REQUIRED flag
	TOKOBJ=$$(grep -l openconnect-test3 $(srcdir)/softhsm/*/token.object); \
	if [ -n "$$TOKOBJ" ] && od -t x1 $$TOKOBJ | grep -q '^0000160.* 04 2d$$'; then \
		echo -en \\x29 | dd bs=1 count=1 conv=notrunc seek=127 of=$$TOKOBJ; \
	else \
		echo "Token file not understood"; \
		exit 1; \
	fi

	$(P11TOOL) --load-certificate $(certsdir)/user-cert.pem \
		   --load-privkey $(certsdir)/user-key-pkcs8.pem \
		   --label RSA --id 01 --login \
		   --write "pkcs11:token=openconnect-test3;pin-value=1234"

	$(P11TOOL) --load-certificate $(certsdir)/dsa-cert.pem \
		   --load-privkey $(certsdir)/dsa-key-pkcs8.pem \
		   --label DSA --id 02 --login \
		   --write "pkcs11:token=openconnect-test3;pin-value=1234"

	$(P11TOOL) --load-certificate $(certsdir)/ec-cert.pem \
		   --load-privkey $(certsdir)/ec-key-pkcs8.pem \
		   --label EC --id 03 --login \
		   --write "pkcs11:token=openconnect-test3;pin-value=1234"

if DISABLE_ASAN_BROKEN_TESTS
TESTS_ENVIRONMENT += DISABLE_ASAN_BROKEN_TESTS=1
else
TESTS_ENVIRONMENT += DISABLE_ASAN_BROKEN_TESTS=0
endif
