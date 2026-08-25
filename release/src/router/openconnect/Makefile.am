SUBDIRS = tests
# We kind of want openconnect to be built before we try to test it
# We also want to have wintun library when running wintun tests, if applicable
check-recursive: openconnect$(EXEEXT) $(WINTUN_DLL)
# And even *building* some of tests/*.c needs libopenconnect
install-recursive: libopenconnect.la
all-recursive: libopenconnect.la

if BUILD_WWW
SUBDIRS += www
endif
if USE_NLS
SUBDIRS += po
endif
if BUILD_NSIS
noinst_DATA = openconnect-installer-$(INSTALLER_SUFFIX).exe
endif

lib_LTLIBRARIES = libopenconnect.la
sbin_PROGRAMS = openconnect
man8_MANS = openconnect.8
bin_PROGRAMS :=
sbin_SCRIPTS :=
noinst_PROGRAMS :=

AM_CFLAGS = @WFLAGS@
AM_CPPFLAGS = -DLOCALEDIR="\"$(localedir)\""

openconnect_SOURCES = xml.c main.c
openconnect_CFLAGS = $(AM_CFLAGS) $(SSL_CFLAGS) $(DTLS_SSL_CFLAGS) \
	$(LIBXML2_CFLAGS) $(JSON_CFLAGS) $(LIBPROXY_CFLAGS) \
	$(ZLIB_CFLAGS) $(LIBSTOKEN_CFLAGS) $(LIBPSKC_CFLAGS) \
	$(GSSAPI_CFLAGS) $(INTL_CFLAGS) $(ICONV_CFLAGS) \
	$(LIBPCSCLITE_CFLAGS)
openconnect_LDADD = libopenconnect.la $(SSL_LIBS) $(LIBXML2_LIBS) \
	$(LIBPROXY_LIBS) $(INTL_LIBS) $(ICONV_LIBS)

if OPENCONNECT_WIN32
openconnect_SOURCES += openconnect.rc
sbin_SCRIPTS += vpnc-script-win.js
endif
library_srcs = ssl.c http.c textbuf.c http-auth.c auth-common.c \
	auth-html.c library.c compat.c lzs.c mainloop.c script.c \
	ntlm.c digest.c mtucalc.c openconnect-internal.h
lib_srcs_cisco = auth.c cstp.c hpke.c multicert.c
lib_srcs_juniper = oncp.c lzo.c auth-juniper.c
lib_srcs_pulse = pulse.c
lib_srcs_globalprotect = gpst.c win32-ipicmp.h auth-globalprotect.c
lib_srcs_array = array.c
lib_srcs_oath = oath.c
lib_srcs_oidc = oidc.c
lib_srcs_ppp = ppp.c ppp.h
lib_srcs_nullppp = nullppp.c
lib_srcs_f5 = f5.c
lib_srcs_fortinet = fortinet.c
lib_srcs_json = jsondump.c

library_srcs += $(lib_srcs_juniper) $(lib_srcs_cisco) $(lib_srcs_oath) \
		$(lib_srcs_globalprotect) $(lib_srcs_pulse) \
		$(lib_srcs_oidc) $(lib_srcs_ppp) $(lib_srcs_nullppp) \
		$(lib_srcs_f5) $(lib_srcs_fortinet) $(lib_srcs_json) \
		$(lib_srcs_array)

lib_srcs_gnutls = gnutls.c gnutls_tpm.c gnutls_tpm2.c
lib_srcs_openssl = openssl.c openssl-pkcs11.c
lib_srcs_win32 = wintun.c tun-win32.c sspi.c wintun.h
lib_srcs_posix = tun.c
lib_srcs_gssapi = gssapi.c
lib_srcs_iconv = iconv.c
lib_srcs_yubikey = yubikey.c
lib_srcs_stoken = stoken.c
lib_srcs_esp = esp.c esp-seqno.c
lib_srcs_dtls = dtls.c
lib_srcs_vhost = vhost.c

POTFILES = $(openconnect_SOURCES) gnutls-esp.c gnutls-dtls.c openssl-esp.c openssl-dtls.c \
	   $(lib_srcs_esp) $(lib_srcs_dtls) gnutls_tpm2_esys.c gnutls_tpm2_ibm.c \
	   $(lib_srcs_openssl) $(lib_srcs_gnutls) $(library_srcs) \
	   $(lib_srcs_win32) $(lib_srcs_posix) $(lib_srcs_gssapi) $(lib_srcs_iconv) \
	   $(lib_srcs_yubikey) $(lib_srcs_stoken) $(lib_srcs_oidc) $(lib_srcs_vhost)

if OPENCONNECT_VHOST
library_srcs += $(lib_srcs_vhost)
endif
if OPENCONNECT_LIBPCSCLITE
library_srcs += $(lib_srcs_yubikey)
endif
if OPENCONNECT_STOKEN
library_srcs += $(lib_srcs_stoken)
endif
if OPENCONNECT_GSSAPI
library_srcs += $(lib_srcs_gssapi)
endif
if OPENCONNECT_GNUTLS
library_srcs += $(lib_srcs_gnutls)
lib_srcs_esp += gnutls-esp.c
lib_srcs_dtls += gnutls-dtls.c
endif
if OPENCONNECT_TSS2_ESYS
library_srcs += gnutls_tpm2_esys.c
endif
if OPENCONNECT_TSS2_IBM
library_srcs += gnutls_tpm2_ibm.c
endif
if OPENCONNECT_OPENSSL
library_srcs += $(lib_srcs_openssl)
lib_srcs_esp += openssl-esp.c
lib_srcs_dtls += openssl-dtls.c
endif
if OPENCONNECT_DTLS
lib_srcs_cisco += $(lib_srcs_dtls)
endif
if OPENCONNECT_ESP
lib_srcs_juniper += $(lib_srcs_esp)
endif
if OPENCONNECT_ICONV
library_srcs += $(lib_srcs_iconv)
endif
if BUILTIN_JSON
library_srcs += json/json.c json/json.h
endif
if OPENCONNECT_WIN32
library_srcs += $(lib_srcs_win32)
.rc.o:
	$(WINDRES) $^ -o $@
%.o : %.rc
	$(WINDRES) $^ -o $@
else
library_srcs += $(lib_srcs_posix)
endif


libopenconnect_la_SOURCES = version.c $(library_srcs)
libopenconnect_la_CFLAGS = $(AM_CFLAGS) $(SSL_CFLAGS) $(DTLS_SSL_CFLAGS) \
	$(LIBXML2_CFLAGS) $(JSON_CFLAGS) $(LIBPROXY_CFLAGS) $(ZLIB_CFLAGS) \
	$(P11KIT_CFLAGS) $(TSS_CFLAGS) $(LIBSTOKEN_CFLAGS) $(LIBPSKC_CFLAGS) \
	$(GSSAPI_CFLAGS) $(INTL_CFLAGS) $(ICONV_CFLAGS) $(LIBPCSCLITE_CFLAGS) \
	$(LIBP11_CFLAGS) $(LIBLZ4_CFLAGS)
libopenconnect_la_LIBADD = $(SSL_LIBS) $(DTLS_SSL_LIBS) \
	$(LIBXML2_LIBS) $(LIBPROXY_LIBS) $(ZLIB_LIBS) $(P11KIT_LIBS) \
	$(TSS_LIBS) $(LIBSTOKEN_LIBS) $(LIBPSKC_LIBS) $(GSSAPI_LIBS) \
	$(INTL_LIBS) $(ICONV_LIBS) $(LIBPCSCLITE_LIBS) $(LIBP11_LIBS)\
	$(LIBLZ4_LIBS) ${JSON_LIBS}

if OPENBSD_LIBTOOL
# OpenBSD's libtool doesn't have -version-number, but its -version-info arg
# does what GNU libtool's -version-number does. Which arguably is what the
# GNU -version-info arg ought to do too. I hate libtool.
LT_VER_ARG = -version-info
else
LT_VER_ARG = -version-number
endif
libopenconnect_la_LDFLAGS = $(LT_VER_ARG) @APIMAJOR@:@APIMINOR@ -no-undefined
noinst_HEADERS = openconnect-internal.h openconnect.h gnutls.h lzo.h
include_HEADERS = openconnect.h
if HAVE_VSCRIPT
libopenconnect_la_LDFLAGS += @VSCRIPT_LDFLAGS@,libopenconnect.map
libopenconnect_la_DEPENDENCIES = libopenconnect.map
endif

if OPENCONNECT_JNI
if JNI_STANDALONE
libopenconnect_la_SOURCES += jni.c
libopenconnect_la_CFLAGS += $(JNI_CFLAGS) -Wno-missing-declarations
else
lib_LTLIBRARIES += libopenconnect-wrapper.la
libopenconnect_wrapper_la_SOURCES = jni.c
libopenconnect_wrapper_la_CFLAGS = $(AM_CFLAGS) $(JNI_CFLAGS) -Wno-missing-declarations
libopenconnect_wrapper_la_LIBADD = libopenconnect.la
endif
endif

if OPENCONNECT_SYSTEM_KEYS
if OPENCONNECT_WIN32
#install list-system-keys on Windows
bin_PROGRAMS += list-system-keys
else
#Don't install list-system-keys
#It breaks the Linux COPR builds since the native RPM doesn't list it as
#one of the files that are expected to be installed.
#see commit 17887b53e171ec7223340092dc042298a29defb0
noinst_PROGRAMS += list-system-keys
endif #OPENCONNECT_WIN32
list_system_keys_SOURCES = list-system-keys.c
list_system_keys_CFLAGS = $(GNUTLS_CFLAGS)
list_system_keys_LDADD = $(GNUTLS_LIBS)
endif

if !OPENCONNECT_WIN32
noinst_PROGRAMS += os-tcp-mtu
os_tcp_mtu_SOURCES = os-tcp-mtu.c
endif

pkgconfig_DATA = openconnect.pc

EXTRA_DIST = AUTHORS version.sh COPYING.LGPL openconnect.ico $(POTFILES) openconnect.nsi.in
EXTRA_DIST += json/AUTHORS json/LICENSE json/json.c json/json.h libopenconnect5.symbols gensymbols.sed
EXTRA_DIST += $(shell cd "$(top_srcdir)" && \
		git ls-tree HEAD -r --name-only -- android/ java/ trojans/ bash/ 2>/dev/null)
EXTRA_DIST += Makefile.dlldeps

DISTCLEANFILES = $(pkgconfig_DATA) version.c

pkglibexec_SCRIPTS = trojans/csd-post.sh trojans/csd-wrapper.sh trojans/tncc-wrapper.py \
	trojans/hipreport.sh trojans/hipreport-android.sh trojans/tncc-emulate.py

bashcompletiondir = $(datadir)/bash-completion/completions
bashcompletion_DATA = bash/openconnect

# main.c includes version.c
openconnect-main.$(OBJEXT): version.c

version.c: $(library_srcs) $(lib_openssl_srcs) $(lib_gnutls_srcs) \
	   $(openconnect_SOURCES) Makefile.am configure.ac \
	   openconnect.h openconnect-internal.h version.sh @GITVERSIONDEPS@
	@cd $(srcdir) && ./version.sh $(abs_builddir)/version.c

AUTHORS: @GITVERSIONDEPS@
	@git shortlog -sen > AUTHORS

tmp-dist: uncommitted-check
	$(MAKE) $(AM_MAKEFLAGS) VERSION=$(patsubst v%,%,$(shell git describe --tags)) DISTHOOK=0 dist

tmp-distdir: uncommitted-check
	$(MAKE) $(AM_MAKEFLAGS) VERSION=$(patsubst v%,%,$(shell git describe --tags)) DISTHOOK=0 distdir

uncommitted-check:
	@if ! git update-index --refresh --unmerged || \
	    ! git diff-index --name-only --exit-code HEAD; then \
		echo "*** ERROR: Uncommitted changes in above files"; exit 1; fi

DISTHOOK=1
dist-hook: uncommitted-check
	@if [ $(DISTHOOK) = 1 ]; then \
	    if ! git rev-parse --verify v$(VERSION) &> /dev/null; then \
		echo "*** ERROR: Version v$(VERSION) is not tagged"; exit 1; fi ; \
	    if ! git diff --name-only --exit-code v$(VERSION) HEAD > /dev/null; then \
		echo "*** ERROR: Git checkout not at version v$(VERSION)"; exit 1; fi ; \
	fi

sign-dist: dist
	@for a in $(DIST_ARCHIVES); do \
		gpg --default-key 67E2F359 --detach-sign -a $$a ; \
	done

tag: uncommitted-check
	@if git rev-parse --verify v$(VERSION) &> /dev/null; then \
		echo "*** ERROR: Version v$(VERSION) is already tagged"; exit 1; fi
	@sed 's/AC_INIT.*/AC_INIT([openconnect], [$(VERSION)])/' -i $(srcdir)/configure.ac
	@sed 's/^v=.*/v="v$(VERSION)"/' -i $(srcdir)/version.sh
	@( echo '1,/<!-- latest-release-start -->/p' ;\
	   echo '/<!-- latest-release-end -->/,$$p' ;\
	   echo  '/<!-- latest-release-start -->/a\' ;\
	   echo  'The latest release is <a href="https://www.infradead.org/openconnect/download/openconnect-$(VERSION).tar.gz">OpenConnect v$(VERSION)</a>\' ;\
	   echo  '<i>(<a href="https://www.infradead.org/openconnect/download/openconnect-$(VERSION).tar.gz.asc">PGP signature</a>)</i>,\' ;\
	   echo 'released on $(shell date +%Y-%m-%d) with the following changelog:</p>\' ;\
	   sed '0,/<b>OpenConnect HEAD/d;/<\/ul><br\/>/,$$d;s/$$/\\/' $(srcdir)/www/changelog.xml ;\
	   echo '     </ul>' ) | \
	 sed -n -f - -i $(srcdir)/www/download.xml
	@( echo "s/Last modified: .*/Last modified: $(shell date)/" ;\
	   echo '/  <li><b>OpenConnect HEAD/a\' ;\
	   echo '     <ul>\' ;\
	   echo '       <li><i>No changelog entries yet</i></li>\';\
	   echo '     </ul><br/>\' ;  echo '  </li>\' ;\
	   echo '  <li><b><a href="https://www.infradead.org/openconnect/download/openconnect-$(VERSION).tar.gz">OpenConnect v$(VERSION)</a></b>\' ;\
	   echo '     <i>(<a href="https://www.infradead.org/openconnect/download/openconnect-$(VERSION).tar.gz.asc">PGP signature</a>)</i> &#8212; $(shell date +%Y-%m-%d)' ) | \
		sed -f - -i $(srcdir)/www/changelog.xml
	@echo '/API version [0-9]\+\.[0-9]\+:$$/s/:/ (v$(VERSION); $(shell date +%Y-%m-%d)):/' | \
		sed -f - -i $(srcdir)/openconnect.h
	@sed -Enf $(srcdir)/gensymbols.sed $(srcdir)/openconnect.h | \
	  sed -Enf- $(srcdir)/libopenconnect.map.in > $(srcdir)/libopenconnect5.symbols
# stupid syntax highlighting '
	@cd $(srcdir) && git commit -s -m "Tag version $(VERSION)" configure.ac version.sh www/download.xml www/changelog.xml openconnect.h libopenconnect5.symbols
	@git tag v$(VERSION)
	@cd $(srcdir) && ./autogen.sh


###########################################################################
#
# Translations are handled in the NetworkManager-openconnect repository by
# GNOME translation teams. We export all our translatable strings to a file
# 'openconnect-strings.txt' which is included in their set of files to be
# translated.
#
# We have an 'import-strings' make target which, for each translation, does
# a merge of their file with ours and compares with a canonicalised version
# of ours to see if there are any substantive changes. The strings from
# NetworkManager-openconnect take precedence over ours, so if there are
# any *corrections* to translations they need to be applied there first,
# because changes in openconnect to a string which is already translated
# in NetworkManager-openconnect will get overwritten on the next sync.
#
# Given that precedence, the 'export-strings' target is mostly only useful
# when we add *new* strings which already have translations, which happens
# occasionally when we change a non-translated part of a string (e.g. when
# we recently replaced URLs and email addresses with '%s' and could do that
# without 'losing' the existing translations by changing those too).
#
# A decent guess at where NetworkManager-openconnect might be checked out...
NMO_DIR := $(srcdir)/../NetworkManager-openconnect
NMO_POT := $(NMO_DIR)/po/NetworkManager-openconnect.pot
NMO_STRINGS := $(NMO_DIR)/openconnect-strings.txt

NMO_LINGUAS = $(wildcard $(NMO_DIR)/po/*.po)
OC_LINGUAS = $(shell grep -v ^\# $(srcdir)/po/LINGUAS)

# Generate the openconnect-strings.txt file in the NetworkManager-openconnect
# repository, which 'injects' our strings there to be translated.
$(NMO_STRINGS): po/$(PACKAGE).pot uncommitted-check
	$(srcdir)/export-strings.sh $@ $<

.PHONY: $(NMO_POT)
$(NMO_POT): $(NMO_STRINGS)
	make -C $(NMO_DIR)/po NetworkManager-openconnect.pot

# Sync translations from our own po/ directory to NetworkManager-openconnect,
# with theirs taking precedence. Use a strange path with extra 'po/..' to
# avoid circular dependencies.
$(NMO_DIR)/po/../po/%.po: $(srcdir)/po/%.po $(NMO_POT) po/$(PACKAGE).pot
	@msgattrib -F --no-fuzzy $< > $@.openconnect
# Merge using local strings as additional compendium
	@msgmerge -q -N -F $@ -C $@.openconnect ${NMO_POT} > $@.merged
# Dummy merge (cleanup) for comparison.
	@msgmerge -q -N -F $@ ${NMO_POT} > $@.unmerged
# If the result is different, update the NM version.
	@if ! cmp $@.merged $@.unmerged; then \
		echo "New changes for NetworkManager-openconnect $(notdir $@)"; \
		mv $@.merged $@; \
	else \
		echo "No changes for NetworkManager-openconnect $(notdir $@)"; \
	fi
	@rm -f $@.openconnect $@.merged $@.unmerged

# Sync translations from NetworkManager-openconnect, with theirs taking
# precedence.
$(srcdir)/po/../po/%.po: $(NMO_DIR)/po/%.po $(NMO_POT) po/$(PACKAGE).pot
	@msgattrib -F --no-fuzzy $< > $@.nmo
# Merge NM against openconnect.pot, using local strings as additional compendium
	@msgmerge -q -N -C $@ -F $@.nmo po/$(PACKAGE).pot > $@.merged1
# Remove fuzzy and obsolete translations
	@msgattrib -F --no-fuzzy --no-obsolete $@.merged1 > $@.merged2
# Unmerged, clean up for simple comparison
	@msgmerge -q -N -F $@ po/$(PACKAGE).pot > $@.unmerged
	@if ! cmp $@.merged2 $@.unmerged; then \
		echo "New changes for $(notdir $@)"; \
		mv $@.merged2 $@; \
	else \
		echo "No changes for $(notdir $@)"; \
	fi
	@rm -f $@.nmo $@.merged1 $@.merged2 $@.unmerged

# Import translated strings from NetworkManager-openconnect
import-strings: $(patsubst $(NMO_DIR)/%,$(srcdir)/po/../%,$(NMO_LINGUAS))
	if ! git update-index -q --refresh --unmerged || \
	   ! git diff-index --name-only --exit-code HEAD -- $(srcdir)/po/ >/dev/null; then \
		git commit -s -m "Import translations from GNOME" -- $(srcdir)/po/ ; \
	else \
		echo No changes to commit ; \
	fi

# Export our translatable strings to NetworkManager-openconnect
export-strings: $(patsubst $(NMO_DIR)/%,$(NMO_DIR)/po/../%,$(NMO_LINGUAS))

# Just resync the translation comments to reflect accurate line numbers, etc.
update-po: po/$(PACKAGE).pot
	@cd $(top_srcdir); if ! git diff-index --name-only --exit-code HEAD -- po/; then \
		echo "*** ERROR: Uncommitted changes in above files"; exit 1; \
	else \
		> po/LINGUAS; \
		for a in po/*.po; do \
			msgmerge -q -N -F $$a $(abs_builddir)/po/$(PACKAGE).pot > $$a.merge ; \
			msgattrib -F --no-fuzzy --no-obsolete $$a.merge > $$a ; \
			rm $$a.merge ; \
			if msgattrib --translated $$a | grep -q msgstr; then \
				echo $$a | sed 's%^po/\(.*\)\.po%\1%' >> po/LINGUAS ; \
			fi ; \
		done && \
		if ! git update-index -q --refresh --unmerged || \
		   ! git diff-index --name-only --exit-code HEAD -- po/ >/dev/null; then \
			git commit -s -m "Resync translations with sources" -- po/ ; \
		else \
			echo No changes to commit ; \
		fi; \
	fi

po/$(PACKAGE).pot: $(POTFILES) version.sh
	@echo "Regenerating $@" ; rm -f $@ && \
	xgettext --directory=$(top_srcdir) --from-code=UTF-8 \
	  --sort-by-file --add-comments --keyword=_ --keyword=N_ \
	  --package-name="@PACKAGE@" --package-version="@VERSION@" \
	  --msgid-bugs-address=openconnect-devel@lists.infradead.org \
	  -o $@ $(POTFILES)

ACLOCAL_AMFLAGS = -I m4

if BUILD_NSIS
DISTCLEANFILES += .*.dll.d .*.exe.d file-list*.txt instfiles.nsh uninstfiles.nsh vpnc-script-win.js openconnect.nsi openconnect-installer-*.exe

# Including openconnect-gui.exe and Qt bits (as a hack)
#EXTRA_EXECUTABLES := openconnect-gui.exe qwindows.dll qwindowsvistastyle.dll
#EXTRA_NSIS_FILES := $(OPENCONNECT_GUI_DIR)/nsis/qt.conf
#EXTRA_DLLDIRS := $(OPENCONNECT_GUI_DIR)/bin $(libdir)/qt5/plugins/platforms $(libdir)/qt5/plugins/styles

DLL_EXECUTABLES := openconnect$(EXEEXT) $(EXTRA_EXECUTABLES)
endif

if OPENCONNECT_WINTUN
WINTUN_DLL = .libs/wintun.dll
DISTCLEANFILES += $(WINTUN_DLL)
sbin_SCRIPTS += .libs/wintun.dll
if BUILD_NSIS
DLL_EXECUTABLES += wintun.dll
endif
endif

if BUILD_NSIS
if OPENCONNECT_SYSTEM_KEYS
DLL_EXECUTABLES += list-system-keys$(EXEEXT)
endif

# DLL dependencies are found recursively with make, with each .foo.dll.d being
# generated automatically from foo.dll by a pattern rule. However, we don't
# want the normal top-level Makefile doing that directly because it would try
# to do so *every* time it's invoked, just because of the -include directives.
# So we split it out to a *separate* Makefile.dlldeps to be invoked only when
# we are actually building the NSIS installer.
#
# The 'file-list.txt' contains the full transitive list of executables and
# DLLs to be included in the installer. It potentially needs to be rebuilt if
# any of them change (as they may now link against a different set of DLLs),
# and *that* much does need to be visible to this top-level Makefile, so
# include them if they exist.
-include $(patsubst %,.%.d,$(DLL_EXECUTABLES))

export V AM_DEFAULT_VERBOSITY bindir libdir OBJDUMP DLL_EXECUTABLES EXTRA_DLLDIRS

file-list.txt: Makefile.dlldeps openconnect$(EXEEXT) libopenconnect.la $(WINTUN_DLL)
	@$(MAKE) --no-print-directory -f $< $@
endif #BUILD_NSIS

# Wintun Layer 3 TUN driver for Windows 7 and newer
# (see https://wintun.net)
WINTUNDRIVER = wintun-0.14.1.zip
WINTUNSHA256 = 07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51

$(WINTUNDRIVER):
	( test -f "/opt/$(WINTUNDRIVER)" && cp "/opt/$(WINTUNDRIVER)" ./ ) || curl https://www.wintun.net/builds/$(WINTUNDRIVER) -o $@

.libs/wintun.dll: $(WINTUNDRIVER)
	echo $(WINTUNSHA256) $< | sha256sum -c
	unzip -DD -o -j -d .libs $< wintun/bin/$(WINTUN_ARCH)/wintun.dll

# Latest vpnc-script-win.js, annotated with a header documenting the
# exact source revision.
vpnc-script-win.js:
	curl 'https://gitlab.com/api/v4/projects/openconnect%2Fvpnc-scripts/repository/commits?path=vpnc-script-win.js&branch=master' | \
	    jq -r '.[0] | "// This script matches the version found at " + (.web_url | sub("/commit/"; "/blob/")) + "/vpnc-script-win.js\n// Updated on " + .authored_date[:10] + " by " + .author_name + " <" + .author_email + "> (\"" + .title + "\")\n//"' > $@
	curl https://gitlab.com/openconnect/vpnc-scripts/raw/master/vpnc-script-win.js >> $@

if BUILD_NSIS
# Let make find the file in VPATH
file-list-%.txt: %
	echo $< > $@

file-list-extra.txt:
	$(AM_V_GEN) for f in $(EXTRA_NSIS_FILES); do echo "$${f}" ; done > $@

# Rather than trying to get clever in NSIS and iterate over lists,
# just emit raw snippets to be included separately in the install
# and uninstall sections.
instfiles.nsh: file-list.txt file-list-vpnc-script-win.js.txt file-list-extra.txt
	$(AM_V_GEN) ( for f in `grep -hv "^$(libdir)/qt5/plugins" $^`; do g=`$(CYGPATH_W) $$f`; echo File \"$$g\"; done; \
	grep -h "^$(libdir)/qt5/plugins" $^ | sed 's%\(.*/qt5/plugins\)/\([^/]*\)/\([^/]*\)%SetOutPath "$$INSTDIR\\\\\2"\nFile "\1/\2/\3"%' ) > $@

uninstfiles.nsh: file-list.txt file-list-vpnc-script-win.js.txt file-list-extra.txt
	$(AM_V_GEN) ( grep -hv "^$(libdir)/qt5/plugins" $^ | sed 's%\(.*/\)\?\([^/]*\)%Delete /rebootok "$$INSTDIR\\\\\2"%' ; \
	grep -h "^$(libdir)/qt5/plugins" $^ | sed 's%.*/qt5/plugins/\([^/]*\)/\([^/]*\)%Delete /rebootok "$$INSTDIR\\\\\1\\\\\2"\nRMDir "$$INSTDIR\\\\\1"%' ) > $@

# Theoretically makensis can define symbols with the -D command line
# option and much of this could just be done that way, but I couldn't
# get it to work and life's too short.
openconnect.nsi: version.c
	$(AM_V_GEN) VERSION=$$(cut -f2 -d\" version.c); \
	PROD_VERSION=$$(echo "$$VERSION" | perl -ne 'm|v(\d+)\.(\d+)(?:\.git\.\|\-)?(\d+)?(?:-g.+\|.*)|; printf("%1d.%1d.%1d.0",$$1,$$2,$$3)'); \
	if grep -E -q '^#define OPENCONNECT_GNUTLS' config.h; then \
	    TLS_LIBRARY=GnuTLS; \
	elif grep -E -q '^#define OPENCONNECT_OPENSSL' config.h; then \
	    TLS_LIBRARY=OpenSSL; \
	else \
	    TLS_LIBRARY="Unknown_TLS_library"; \
	fi; \
	INSTALLER_NAME="openconnect-installer-$(INSTALLER_SUFFIX)-$${VERSION}.exe"; \
	( echo "VIProductVersion \"$$PROD_VERSION\""; \
	  echo "VIAddVersionKey ProductVersion \"$$VERSION\""; \
	  echo "VIAddVersionKey Comments \"OpenConnect multi-protocol VPN client for Windows (command-line version, built with $$TLS_LIBRARY). For more information, visit https://www.infradead.org/openconnect/\""; \
	  echo "OutFile \"$$INSTALLER_NAME\""; \
	  cat "$(srcdir)/openconnect.nsi.in" ) > $@

AM_V_MAKENSIS = $(am__v_MAKENSIS_$(V))
am__v_MAKENSIS_ = $(am__v_MAKENSIS_$(AM_DEFAULT_VERBOSITY))
am__v_MAKENSIS_0 = @echo "  MAKENSIS   " $@;
am__v_MAKENSIS_1 =

openconnect-installer-$(INSTALLER_SUFFIX).exe: openconnect.nsi instfiles.nsh uninstfiles.nsh $(srcdir)/openconnect.nsi.in html-recursive
	$(AM_V_MAKENSIS) $(MAKENSIS) $<
	ln -f "$$(grep -E '^OutFile' openconnect.nsi | cut -f2 -d\")" $@

endif #BUILD_NSIS
