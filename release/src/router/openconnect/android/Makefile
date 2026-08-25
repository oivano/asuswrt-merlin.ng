#
# This Makefile attempts to build OpenConnect and its dependencies for Android
#
# It doesn't do a stunning job of tracking changes in the dependencies and
# automatically rebuilding them, but it's good enough for getting them built
# and installed into its own local sysroot.
#
# As long as you have the Android NDK toolchain on your path, you should then
# be able to edit fairly much anything in place and rebuild it locally.
#
# It should also be fairly simple to extend this to cross-compile for any target

# Last tested with https://dl.google.com/android/repository/android-ndk-r21b-linux-x86_64.zip


NDK     := /opt/android-sdk-linux_x86/android-ndk-r27c
ARCH    := x86_64
API_LEVEL := 23

EXTRA_CFLAGS := -D__ANDROID_API__=$(API_LEVEL) -O2 -Wno-macro-redefined

# You should be able to just 'make ARCH=x86' and it should DTRT.
ifeq ($(ARCH),arm)
TRIPLET := armv7a-linux-androideabi
EXTRA_CFLAGS += -march=armv7-a -mthumb
endif
ifeq ($(ARCH),arm64)
TRIPLET := aarch64-linux-android
endif
ifeq ($(ARCH),x86)
TRIPLET := i686-linux-android
endif
ifeq ($(ARCH),x86_64)
TRIPLET := x86_64-linux-android
endif

TOPDIR := $(shell pwd)
DESTDIR := $(TOPDIR)/$(TRIPLET)/out

TOOLCHAIN := $(NDK)/toolchains/llvm/prebuilt/linux-x86_64
PATH := $(TOOLCHAIN)/bin:$(PATH)
OC_SYSROOT := $(TOPDIR)/$(TRIPLET)/sysroot/usr
OC_SYSROOT_PATCHES := $(TOPDIR)/sysroot-patches

AR := $(TOOLCHAIN)/bin/llvm-ar
AS := $(TOOLCHAIN)/bin/llvm-as
CC := $(TOOLCHAIN)/bin/$(TRIPLET)$(API_LEVEL)-clang --sysroot=$(OC_SYSROOT)/..
CXX := $(TOOLCHAIN)/bin/$(TRIPLET)$(API_LEVEL)-clang++ --sysroot=$(OC_SYSROOT)/..
LD := $(TOOLCHAIN)/bin/ld --sysroot=$(OC_SYSROOT)/..
RANLIB := $(TOOLCHAIN)/bin/llvm-ranlib
STRIP := $(TOOLCHAIN)/bin/llvm-strip

PKG_CONFIG_LIBDIR := $(OC_SYSROOT)/lib/pkgconfig

export PATH PKG_CONFIG_LIBDIR AR AS CC CXX LD RANLIB STRIP

# PKG_CONFIG_LIBDIR gets exported to sub-makes, but not to $(shell
PKG_CONFIG := PKG_CONFIG_LIBDIR=$(PKG_CONFIG_LIBDIR) pkg-config

MAKEINSTALL=$(MAKE) INSTALL=$(TOPDIR)/install_symlink.sh
FETCH=$(TOPDIR)/fetch.sh

CONFIGURE_ARGS := --host=$(TRIPLET) --prefix=$(OC_SYSROOT) \
		  --disable-shared --enable-static --with-pic \
		  CFLAGS="$(EXTRA_CFLAGS)"

SOURCE_LIST = $(LIBXML2_SRC)/configure $(GMP_SRC)/configure \
	$(NETTLE_SRC)/configure $(GNUTLS_SRC)/configure \
	$(STOKEN_SRC)/configure \
	$(LZ4_DIR)/Makefile

PKG_LIST := LIBXML2 GMP NETTLE GNUTLS STOKEN LZ4

MIRROR_TEST_TARGETS := $(addprefix mirror-test-,$(PKG_LIST))

all: openconnect run_pie

#####################################################################
#
# Link NDK sysroot to local directory and apply patches
#
$(OC_SYSROOT):
	mkdir -p $(OC_SYSROOT)/lib $(OC_SYSROOT)/include
	ln -Ls $(TOOLCHAIN)/sysroot/usr/lib/* $(OC_SYSROOT)/lib
	ln -Ls $(TOOLCHAIN)/sysroot/usr/include/* $(OC_SYSROOT)/include
	find $(OC_SYSROOT_PATCHES) -type f -print0 | sort -z | xargs -0n 1 patch \
		--follow-symlinks -p1 -d $(OC_SYSROOT) -i

#####################################################################
#
# Build libxml2 with minimal configuration for OpenConnect
#
# http://xmlsoft.org/news.html
LIBXML2_VER := 2.14.5
LIBXML2_TAR := libxml2-$(LIBXML2_VER).tar.xz
LIBXML2_SHA := 03d006f3537616833c16c53addcdc32a0eb20e55443cba4038307e3fa7d8d44b
LIBXML2_SRC := sources/libxml2-$(LIBXML2_VER)
LIBXML2_BUILD := $(TRIPLET)/libxml2

$(LIBXML2_TAR):
	$(FETCH) $@ $(LIBXML2_SHA)

$(LIBXML2_SRC)/configure: $(LIBXML2_TAR)
	mkdir -p sources
	tar xfJ $< -C sources
	touch $@

$(LIBXML2_BUILD)/Makefile: $(OC_SYSROOT) $(LIBXML2_SRC)/configure
	mkdir -p $(LIBXML2_BUILD)
	cd $(LIBXML2_BUILD) && ../../$(LIBXML2_SRC)/configure $(CONFIGURE_ARGS) \
	    --without-c14n -without-catalog --without-debug --without-docbook \
	    --without-fexceptions --without-ftp --without-history \
	    --without-http --without-iconv --without-iconv \
	    --without-iso8859x --without-legacy --without-pattern \
	    --without-push --without-regexps --without-run-debug \
	    --without-sax1 --without-schemas --without-schematron \
	    --without-threads --without-valid --without-xinclude \
	    --without-xpath --without-xptr --without-zlib --without-lzma \
	    --without-coverage --without-python

$(LIBXML2_BUILD)/libxml2.la: $(LIBXML2_BUILD)/Makefile
	$(MAKE) -C $(LIBXML2_BUILD) libxml2.la

$(LIBXML2_BUILD)/libxml-2.0.pc: $(LIBXML2_BUILD)/Makefile
	$(MAKE) -C $(LIBXML2_BUILD) libxml-2.0.pc

$(OC_SYSROOT)/lib/libxml2.la: $(LIBXML2_BUILD)/libxml2.la
	$(MAKEINSTALL) -C $(LIBXML2_BUILD) install-libLTLIBRARIES

$(OC_SYSROOT)/lib/pkgconfig/libxml-2.0.pc: $(LIBXML2_BUILD)/libxml-2.0.pc
	$(MAKEINSTALL) -C $(LIBXML2_BUILD) install-data

LIBXML_DEPS := $(OC_SYSROOT)/lib/libxml2.la $(OC_SYSROOT)/lib/pkgconfig/libxml-2.0.pc

libxml: $(LIBXML_DEPS)


#####################################################################
#
# Build GNU MP
#
# https://gmplib.org/
GMP_VER := 6.3.0
GMP_TAR := gmp-$(GMP_VER).tar.xz
GMP_SHA := a3c2b80201b89e68616f4ad30bc66aee4927c3ce50e33929ca819d5c43538898
GMP_SRC := sources/gmp-$(GMP_VER)
GMP_BUILD := $(TRIPLET)/gmp

$(GMP_TAR):
	$(FETCH) $@ $(GMP_SHA)

$(GMP_SRC)/configure: $(GMP_TAR)
	mkdir -p sources
	tar -xJf $< -C sources
	touch $@

# binvert_limb_table is not PIC on arm
ifeq ($(ARCH),arm)
GMP_EXTRA_FLAGS := --disable-assembly
endif

$(GMP_BUILD)/Makefile: $(OC_SYSROOT) $(GMP_SRC)/configure
	mkdir -p $(GMP_BUILD)
	cd $(GMP_BUILD) && ../../$(GMP_SRC)/configure \
		$(CONFIGURE_ARGS) $(GMP_EXTRA_FLAGS)


$(GMP_BUILD)/libgmp.la: $(GMP_BUILD)/Makefile
	$(MAKE) -C $(GMP_BUILD)

$(OC_SYSROOT)/lib/libgmp.la: $(GMP_BUILD)/libgmp.la
	$(MAKEINSTALL) -C $(GMP_BUILD) install

GMP_DEPS := $(OC_SYSROOT)/lib/libgmp.la

gmp: $(GMP_DEPS)


#####################################################################
#
# Build nettle
#
# https://ftp.gnu.org/gnu/nettle/
NETTLE_VER := 3.10
NETTLE_TAR := nettle-$(NETTLE_VER).tar.gz
NETTLE_SHA := b4c518adb174e484cb4acea54118f02380c7133771e7e9beb98a0787194ee47c
NETTLE_SRC := sources/nettle-$(NETTLE_VER)
NETTLE_BUILD := $(TRIPLET)/nettle

$(NETTLE_TAR):
	$(FETCH) $@ $(NETTLE_SHA)

$(NETTLE_SRC)/configure: $(NETTLE_TAR)
	mkdir -p sources
	tar xfz $< -C sources
	touch $@

$(NETTLE_BUILD)/Makefile: $(OC_SYSROOT) $(NETTLE_SRC)/configure $(GMP_DEPS)
	mkdir -p $(NETTLE_BUILD)
	cd $(NETTLE_BUILD) && ../../$(NETTLE_SRC)/configure $(CONFIGURE_ARGS)

$(NETTLE_BUILD)/libnettle.a: $(NETTLE_BUILD)/Makefile
	$(MAKE) -C $(NETTLE_BUILD) SUBDIRS=

$(OC_SYSROOT)/lib/libnettle.a: $(NETTLE_BUILD)/libnettle.a
	$(MAKEINSTALL) -C $(NETTLE_BUILD) SUBDIRS= install

NETTLE_DEPS := $(OC_SYSROOT)/lib/libnettle.a

nettle: $(NETTLE_DEPS)


#####################################################################
#
# Build GnuTLS
#
# https://www.gnutls.org/download.html
GNUTLS_VER := 3.7.11
GNUTLS_TAR := gnutls-$(GNUTLS_VER).tar.xz
GNUTLS_SHA := 90e337504031ef7d3077ab1a52ca8bac9b2f72bc454c95365a1cd1e0e81e06e9
GNUTLS_SRC := sources/gnutls-$(GNUTLS_VER)
GNUTLS_BUILD := $(TRIPLET)/gnutls

$(GNUTLS_TAR):
	$(FETCH) $@ $(GNUTLS_SHA)

$(GNUTLS_SRC)/configure: $(GNUTLS_TAR)
	mkdir -p sources
	xz -d < $< | tar xf - -C sources
	touch $@

$(GNUTLS_BUILD)/Makefile: $(OC_SYSROOT) $(GNUTLS_SRC)/configure $(NETTLE_DEPS)
	mkdir -p $(GNUTLS_BUILD)
	# ac_cv_func_*alloc_0_nonnull: malloc(0) returns a non-null value, as tested on
	# arm64 target; however, GnuTLS fails to check for this.
	cd $(GNUTLS_BUILD) && ../../$(GNUTLS_SRC)/configure $(CONFIGURE_ARGS) \
		AUTOGEN=/bin/false \
		--disable-threads --disable-tests --disable-nls \
		--disable-doc --disable-openssl-compatibility --disable-cxx \
		--disable-openssl-compatibility --disable-tools \
		--disable-anon-authentication --with-included-libtasn1 \
		--enable-psk-authentication --disable-srp-authentication \
		--disable-dtls-srtp-support  --enable-dhe --enable-ecdhe \
		--with-included-unistring --without-p11-kit --disable-guile \
		ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes \

$(GNUTLS_BUILD)/lib/libgnutls.la: $(GNUTLS_BUILD)/Makefile
	$(MAKE) -C $(GNUTLS_BUILD)

$(OC_SYSROOT)/lib/libgnutls.la: $(GNUTLS_BUILD)/lib/libgnutls.la
	$(MAKEINSTALL) -C $(GNUTLS_BUILD) install

GNUTLS_DEPS := $(OC_SYSROOT)/lib/libgnutls.la

gnutls: $(GNUTLS_DEPS)


#####################################################################
#
# Build libstoken
#
# https://sourceforge.net/projects/stoken/files/
STOKEN_VER := 0.93
STOKEN_TAR := stoken-v$(STOKEN_VER).tar.gz
STOKEN_SHA := 102e2d112b275efcdc20ef438670e4f24f08870b9072a81fda316efcc38aef9c
STOKEN_SRC := sources/stoken-$(STOKEN_VER)
STOKEN_BUILD := $(TRIPLET)/stoken

$(STOKEN_TAR):
	$(FETCH) $@ $(STOKEN_SHA)

$(STOKEN_SRC)/configure: $(STOKEN_TAR)
	mkdir -p sources
	tar xfz $< -C sources
	cd $(STOKEN_SRC) && ./autogen.sh

$(STOKEN_BUILD)/Makefile: $(OC_SYSROOT) $(STOKEN_SRC)/configure $(NETTLE_DEPS)
	mkdir -p $(STOKEN_BUILD)
	cd $(STOKEN_BUILD) && ../../$(STOKEN_SRC)/configure $(CONFIGURE_ARGS) \
		--without-gtk

$(STOKEN_BUILD)/libstoken.la: $(STOKEN_BUILD)/Makefile
	$(MAKE) -C $(STOKEN_BUILD)

$(OC_SYSROOT)/lib/libstoken.la: $(STOKEN_BUILD)/libstoken.la
	$(MAKEINSTALL) -C $(STOKEN_BUILD) install

STOKEN_DEPS := $(OC_SYSROOT)/lib/libstoken.la

stoken: $(STOKEN_DEPS)


#####################################################################
#
# Build liblz4
#
# https://github.com/lz4/lz4/tags
LZ4_VER := 1.10.0
LZ4_TAR := lz4-v$(LZ4_VER).tar.gz
LZ4_SHA := 537512904744b35e232912055ccf8ec66d768639ff3abe5788d90d792ec5f48b
LZ4_DIR := $(TRIPLET)/lz4-$(LZ4_VER)

$(LZ4_TAR):
	$(FETCH) $@ $(LZ4_SHA)

$(LZ4_DIR)/Makefile: $(LZ4_TAR)
	mkdir -p $(TRIPLET)
	tar xzf $< -C $(TRIPLET)
	touch $@

ifeq ($(ARCH),x86)
LZ4_EXTRA_CFLAGS := -fPIC
endif

$(OC_SYSROOT)/lib/liblz4.a: $(OC_SYSROOT) $(LZ4_DIR)/Makefile
	$(MAKE) -C $(LZ4_DIR)/lib \
		LIBDIR=$(OC_SYSROOT)/lib \
		INCLUDEDIR=$(OC_SYSROOT)/include \
		CFLAGS="$(EXTRA_CFLAGS) $(LZ4_EXTRA_CFLAGS)" \
		BUILD_SHARED=no \
		install

LZ4_DEPS := $(OC_SYSROOT)/lib/liblz4.a

lz4: $(LZ4_DEPS)

#####################################################################
#
# Build OpenConnect for Android
#
OPENCONNECT_SRC := ..
OPENCONNECT_BUILD := $(TRIPLET)/openconnect

$(OPENCONNECT_SRC)/configure:
	cd $(OPENCONNECT_SRC) && ./autogen.sh

$(OPENCONNECT_BUILD)/Makefile: $(OC_SYSROOT) $(GNUTLS_DEPS) $(LIBXML_DEPS) \
		$(STOKEN_DEPS) $(LZ4_DEPS) $(OPENCONNECT_SRC)/configure
	mkdir -p $(OPENCONNECT_BUILD)
	cd $(OPENCONNECT_BUILD) && ../../../configure \
	--host=$(TRIPLET) --prefix=/ \
	CFLAGS="$(EXTRA_CFLAGS) -fvisibility=default -fPIE" \
	LDFLAGS="$(EXTRA_LDFLAGS) -rdynamic -pie" \
	GNUTLS_LIBS="$(shell $(PKG_CONFIG) --static --libs gnutls)" \
	LIBSTOKEN_LIBS="$(shell $(PKG_CONFIG) --static --libs stoken)" \
	--enable-shared --with-vpnc-script=/etc/vpnc/vpnc-script \
	--with-java=$(OC_SYSROOT)/include --enable-jni-standalone \
	--disable-symvers

openconnect: $(OPENCONNECT_BUILD)/Makefile
	make -C $(OPENCONNECT_BUILD)
	make -C $(OPENCONNECT_BUILD) install-strip DESTDIR=$(DESTDIR)


#####################################################################
#
# Build run_pie helper program
#
$(DESTDIR)/sbin/run_pie: run_pie.c $(TOOLCHAIN_BUILT)
	mkdir -p $(DESTDIR)/sbin
	$(CC) $< -o $@ -ldl

.PHONY: run_pie
run_pie: $(DESTDIR)/sbin/run_pie


#####################################################################
#
# Special targets for maintainer use
#

# download + extract, but do not build
.PHONY: sources
sources: $(SOURCE_LIST)

.PHONY: $(MIRROR_TEST_TARGETS)
$(MIRROR_TEST_TARGETS) : mirror-test-% :
	$(FETCH) --mirror-test $($(*)_TAR) $($(*)_SHA)

# (re)test all mirrors for all packages. safe for use with "make -jN"
.PHONY: mirror-test
mirror-test: $(MIRROR_TEST_TARGETS)
