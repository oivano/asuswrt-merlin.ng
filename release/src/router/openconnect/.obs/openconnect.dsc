Format: 1.0
Source: openconnect
Binary: openconnect, libopenconnect-dev, libopenconnect5
Architecture: any
Version: 8.20-0
Maintainer: OpenConnect Team <openconnect-devel@lists.infradead.org>
Homepage: https://www.infradead.org/openconnect/
Standards-Version: 4.6.0
Build-Depends: debhelper-compat (= 12), groff, libgcrypt20-dev, libgnutls28-dev, libkrb5-dev, liblz4-dev, libp11-kit-dev, libpcsclite-dev, libproxy-dev, libsocket-wrapper [!hurd-i386] <!nocheck>, libstoken-dev, libtasn1-6-dev, libuid-wrapper [!alpha !hurd-i386 !kfreebsd-amd64 !kfreebsd-i386] <!nocheck>, libxml2-dev, locales-all <!nocheck>, ocserv [!hurd-i386 !kfreebsd-amd64 !kfreebsd-i386] <!nocheck>, openssl <!nocheck>, pkg-config, python3:any, softhsm2 [!hurd-i386] <!nocheck>, xdg-utils, zlib1g-dev
Package-List:
 libopenconnect-dev deb libdevel optional arch=any
 libopenconnect5 deb libs optional arch=any
 openconnect deb net optional arch=any
Checksums-Sha1:
 5518304b35d865bea3ea6cf927fa0e0e4dd5f08a 2651542 openconnect_8.20.tar.gz
Checksums-Sha256:
 c1452384c6f796baee45d4e919ae1bfc281d6c88862e1f646a2cc513fc44e58b 2651542 openconnect_8.20.orig.tar.gz
Files:
 26218ee45fea950ebcc65be242f3eb42 2651542 openconnect_8.20.tar.gz
DEBTRANSFORM-RELEASE: 1
