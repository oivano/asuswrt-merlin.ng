# RHEL6/7 still has ancient GnuTLS
%if 0%{?rhel_version} > 0 && 0%{?rhel_version} < 800
%define use_gnutls 0
%else
%define use_gnutls 1
%endif

# RHEL has no libproxy, and no %%make_install macro
%if 0%{?rhel}
%define use_libproxy 0
%define make_install %{__make} install DESTDIR=%{?buildroot}
%define use_tokens 0
%else
%define use_libproxy 1
%define use_tokens 1
%endif

# Fedora has tss2-sys from F29 onwards, and RHEL from 9 onwards.
%if 0%{?rhel_version} < 900
%define use_tss2_esys 0
%else
%define use_tss2_esys 1
%endif

%{!?_pkgdocdir: %global _pkgdocdir %{_docdir}/%{name}-%{version}}

%define libname libopenconnect5
Name:		openconnect
Version:	8.20+git20220220
Release:	0
Summary:	Open client for SSL VPNs

License:	LGPL-2.1
URL:		https://www.infradead.org/openconnect.html
Source0:    https://www.infradead.org/openconnect/download/%{name}-%{version}.tar.gz


BuildRequires:	pkgconfig(libxml-2.0) krb5-devel
BuildRequires:	autoconf automake libtool gettext
%if !0%{?rhel_version} == 700
BuildRequires:	pkgconfig(liblz4) pkgconfig(libpcsclite)
BuildRequires:	pkgconfig(uid_wrapper) pkgconfig(socket_wrapper)
%endif
%if 0%{?fedora}
BuildRequires:  pkgconfig(json-parser)
%endif
%if 0%{?fedora}
# SoftHSM doesn't install on EPEL8: https://bugzilla.redhat.com/show_bug.cgi?id=1829480
# and it is not available on SUSE
BuildRequires:  softhsm
%endif
Obsoletes:	openconnect-lib-compat < %{version}-%{release}
Requires:	vpnc-script

%if 0%{?fedora} || 0%{?suse_version}
BuildRequires: pkgconfig(libp11) pkgconfig(p11-kit-1)
%endif
%if 0%{?fedora}
BuildRequires: glibc-langpack-cs
%endif
%if %{use_gnutls}
%if !0%{?rhel_version} == 700
BuildRequires:	trousers-devel
%endif
BuildRequires:	pkgconfig(gnutls)
%if !0%{?suse_version} == 1500
BuildRequires:	ocserv
%endif
%else
BuildRequires:	pkgconfig(openssl)
%endif
%if %{use_libproxy}
BuildRequires:	pkgconfig(libproxy-1.0)
%endif
%if %{use_tokens}
BuildRequires:  pkgconfig(stoken) pkgconfig(libpskc)
%endif
%if %{use_tss2_esys}
BuildRequires: pkgconfig(tss2-esys) pkgconfig(tss2-tctildr) pkgconfig(tss2-mu)
# https://bugzilla.redhat.com/show_bug.cgi?id=1638961
BuildRequires: libgcrypt-devel
%if 0%{?fedora} > 32
# Older versions of tss2-esys don't have the swtpm TCTI
BuildRequires: swtpm swtpm-tools
%endif
%endif

%description
This package provides a multiprotocol VPN client for Cisco AnyConnect,
Juniper SSL VPN / Pulse Connect Secure, and Palo Alto Networks GlobalProtect
SSL VPN.

%package -n %{libname}
Summary:        Libraries for openconnect
Group:          System/Libraries

%description -n %{libname}
This package provides libraries for Cisco's "AnyConnect" VPN, which uses
HTTPS and DTLS protocols.  AnyConnect is supported by the ASA5500 Series,
by IOS 12.4(9)T or later on Cisco SR500, 870, 880, 1800, 2800, 3800,
7200 Series and Cisco 7301 Routers, and probably others.

%package devel
Summary: Development package for OpenConnect VPN authentication tools
Requires: %{name}%{?_isa} = %{version}-%{release}

%description devel
This package provides the core HTTP and authentication support from
the OpenConnect VPN client, to be used by GUI authentication dialogs
for NetworkManager etc.

%prep
%setup -q
if [ ! -x configure ]; then
    NOCONFIGURE=x ./autogen.sh
fi

%build
%configure	--disable-dsa-tests \
%if %{use_gnutls}
%if 0%{?fedora} || 0%{?rhel_version} > 700
		--with-default-gnutls-priority="@OPENCONNECT,SYSTEM" \
%endif
		--without-gnutls-version-check \
%else
		--with-openssl --without-openssl-version-check \
%endif
%if 0%{?rhel_version} == 0 || 0%{?rhel_version} >= 800
		--htmldir=%{_pkgdocdir} \
%else
		--disable-docs \
%endif
		--with-vpnc-script=/etc/vpnc/vpnc-script
make %{?_smp_mflags} V=1


%install
%make_install
mkdir -p $RPM_BUILD_ROOT/%{_pkgdocdir}
rm -f $RPM_BUILD_ROOT/%{_libdir}/libopenconnect.la
rm -f $RPM_BUILD_ROOT/%{_libexecdir}/openconnect/tncc-wrapper.py
rm -f $RPM_BUILD_ROOT/%{_libexecdir}/openconnect/hipreport-android.sh
%find_lang %{name}

%check
%if 0%{?fedora} || 0%{?rhel_version} > 700
# Clear RDRAND capability bit to work around
# https://bugzilla.redhat.com/show_bug.cgi?id=1831086
make VERBOSE=1 OPENSSL_ia32cap=~0x4000000000000000 XFAIL_TESTS="obsolete-server-crypto" check
%else
# Test setup for OpenSSL builds in RHEL6.
make VERBOSE=1 XFAIL_TESTS="auth-nonascii bad_dtls_test" check
%endif

%files -f %{name}.lang
%{_sbindir}/openconnect
%{_libexecdir}/openconnect/
%{_mandir}/man8/*
%{_datadir}/bash-completion/completions/openconnect
%doc TODO COPYING.LGPL
%doc %{_pkgdocdir}

%post -n %{libname} -p /sbin/ldconfig
%postun -n %{libname} -p /sbin/ldconfig

%files -n %{libname}
%{_libdir}/libopenconnect.so.*

%files devel
%{_libdir}/libopenconnect.so
%{_includedir}/openconnect.h
%{_libdir}/pkgconfig/openconnect.pc

%changelog
* Wed Feb 23 2022 OpenConnect Team <openconnect-devel@lists.infradead.org> - %{version}-%{release}
- Adapt for SUSE builds for OBS
* Tue Jul 16 2019 David Woodhouse <dwmw2@infradead.org> - %{version}-%{release}
- Autopackaging for COPR
