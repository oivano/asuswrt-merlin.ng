#!/bin/sh
#
# Copyright 2013-2016 Nikos Mavrogiannopoulos
#
# This file is part of openconnect.
#
# This is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

#this test can only be run as root

if ! test -x /usr/sbin/ocserv;then
	echo "You need ocserv to run this test"
	exit 77
fi

if test "${DISABLE_ASAN_BROKEN_TESTS}" = 1 && test "${PRELOAD}" = 1;then
	echo "This test cannot be run under asan"
	exit 77
fi

OCSERV=/usr/sbin/ocserv
PPPD=/usr/sbin/pppd
test $(id -u) -eq 0 && SUDO= || SUDO=sudo

top_builddir=${top_builddir:-..}
SOCKDIR="./sockwrap.$$.tmp"
mkdir -p $SOCKDIR
export SOCKET_WRAPPER_DIR=$SOCKDIR
export SOCKET_WRAPPER_DEFAULT_IFACE=2
ADDRESS=127.0.0.$SOCKET_WRAPPER_DEFAULT_IFACE
OPENCONNECT="${OPENCONNECT:-${top_builddir}/openconnect}"${EXEEXT}
LOGFILE="$SOCKDIR/log.$$.tmp"
OCCTL_SOCKET="${OCCTL_SOCKET:-./occtl-comp-$$.socket}"

certdir="${srcdir}/certs"
confdir="${srcdir}/configs"

update_config() {
	file=$1
	username=$(whoami)
	group=$(groups|cut -f 1 -d ' ')
	cp "${srcdir}/configs/${file}" "$file.$$.tmp"
	sed -i -e 's|@USERNAME@|'${username}'|g' "$file.$$.tmp" \
	       -e 's|@GROUP@|'${group}'|g' "$file.$$.tmp" \
	       -e 's|@SRCDIR@|'${srcdir}'|g' "$file.$$.tmp" \
	       -e 's|@OTP_FILE@|'${OTP_FILE}'|g' "$file.$$.tmp" \
	       -e 's|@CRLNAME@|'${CRLNAME}'|g' "$file.$$.tmp" \
	       -e 's|@PORT@|'${PORT}'|g' "$file.$$.tmp" \
	       -e 's|@ADDRESS@|'${ADDRESS}'|g' "$file.$$.tmp" \
	       -e 's|@VPNNET@|'${VPNNET}'|g' "$file.$$.tmp" \
	       -e 's|@VPNNET6@|'${VPNNET6}'|g' "$file.$$.tmp" \
	       -e 's|@OCCTL_SOCKET@|'${OCCTL_SOCKET}'|g' "$file.$$.tmp" \
	       -e 's|@TLS_PRIORITIES@|'${TLS_PRIORITIES}'|g' "$file.$$.tmp"
	CONFIG="$file.$$.tmp"
}

launch_simple_sr_server() {
       LD_PRELOAD=libsocket_wrapper.so:libuid_wrapper.so UID_WRAPPER=1 UID_WRAPPER_ROOT=1 $OCSERV $* &
}

launch_simple_pppd() {
       CERT="$1"
       KEY="$2"
       shift 2 # remaining arguments (now in $*) are for pppd

       # In addition to its arcane option naming, pppd is very poorly designed for mocking and testing
       # in isolation, and running as non-root. We use socat(1) to connect it to a TLS socat. There
       # are a number of caveats in about this process.
       #
       # 1) The 'raw,echo=0' option is obsolete (http://www.dest-unreach.org/socat/doc/CHANGES), but its
       #    replacement 'rawer' isn't available until v1.7.3.0, which is newer than what we have available
       #    on our CentOS 6 CI image.
       # 2) pppd complains vigorously about being started with libsocket_wrapper.so, and does not need it
       #    anyway since its direct I/O is only with the pty.
       # 3) The pppd process should be started first, and the TLS listener second. If this is run the other
       #    way around, the client's initial TLS packets may go to a black hole before pppd starts up
       #    and begins receiving them.
       # 4) These pppd options should always be present for our test usage:
       #      - nauth (self-explanatory)
       #      - local (no modem control lines)
       #      - nodefaultroute (don't touch routing)
       #      - debug and logfile (log all control packets to a file so test can analyze them)
       # 5) The scripts normally installed in /etc/ppp (e.g. ip-up, ipv6-up) should NOT be present for
       #    our test usage, since they require true root and probably cannot be run in our containerized
       #    CI environments. CI should move these scripts out of the way before running tests with pppd.
       # 6) The pppd option 'sync' can be used to avoid "HDLC" (more precisely, "asynchronous HDLC-like
       #    framing").
       #
       #    However, pppd+socat has problems framing its I/O correctly in this case, occasionally
       #    misinterpreting incoming packets as concatenated to one another, or sending outgoing packets
       #    in a single TLS record. This effectively means that the peers may drop/miss some of
       #    the config packets exchanged, causing retries and leading to a longer negotiation period.
       #    [use `socat -x` for a hex log of I/O to/from the connected sockets]

       LD_PRELOAD=libsocket_wrapper.so socat \
		 SYSTEM:"LD_PRELOAD= $SUDO $PPPD noauth local debug nodefaultroute logfile '$LOGFILE' $*",pty,raw,echo=0 \
		 OPENSSL-LISTEN:443,verify=0,cert="$CERT",key="$KEY" 2>&1 &
       PID=$!
}

wait_server() {
	test $# -ge 2 && DELAY="$2" || DELAY=5
	trap "kill $1" 1 15 2
	sleep "$DELAY"
}

cleanup() {
	ret=0
	kill $PID 2>/dev/null
	if test $? != 0;then
		ret=1
	fi
	wait
	test -n "$SOCKDIR" && rm -rf $SOCKDIR && mkdir -p $SOCKDIR
	return $ret
}

fail() {
	PID="$1"
	shift;
	echo "Failure: $1" >&2
	kill $PID
	test -n "$SOCKDIR" && rm -rf $SOCKDIR
	exit 1
}

trap "fail \"Failed to launch the server, aborting test... \"" 10
