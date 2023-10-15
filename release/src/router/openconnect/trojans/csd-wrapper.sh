#!/bin/bash
# Cisco Anyconnect CSD wrapper for OpenConnect
#
# [05 May 2015] Written by Nikolay Panin <nick_panin@mail.ru>:
#   - source: https://gist.github.com/l0ki000/56845c00fd2a0e76d688
# [27 Oct 2017] Updated by Daniel Lenski <dlenski@gmail.com>:
#   - use -url argument
#   - kill cstub after timeout
#   - fix small typos:
# [31 May 2018] Updated by Daniel Lenski <dlenski@gmail.com>:
#   - use curl with --pinnedpubkey to rely on sha256 hash of peer cert passed by openconnect
# [10 Feb 2023] Updated by Andy Teijelo <ateijelo@gmail.com>:
#   - use coreutil's timeout when spawning cstub

TIMEOUT=30
URL="https://${CSD_HOSTNAME}/CACHE"
HOSTSCAN_DIR="$HOME/.cisco/hostscan"
LIB_DIR="$HOSTSCAN_DIR/lib"
BIN_DIR="$HOSTSCAN_DIR/bin"

# cURL 7.39 (https://bugzilla.redhat.com/show_bug.cgi?id=1195771)
# is required to support pin-based certificate validation. Must set this
# to true if using an earlier version of cURL.

MISSING_OPTION_PINNEDPUBKEY=false
if [[ "$MISSING_OPTION_PINNEDPUBKEY" == "true" ]]; then
    # Don't validate server certificate at all
    echo "*********************************************************************" >&2
    echo "WARNING: running insecurely; will not validate CSD server certificate" >&2
    echo "*********************************************************************" >&2
    PINNEDPUBKEY="-k"
elif [[ -z "$CSD_SHA256" ]]; then
    # We must be running with a version of OpenConnect prior to v8.00 if CSD_SHA256
    # is unset. In that case, fallback to cURL's default certificate validation so
    # as to fail-closed rather than fail-open in the case of an unknown or untrusted
    # server certificate.
    PINNEDPUBKEY=""
else
    # Validate certificate using pin-sha256 value in CSD_SHA256. OpenConnect v8.00
    # and newer releases set the CSD_SHA256 variable unconditionally.
    PINNEDPUBKEY="-k --pinnedpubkey sha256//$CSD_SHA256"
fi

BINS=("cscan" "cstub" "cnotify")

# parsing command line
shift

URL=
TICKET=
STUB=
GROUP=
CERTHASH=
LANGSELEN=

while [ "$1" ]; do
    if [ "$1" == "-ticket" ];   then shift; TICKET=$1; fi
    if [ "$1" == "-stub" ];     then shift; STUB=$1; fi
    if [ "$1" == "-group" ];    then shift; GROUP=$1; fi
    if [ "$1" == "-certhash" ]; then shift; CERTHASH=$1; fi
    if [ "$1" == "-url" ];      then shift; URL=$(echo $1|tr -d '"'); fi # strip quotes
    if [ "$1" == "-langselen" ];then shift; LANGSELEN=$1; fi
    shift
done

OS="$(uname -s)"
ARCH="$(uname -m)"

if [[ "$OS $ARCH" == "Linux x86_64" ]]
then
    ARCH="linux_x64"
elif [[ "$OS $ARCH" == "Linux i386" || "$ARCH" == "Linux i686" ]]
then
    ARCH="linux_i386"
else
    echo "This CSD wrapper script does not know how to handle your platform: $OS on $ARCH" >&2
    exit 1
fi

# creating dirs
for dir in $HOSTSCAN_DIR $LIB_DIR $BIN_DIR ; do
    if [[ ! -f $dir ]]
    then
        mkdir -p $dir
    fi
done

# getting manifest, and checking binaries
curl $PINNEDPUBKEY -s "${URL}/sdesktop/hostscan/$ARCH/manifest" -o "$HOSTSCAN_DIR/manifest"

# generating md5.sum with full paths from manifest
export HOSTSCAN_DIR=$HOSTSCAN_DIR
while read HASHTYPE FILE EQU HASHVAL; do
    FILE="${FILE%*)}"
    FILE="${FILE#(}"
    if grep --extended-regexp --quiet --invert-match ".so|tables.dat" <<< "$FILE"; then
	PATHNAME="${BIN_DIR}/$FILE"
	IS_BIN=yes
    else
	PATHNAME="${LIB_DIR}/$FILE"
	IS_BIN=no
    fi
    DOWNLOAD=yes
    case $HASHTYPE in
	MD5)
	    if [ -r "$PATHNAME" ] && md5sum --status -c <<< "$HASHVAL $PATHNAME"; then
		DOWNLOAD=no
	    fi
	    ;;
	SHA1)
	    if [ -r "$PATHNAME" ] && sha1sum --status -c <<< "$HASHVAL $PATHNAME"; then
		DOWNLOAD=no
	    fi
	    ;;
	SHA256)
	    if [ -r "$PATHNAME" ] && sha256sum --status -c <<< "$HASHVAL $PATHNAME"; then
		DOWNLOAD=no
	    fi
	    ;;
	*)
	    echo "Unsupported hash type $HASHTYPE"
	    ;;
    esac
    if [ "$DOWNLOAD" = "yes" ]; then
	echo "Downloading: $FILE"
	TMPFILE="${PATHNAME}.tmp"

        curl $PINNEDPUBKEY -s "${URL}/sdesktop/hostscan/$ARCH/$FILE" -o "${TMPFILE}"

        # some files are in gz (don't understand logic here)
        if [[ ! -f "${TMPFILE}" || ! -s "${TMPFILE}" ]]
        then
            # remove 0 size files
            if [[ ! -s ${TMPFILE} ]]; then
                rm ${TMPFILE}
            fi

            echo "Failure on $FILE, trying gz"
            FILE_GZ="${FILE}.gz"
            curl $PINNEDPUBKEY -s "${URL}/sdesktop/hostscan/$ARCH/$FILE_GZ" -o "${TMPFILE}.gz" &&
		gunzip --verbose --decompress "${TMPFILE}.gz"
        fi

	if [ -r "${TMPFILE}" ]; then
	    if [ "$IS_BIN" = "yes" ]; then
		chmod +x "${TMPFILE}"
	    fi
	    mv "${TMPFILE}" "${PATHNAME}"
	fi
    fi
done < $HOSTSCAN_DIR/manifest

# cstub doesn't care about logging options, sic!
#ARGS="-log debug -ticket $TICKET -stub $STUB -group $GROUP -host "$URL" -certhash $CERTHASH"
ARGS="-log error -ticket $TICKET -stub $STUB -group $GROUP -host \"$URL\" -certhash $CERTHASH"

echo "Launching: $BIN_DIR/cstub $ARGS"

timeout $TIMEOUT "$BIN_DIR/cstub" $ARGS
