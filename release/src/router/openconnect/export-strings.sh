#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Copyright © 2012-2022 David Woodhouse <dwmw2@infradead.org>
#
# OpenConnect export-strings.sh
#
# Export strings for translation in NetworkManager-openconnect
#

OUTFILE="$1"
POTFILE="$2"

if [ -z "${POTFILE}" -o -z "${OUTFILE}" ]; then
    echo "Usage: $0 <NetworkManager-openconnect/openconnect-strings.txt> <openconnect.pot>"
    exit 1
fi

if ! grep -q "This file contains strings from the OpenConnect VPN client" "${OUTFILE}"; then
    echo "Error: ${OUTFILE} is not the NetworkManager-openconnect openconnect-strings.txt file."
    exit 1
fi

if ! grep -q "Project-Id-Version: openconnect " "${POTFILE}"; then
    echo "Error: ${POTFILE} is not a valid openconnect .pot file."
    exit 1
fi

COMMIT="$(git rev-parse HEAD)"
if ! echo ${COMMIT} | grep -E -q "[a-f0-9]{40}"; then
    echo "Error: Failed to fetch commit ID from git"
    exit 1
fi
# Truncate to ten characters
COMMIT="${COMMIT:0:10}"
GITWEB="https://git.infradead.org/users/dwmw2/openconnect.git/blob/${COMMIT}:/"

GENFILE=$(mktemp "${OUTFILE}.XXXXXX")
if [ -z "${GENFILE}" ]; then
    echo "Error: Failed to create temporary file"
    exit 1
fi

trap 'rm -f "${GENFILE}"' EXIT

cat >$GENFILE <<EOF
This file contains strings from the OpenConnect VPN client, found at
https://www.infradead.org/openconnect/ and browsable in gitweb at
https://git.infradead.org/users/dwmw2/openconnect.git

We do this because NetworkManager-openconnect authentication dialog
uses a lot of strings from libopenconnect, which also need to be
translated too if the user is to have a fully localised experience.

For translators looking to see source comments in their original context
in order to translate them properly, the URLs by each one will give a
link to the original source code.
EOF

cat "${POTFILE}" |
while read -r line; do
    case "$line" in
	"#:"*)
	    echo >>$GENFILE
	    # FIXME: If it was already in openconnect-strings.txt can we keep the
	    #   previous URL instead of using the latest commit, to reduce churn?
	    for src in ${line###: }; do
		echo "// ${GITWEB}${src%%:*}#l${src##*:}" >>$GENFILE
	    done
	    real_strings=yes
	    ;;
	"msgid "*)
	    if [ "$real_strings" = "yes" ]; then
		echo -n "_(${line##msgid }" >>$GENFILE
		in_msgid=yes
	    fi
	    ;;
	"msgstr "*|"")
	    if [ "$in_msgid" = "yes" ]; then
		in_msgid=no
		echo ");" >>$GENFILE
	    fi
	    ;;
	*)
	    if [ "$in_msgid" = "yes" ]; then
		echo >>$GENFILE
		echo -n "$line" >>$GENFILE
	    fi
	    ;;
   esac
done
MESSAGES=$(grep -c "^_(" ${GENFILE})

echo "Got $MESSAGES messages from openconnect.pot"

if [ "$MESSAGES" -lt 100 ]; then
    echo "Fewer than 100 messages? Something went wrong"
    exit 1
fi

# Ignore differences in the gitweb URLs; those will change for every commit.
NEWSHA=$(grep -v ^// ${GENFILE} | sha1sum)
OLDSHA=$(grep -v ^// ${OUTFILE} | sha1sum)
if [ "${NEWSHA}" != "${OLDSHA}" ]; then
    echo New strings in openconnect-strings.txt
    mv "${GENFILE}" "${OUTFILE}"
else
    echo No new strings. Not changing openconnect-strings.txt
fi
