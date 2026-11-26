#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../release/release-version.sh"

check_version() {
    local version=$1 major=$2 minor=$3
    parse_release_version "$version"
    [[ $MAJOR_VER == "$major" && $MINOR_VER == "$minor" ]] || {
        echo "FAIL $version: got $MAJOR_VER/$MINOR_VER, expected $major/$minor" >&2
        exit 1
    }
}

check_version 386.16-ion 386.16 0
check_version 386.15_4-ion 386.15 4
check_version 386.15_12-ion 386.15 12

parse_release_version 386.16-ion
[[ $ARTIFACT_EXTENDNO == ion ]] || {
    echo "FAIL 386.16-ion artifact suffix: $ARTIFACT_EXTENDNO" >&2
    exit 1
}
parse_release_version 386.15_4-ion
[[ $ARTIFACT_EXTENDNO == 4-ion ]] || {
    echo "FAIL 386.15_4-ion artifact suffix: $ARTIFACT_EXTENDNO" >&2
    exit 1
}

if parse_release_version 386.15_4-ion-beta1 >/dev/null 2>&1; then
    echo "FAIL prerelease tag was accepted" >&2
    exit 1
fi

if parse_release_version not-a-version >/dev/null 2>&1; then
    echo "FAIL invalid tag was accepted" >&2
    exit 1
fi

echo "release-version tests passed"
