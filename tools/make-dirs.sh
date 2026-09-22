#!/bin/bash
set -euo pipefail

REPO=${REPO:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
BUILD_NAME=${BUILD_NAME:-DSL-AC68U}

if [ "$BUILD_NAME" != "DSL-AC68U" ]; then
	echo "Error: only DSL-AC68U is supported" >&2
	exit 1
fi

for directory in \
	release/src/router/httpd/prebuild \
	release/src/router/rc/prebuild \
	release/src/router/shared/prebuild \
	release/src/router/sw-hw-auth/prebuild \
	release/src/router/bwdpi_source/asus/prebuild \
	release/src/router/bwdpi_source/asus_sql/prebuild \
	release/src/router/bwdpi_source/prebuild \
	release/src/router/cfg_mnt/prebuild \
	release/src/router/dblog/commands/prebuild \
	release/src/router/dblog/daemon/prebuild \
	release/src/router/libasc/prebuild \
	release/src/router/libasuslog/prebuild \
	release/src/router/libbcm/prebuilt \
	release/src/router/libletsencrypt/prebuild \
	release/src/router/networkmap/prebuild \
	release/src/router/nt_center/actMail/prebuild \
	release/src/router/nt_center/lib/prebuild \
	release/src/router/nt_center/prebuild \
	release/src/router/protect_srv/lib/prebuild \
	release/src/router/protect_srv/prebuild \
	release/src/router/sysstate/commands/prebuild \
	release/src/router/sysstate/log_daemon/prebuild \
	release/src/router/wlc_nt/prebuild; do
	mkdir -p "$REPO/$directory/$BUILD_NAME"
done
