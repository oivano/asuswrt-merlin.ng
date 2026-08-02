#!/bin/sh
#
#
# This is a "library" of sorts for use by the other FRR shell scripts.  It
# has most of the daemon start/stop logic, but expects the following shell
# functions/commands to be provided by the "calling" script:
#
#   log_success_msg
#   log_warning_msg
#   log_failure_msg
#
# (coincidentally, these are LSB standard functions.)
#
# Sourcing this file in a shell script will load FRR config variables but
# not perform any action.  Note there is an "exit 1" if the main config
# file does not exist.
#
# This script should be installed in  /usr/sbin/frrcommon.sh
# FRR_PATHSPACE is passed in from watchfrr
suffix="${FRR_PATHSPACE:+/${FRR_PATHSPACE}}"
nsopt="${FRR_PATHSPACE:+-N ${FRR_PATHSPACE}}"

PATH=/bin:/usr/bin:/sbin:/usr/sbin
D_PATH="/usr/sbin"
DEFAULT_C_PATH="/etc"
C_PATH="$DEFAULT_C_PATH"
PRIMARY_C_PATH=""
DAEMONS_C_PATH=""
RUNTIME_C_PATH=""
V_PATH="/var/run/frr"
VTYSH="/usr/sbin/vtysh"
FRR_USER="nobody"
FRR_GROUP="nobody"
FRR_VTY_GROUP=""
FRR_CONFIG_MODE="0600"
FRR_DEFAULT_PROFILE="traditional"
MAX_FDS=1024
STOP_GRACE_TIMEOUT=10
STOP_TERM_TIMEOUT=5
STOP_KILL_TIMEOUT=10

if [ -n "$FRR_CONFIG_DIR" ]; then
	cfg_dir="$FRR_CONFIG_DIR${suffix}"
	if [ -d "$cfg_dir" ]; then
		PRIMARY_C_PATH="$cfg_dir"
	fi
elif command -v nvram >/dev/null 2>&1; then
	NVRAM_FRR_CONFIG_DIR="$(nvram get frr_config_dir 2>/dev/null)"

	case "$NVRAM_FRR_CONFIG_DIR" in
	/*)
		case "$NVRAM_FRR_CONFIG_DIR" in
		*..*) NVRAM_FRR_CONFIG_DIR="" ;;
		esac
		;;
	*)
		NVRAM_FRR_CONFIG_DIR=""
		;;
	esac

	while [ -n "$NVRAM_FRR_CONFIG_DIR" ] && [ "$NVRAM_FRR_CONFIG_DIR" != "/" ]; do
		old_cfg_dir="$NVRAM_FRR_CONFIG_DIR"
		NVRAM_FRR_CONFIG_DIR="${NVRAM_FRR_CONFIG_DIR%/}"
		NVRAM_FRR_CONFIG_DIR="${NVRAM_FRR_CONFIG_DIR%.}"
		[ "$NVRAM_FRR_CONFIG_DIR" = "$old_cfg_dir" ] && break
	done

	[ "$NVRAM_FRR_CONFIG_DIR" = "/etc" ] && NVRAM_FRR_CONFIG_DIR=""
	if [ -n "$NVRAM_FRR_CONFIG_DIR" ]; then
		cfg_dir="$NVRAM_FRR_CONFIG_DIR${suffix}"
		if [ -d "$cfg_dir" ]; then
			PRIMARY_C_PATH="$cfg_dir"
		fi
	fi
fi

if [ -n "$PRIMARY_C_PATH" ] && [ -r "$PRIMARY_C_PATH/daemons" ]; then
	DAEMONS_C_PATH="$PRIMARY_C_PATH"
else
	DAEMONS_C_PATH="$DEFAULT_C_PATH"
fi

if [ -n "$PRIMARY_C_PATH" ] && [ -r "$PRIMARY_C_PATH/frr.conf" ]; then
	# Prefer integrated config when present in configured directory.
	RUNTIME_C_PATH="$PRIMARY_C_PATH"
elif [ -r "$DEFAULT_C_PATH/frr.conf" ]; then
	RUNTIME_C_PATH="$DEFAULT_C_PATH"
elif [ -n "$PRIMARY_C_PATH" ]; then
	RUNTIME_C_PATH="$PRIMARY_C_PATH"
else
	RUNTIME_C_PATH="$DEFAULT_C_PATH"
fi

C_PATH="$DAEMONS_C_PATH"

# ORDER MATTERS FOR $DAEMONS!
# - keep zebra first
# - watchfrr does NOT belong in this list
# Only compiled daemons: zebra bgpd ospfd staticd bfdd

DAEMONS="zebra bgpd ospfd staticd bfdd"
RELOAD_SCRIPT="$D_PATH/frr-reload.py"

#
# general helpers
#

debug() {
	[ -n "$watchfrr_debug" ] || return 0

	printf '%s %s(%s):' "`date +%Y-%m-%dT%H:%M:%S.%N`" "$0" $$ >&2
	# this is to show how arguments are split regarding whitespace & co.
	# (e.g. for use with `debug "message" "$@"`)
	while [ $# -gt 0 ]; do
		printf ' "%s"' "$1" >&2
		shift
	done
	printf '\n' >&2
}

is_early_boot() {
	local uptime

	[ -r /proc/uptime ] || return 0
	read uptime _ < /proc/uptime || return 0
	uptime="${uptime%%.*}"
	[ -n "$uptime" ] || return 0
	[ "$uptime" -lt 300 ]
}

frr_ppp_wan_configured() {
	local proto key

	command -v nvram >/dev/null 2>&1 || return 1

	for key in wan_proto wan0_proto wan1_proto wan2_proto wan3_proto; do
		proto="$(nvram get "$key" 2>/dev/null)"
		case "$proto" in
		pppoe|pptp|l2tp)
			return 0
			;;
		esac
	done

	return 1
}

wait_for_pppd_boot_ready() {
	local timeout

	frr_ppp_wan_configured || return 0
	is_early_boot || return 0

	timeout="${frr_pppd_wait_timeout:-90}"
	case "$timeout" in
	''|*[!0-9]*)
		timeout=90
		;;
	esac

	if pidof pppd >/dev/null 2>&1; then
		return 0
	fi

	log_warning_msg "FRR: waiting for pppd before startup"
	while [ "$timeout" -gt 0 ]; do
		if pidof pppd >/dev/null 2>&1; then
			log_success_msg "FRR: pppd detected, continuing startup"
			return 0
		fi
		sleep 1
		timeout=$((timeout - 1))
	done

	log_warning_msg "FRR: pppd not detected within timeout, starting anyway"
	return 0
}

chownfrr() {
	[ -n "$FRR_USER" ] && chown "$FRR_USER" "$1"
	[ -n "$FRR_GROUP" ] && chgrp "$FRR_GROUP" "$1"
	[ -n "$FRR_CONFIG_MODE" ] && chmod "$FRR_CONFIG_MODE" "$1"
	if [ -d "$1" ]; then
		chmod u+x "$1"
	fi
}

vtysh_b () {
	[ "$1" = "watchfrr" ] && return 0
	[ -r "$RUNTIME_C_PATH/frr.conf" ] || return 0
	if [ -n "$1" ]; then
		"$VTYSH" --config_dir "$RUNTIME_C_PATH" `echo $nsopt` -b -d "$1"
	else
		"$VTYSH" --config_dir "$RUNTIME_C_PATH" `echo $nsopt` -b
	fi
}

daemon_inst() {
	# note this sets global variables ($dmninst, $daemon, $inst)
	dmninst="$1"
	daemon="${dmninst%-*}"
	inst=""
	[ "$daemon" != "$dmninst" ] && inst="${dmninst#*-}"
}

daemon_list() {
	# note $1 and $2 specify names for global variables to be set
	local enabled disabled evar dvar
	enabled=""
	disabled=""
	evar="$1"
	dvar="$2"

	for daemon in $DAEMONS; do
		eval cfg=\$$daemon
		eval inst=\$${daemon}_instances
		[ "$daemon" = zebra -o "$daemon" = staticd ] && cfg=yes
		if [ -n "$cfg" -a "$cfg" != "no" -a "$cfg" != "0" ]; then
			if ! daemon_prep "$daemon" "$inst"; then
				continue
			fi
			debug "$daemon enabled"
#			enabled="$enabled $daemon"

			if [ -n "$inst" ]; then
				debug "$daemon multi-instance $inst"
				oldifs="${IFS}"
				IFS="${IFS},"
				for i in $inst; do
					enabled="$enabled $daemon-$i"
				done
				IFS="${oldifs}"
			else
				enabled="$enabled $daemon"
			fi
		else
			debug "$daemon disabled"
			disabled="$disabled $daemon"
		fi
	done

	enabled="${enabled# }"
	disabled="${disabled# }"
	[ -z "$evar" ] && echo "$enabled"
	[ -n "$evar" ] && eval $evar="\"$enabled\""
	[ -n "$dvar" ] && eval $dvar="\"$disabled\""
}

#
# individual daemon management
#

daemon_prep() {
	local daemon inst cfg
	daemon="$1"
	inst="$2"
	[ "$daemon" = "watchfrr" ] && return 0
	[ -x "$D_PATH/$daemon" ] || {
		log_failure_msg "cannot start $daemon${inst:+ (instance $inst)}: daemon binary not installed"
		return 1
	}
	[ -r "$RUNTIME_C_PATH/frr.conf" ] && return 0

	cfg="$RUNTIME_C_PATH/$daemon${inst:+-$inst}.conf"
	if [ ! -r "$cfg" ]; then
		touch "$cfg" || {
			log_failure_msg "cannot prepare $daemon${inst:+ (instance $inst)} config: failed to create $cfg"
			return 1
		}
		chownfrr "$cfg" || {
			log_failure_msg "cannot prepare $daemon${inst:+ (instance $inst)} config: failed to set ownership/permissions on $cfg"
			return 1
		}
	fi
	return 0
}

daemon_start() {
	local dmninst daemon inst args instopt wrap bin
	daemon_inst "$1"

	[ "$daemon" = "watchfrr" ] && wait_for_pppd_boot_ready

	ulimit -n $MAX_FDS > /dev/null 2> /dev/null
	daemon_prep "$daemon" "$inst" || return 1
	if test ! -d "$V_PATH"; then
		mkdir -p "$V_PATH"
		chown $FRR_USER "$V_PATH"
	fi

	eval wrap="\$${daemon}_wrap"
	bin="$D_PATH/$daemon"
	instopt="${inst:+-n $inst}"
	eval args="\$${daemon}_options"

	if eval "$all_wrap $wrap $bin $nsopt -d $frr_global_options $instopt $args"; then
		log_success_msg "Started $dmninst"
		vtysh_b "$daemon"
	else
		log_failure_msg "Failed to start $dmninst!"
	fi
}

wait_for_pid_exit() {
	local pid timeout

	pid="$1"
	timeout="$2"

	while kill -0 "$pid" 2>/dev/null; do
		[ "$timeout" -gt 0 ] || return 1
		sleep 1
		timeout=$((timeout - 1))
	done

	return 0
}

flush_frr_routes() {
	local ip_cmd flushed proto

	ip_cmd="$(command -v ip 2>/dev/null)"
	[ -n "$ip_cmd" ] || ip_cmd="/sbin/ip"
	[ -x "$ip_cmd" ] || return 0

	for proto in 11 42 186 187 188 189 190 191 192 193 194 195 196 197 198; do
		if "$ip_cmd" route flush proto "$proto" >/dev/null 2>&1; then
			flushed=1
		fi
		if "$ip_cmd" -6 route flush proto "$proto" >/dev/null 2>&1; then
			flushed=1
		fi
	done

	[ -n "$flushed" ] && log_success_msg "Flushed FRR kernel routes"
}

daemon_stop() {
	local dmninst daemon inst pidfile vtyfile pid fail
	daemon_inst "$1"

	pidfile="$V_PATH/$daemon${inst:+-$inst}.pid"
	vtyfile="$V_PATH/$daemon${inst:+-$inst}.vty"

	[ -r "$pidfile" ] || fail="pid file not found"
	[ -z "$fail" ] && pid="`cat \"$pidfile\"`"
	[ -z "$fail" -a -z "$pid" ] && fail="pid file is empty"
	[ -n "$fail" ] || kill -0 "$pid" 2>/dev/null || fail="pid $pid not running"

	if [ -n "$fail" ]; then
		case "$fail" in
		"pid file not found"|"pid file is empty"|"pid "*" not running")
			# Already stopped/stale pid state, do not treat as a stop failure.
			log_success_msg "$dmninst already stopped ($fail)"
			return 0
			;;
		esac
		log_failure_msg "Cannot stop $dmninst: $fail"
		return 1
	fi

	debug "kill -2 $pid"
	kill -2 "$pid" 2>/dev/null || fail="failed to send SIGINT"
	if [ -z "$fail" ] && ! wait_for_pid_exit "$pid" "$STOP_GRACE_TIMEOUT"; then
		log_warning_msg "Timed out waiting for $dmninst to exit after SIGINT, escalating"
		debug "kill -15 $pid"
		kill -15 "$pid" 2>/dev/null || true
		if ! wait_for_pid_exit "$pid" "$STOP_TERM_TIMEOUT"; then
			log_warning_msg "$dmninst did not exit after SIGTERM, sending SIGKILL"
			debug "kill -9 $pid"
			kill -9 "$pid" 2>/dev/null || true
			wait_for_pid_exit "$pid" "$STOP_KILL_TIMEOUT" || fail="pid $pid still running"
		fi
	fi
	[ -z "$fail" ] || log_failure_msg "Failed to stop $dmninst: $fail"
	if kill -0 "$pid" 2>/dev/null; then
		log_failure_msg "Failed to stop $dmninst, pid $pid still running"
		still_running=1
		return 1
	else
		log_success_msg "Stopped $dmninst"
		rm -f "$pidfile"
		return 0
	fi
}

daemon_status() {
	local dmninst daemon inst pidfile pid fail
	daemon_inst "$1"

	pidfile="$V_PATH/$daemon${inst:+-$inst}.pid"

	[ -r "$pidfile" ] || return 3
	pid="`cat \"$pidfile\"`"
	[ -z "$pid" ] && return 1
	kill -0 "$pid" 2>/dev/null || return 1
	return 0
}

stop_watchfrr_first() {
	local rv

	daemon_status watchfrr
	rv=$?
	if [ "$rv" -eq 3 ] || [ "$rv" -eq 1 ]; then
		return 0
	fi
	[ "$rv" -eq 0 ] || return "$rv"

	daemon_stop watchfrr
}

print_status() {
	daemon_status "$1"
	rv=$?
	if [ "$rv" -eq 0 ]; then
		log_success_msg "Status of $1: running"
	else
		log_failure_msg "Status of $1: FAILED"
	fi
	return $rv
}

#
# all-daemon commands
#

all_start() {
	daemon_list daemons
	for dmninst in $daemons; do
		daemon_start "$dmninst"
	done
}

all_stop() {
	local reversed keep_routes rc

	daemon_list daemons disabled
	[ "$1" = "--reallyall" ] && daemons="$daemons $disabled"
	[ "$2" = "--keep-routes" ] && keep_routes=1

	reversed=""
	for dmninst in $daemons; do
		reversed="$dmninst $reversed"
	done

	for dmninst in $reversed; do
		daemon_stop "$dmninst"
		rc=$?
		if [ "$rc" -ne 0 ]; then
			still_running=1
		fi
	done
	[ -z "$still_running" ] && [ -z "$keep_routes" ] && flush_frr_routes
}

all_status() {
	local fail

	daemon_list daemons
	fail=0
	for dmninst in $daemons; do
		print_status "$dmninst" || fail=1
	done
	return $fail
}

#
# config sourcing
#

load_old_config() {
	oldcfg="$1"
	[ -r "$oldcfg" ] || return 0
	[ -s "$oldcfg" ] || return 0
	grep -v '^[[:blank:]]*\(#\|$\)' "$oldcfg" > /dev/null || return 0

	log_warning_msg "Reading deprecated $oldcfg.  Please move its settings to $C_PATH/daemons and remove it."

	# save off settings from daemons for the OR below
	for dmn in $DAEMONS; do eval "_new_$dmn=\${$dmn:-no}"; done

	. "$oldcfg"

	# OR together the daemon enabling options between config files
	for dmn in $DAEMONS; do eval "test \$_new_$dmn != no && $dmn=\$_new_$dmn; unset _new_$dmn"; done
}

[ -r "$DAEMONS_C_PATH/daemons" ] || {
	if [ -n "$PRIMARY_C_PATH" ]; then
		log_failure_msg "cannot run $@: $PRIMARY_C_PATH/daemons and $DEFAULT_C_PATH/daemons do not exist"
	else
		log_failure_msg "cannot run $@: $DEFAULT_C_PATH/daemons does not exist"
	fi
	exit 1
}
. "$DAEMONS_C_PATH/daemons"

if [ -z "$FRR_PATHSPACE" ] && [ -z "$PRIMARY_C_PATH" ]; then
	load_old_config "$DAEMONS_C_PATH/daemons.conf"
	load_old_config "/etc/default/frr"
	load_old_config "/etc/sysconfig/frr"
fi

if { declare -p watchfrr_options 2>/dev/null || true; } | grep -q '^declare \-a'; then
	log_warning_msg "watchfrr_options contains a bash array value." \
		"The configured value is intentionally ignored since it is likely wrong." \
		"Please remove or fix the setting."
	unset watchfrr_options
fi

if test -z "$frr_profile"; then
	# try to autodetect config profile
	if test -d /etc/cumulus; then
		frr_profile=datacenter
	# elif test ...; then
	# -- add your distro/system here
	elif test -n "$FRR_DEFAULT_PROFILE"; then
		frr_profile="$FRR_DEFAULT_PROFILE"
	fi
fi
test -n "$frr_profile" && frr_global_options="$frr_global_options -F $frr_profile"


#
# other defaults and dispatch
#

frrcommon_main() {
	local cmd

	debug "frrcommon_main" "$@"

	cmd="$1"
	shift

	if [ "$1" = "all" -o -z "$1" ]; then
		case "$cmd" in
		start)	all_start;;
		stop)	all_stop;;
		restart)
			all_stop
			all_start
			;;
		*)	$cmd "$@";;
		esac
	else
		case "$cmd" in
		start)	daemon_start "$@";;
		stop)	daemon_stop "$@";;
		restart)
			daemon_stop "$@"
			daemon_start "$@"
			;;
		*)	$cmd "$@";;
		esac
	fi
}
