#!/bin/sh
# Enable Swap script
# $1: usb path  $2: Swap enable/disable

umask 077
set -f
LC_ALL=C
export LC_ALL

fail()
{
	echo "USB swap: $*" >&2
	exit 1
}

safe_directory()
{
	set -- $(ls -ldn .) || return 1
	[ "$3:$4" = "0:0" ] || return 1
	case "$1" in
		d????w*|d???????w*) return 1 ;;
		d*) return 0 ;;
	esac
	return 1
}

safe_ancestors()
(
	while :; do
		set -- $(ls -ldn .) || exit 1
		[ "$3:$4" = "0:0" ] || exit 1
		case "$1" in
			d????w*|d???????w*)
				case "$1" in *[tT]) ;; *) exit 1 ;; esac ;;
			d*) ;;
			*) exit 1 ;;
		esac
		[ "$(pwd -P)" = / ] && exit 0
		cd .. || exit 1
	done
)

safe_file()
{
	[ ! -L "$SWAP_FILE" ] && [ -f "$SWAP_FILE" ] || return 1
	set -- $(ls -ldn "$SWAP_FILE") || return 1
	[ "$2:$3:$4" = "1:0:0" ]
}

secure_file()
{
	safe_file || return 1
	chown 0:0 "$SWAP_FILE" && chmod 0600 "$SWAP_FILE" || return 1
	set -- $(ls -ldn "$SWAP_FILE") || return 1
	[ "$1:$2:$3:$4" = "-rw-------:1:0:0" ]
}

is_active()
{
	SWAP_CHECK_PATH="$1" awk 'NR > 1 {
		name = $1
		path = ENVIRON["SWAP_CHECK_PATH"]
		encoded = ""
		for (position = 1; position <= length(path); position++) {
			character = substr(path, position, 1)
			if (character == "\\") character = "\\134"
			else if (character == " ") character = "\\040"
			else if (character == "\t") character = "\\011"
			else if (character == "\n") character = "\\012"
			encoded = encoded character
		}
		if (name == encoded) found = 1
	} END { exit !found }' /proc/swaps
}

protect_directory()
{
	(cd .. && safe_ancestors) || return 1
	set -- $(ls -ldn .)
	[ "$3:$4" = "0:0" ] || return 1
	if ! safe_directory; then
		chmod +t . || return 1
	fi
	safe_ancestors
}

retire_legacy()
(
	cd -P "$1" || exit 1
	if [ -e "$SWAP_FILE" ] || [ -L "$SWAP_FILE" ]; then
		protect_directory && secure_file || fail "unsafe legacy swap file"
		legacy_path="$(pwd -P)/$SWAP_FILE"
		if is_active "$legacy_path"; then
			swapoff "$legacy_path" || fail "cannot deactivate legacy swap; keeping file"
		fi
		rm -f "$SWAP_FILE" || fail "cannot remove legacy swap file"
	fi
)

SWAP_FILE=$(nvram get apps_swap_file)
case "$SWAP_FILE" in
	''|.|..|-*|*[!a-zA-Z0-9._-]*) fail "invalid swap filename" ;;
esac

EXISTING_ONLY=0
if [ "$1" = --activate ]; then
	[ "$#" = 2 ] || fail "expected one existing swap path"
	case "$2" in
		/*/.asus-swap/"$SWAP_FILE") USB_PATH=${2%/.asus-swap/*} ;;
		*) fail "fstab swap files must use .asus-swap/$SWAP_FILE" ;;
	esac
	SWAP_ENABLE=1
	EXISTING_ONLY=1
else
	USB_PATH=${1:-/tmp/mnt/$(nvram get usb_path1_act)}
	SWAP_ENABLE=${2:-$(nvram get apps_swap_enable)}
fi
cd -P "$USB_PATH" || fail "cannot open USB directory"
APPS_FOLDER=$(nvram get apps_install_folder)
case "$APPS_FOLDER" in
	''|.|..|-*|.asus-swap|*[!a-zA-Z0-9._-]*) APPS_FOLDER= ;;
esac
if [ "$SWAP_ENABLE" != 1 ] && [ ! -e .asus-swap ] && [ ! -L .asus-swap ] &&
   [ ! -e "$SWAP_FILE" ] && [ ! -L "$SWAP_FILE" ]; then
	if [ -z "$APPS_FOLDER" ] || { [ ! -e "$APPS_FOLDER/$SWAP_FILE" ] && [ ! -L "$APPS_FOLDER/$SWAP_FILE" ]; }; then
		exit 0
	fi
fi
protect_directory || fail "filesystem cannot protect USB directory entries"
USB_ROOT=$(pwd -P)
if [ "$EXISTING_ONLY" = 1 ]; then
	[ -d .asus-swap ] || fail "missing private swap directory"
fi
mkdir .asus-swap 2>/dev/null || [ -d .asus-swap ] || fail "cannot create private swap directory"
[ ! -L .asus-swap ] || fail "unsafe private swap directory"
cd -P .asus-swap || fail "cannot open private swap directory"
safe_directory || fail "filesystem cannot protect private swap directory"
chmod 0700 . || fail "cannot secure private swap directory"
set -- $(ls -ldn .)
[ "$1:$3:$4" = "drwx------:0:0" ] || fail "unsafe private swap directory permissions"
exec 9< .
flock -x 9 || fail "cannot lock swap lifecycle"
SWAP_PATH="$(pwd -P)/$SWAP_FILE"

retire_legacy "$USB_ROOT" || fail "cannot retire exposed USB swap"
case "$APPS_FOLDER" in
	''|.|..|-*|.asus-swap|*[!a-zA-Z0-9._-]*) ;;
	*)
		if [ -e "$USB_ROOT/$APPS_FOLDER/$SWAP_FILE" ] || [ -L "$USB_ROOT/$APPS_FOLDER/$SWAP_FILE" ]; then
			[ ! -L "$USB_ROOT/$APPS_FOLDER" ] || fail "unsafe legacy app directory"
			retire_legacy "$USB_ROOT/$APPS_FOLDER" || fail "cannot retire exposed app swap"
		fi ;;
esac

if [ "$SWAP_ENABLE" != 1 ]; then
	if [ -e "$SWAP_FILE" ] || [ -L "$SWAP_FILE" ]; then
		secure_file || fail "unsafe swap file"
		if is_active "$SWAP_PATH"; then
			swapoff "$SWAP_PATH" || fail "cannot deactivate swap; keeping file"
		fi
		rm -f "$SWAP_FILE" || fail "cannot remove swap file"
	fi
	exit 0
fi

if [ -e "$SWAP_FILE" ] || [ -L "$SWAP_FILE" ]; then
	secure_file || fail "unsafe swap file"
	is_active "$SWAP_PATH" && exit 0
elif [ "$EXISTING_ONLY" = 1 ]; then
	fail "missing fstab swap file"
fi

SWAP_THRESHOLD=$(nvram get apps_swap_threshold)
SWAP_SIZE=$(nvram get apps_swap_size)
mem_size=$(free | sed '1,3d' | awk '{print $4}')
case "$SWAP_SIZE" in ''|*[!0-9]*) fail "invalid swap size" ;; esac
case "$SWAP_THRESHOLD" in *[!0-9]*) fail "invalid swap threshold" ;; esac
if [ "$EXISTING_ONLY" != 1 ] && [ -n "$SWAP_THRESHOLD" ] && [ "$mem_size" -ge "$SWAP_THRESHOLD" ]; then
	exit 0
fi

if [ -e "$SWAP_FILE" ] || [ -L "$SWAP_FILE" ]; then
	secure_file || fail "unsafe swap file"
else
	pool_size=$(df . | sed '1d' | awk '{print $4}')
	if [ "$pool_size" -le "$SWAP_SIZE" ]; then
		SWAP_SIZE=$((pool_size - pool_size % 10000))
	fi
	swap_count=$((SWAP_SIZE / 1000 - 1))
	[ "$swap_count" -gt 0 ] || fail "not enough partition space"
	FINAL_SWAP_FILE=$SWAP_FILE
	SWAP_FILE=$SWAP_FILE.pending
	[ ! -e "$SWAP_FILE" ] && [ ! -L "$SWAP_FILE" ] || fail "incomplete swap allocation requires cleanup"
	(set -C; : > "$SWAP_FILE") || fail "cannot create swap file exclusively"
	PENDING_SWAP_FILE=$SWAP_FILE
	trap 'if [ -n "$PENDING_SWAP_FILE" ]; then rm -f "$PENDING_SWAP_FILE"; fi' EXIT
	trap 'exit 1' HUP INT TERM
	secure_file || fail "filesystem cannot protect swap file"
	dd if=/dev/zero "of=$SWAP_FILE" bs=1M "count=$swap_count" || fail "cannot allocate swap file"
	mkswap "$SWAP_FILE" || fail "cannot initialize swap file"
	mv "$SWAP_FILE" "$FINAL_SWAP_FILE" || fail "cannot publish swap file"
	PENDING_SWAP_FILE=
	SWAP_FILE=$FINAL_SWAP_FILE
fi
secure_file || fail "unsafe swap file permissions"
swapon "$SWAP_PATH" || fail "cannot activate swap file"

if ! nvram get rc_support | grep -qi bcmhnd; then
	echo 1 > /proc/sys/vm/drop_caches
fi

