#!/bin/sh
INSTANCE=$1
PROTO=$2
METHOD=$3

http_servers="api.ipify.org ident.me"
stun_servers="stun.l.google.com:19302 stun.cloudflare.com:3478"

if [ "$PROTO" = "wireguard" ] ; then
	IFACE="wgc$INSTANCE"
else
	IFACE="tun1$INSTANCE"
fi

is_ipv4() {
	case "$1" in
		""|*[!0-9.]* ) return 1 ;;
	esac
	[ "${#1}" -le 15 ] || return 1
	printf '%s\n' "$1" | awk -F. '
		NF != 4 { exit 1 }
		{
			for (i = 1; i <= 4; i++) {
				if (length($i) > 3 || ($i != "0" && $i ~ /^0/) || $i + 0 > 255)
					exit 1
			}
		}'
}

if [ "$METHOD" = "stun" ] ; then
	for server in $stun_servers; do
		if result=$(/usr/sbin/ministun -t 5000 -c 1 -i "$IFACE" "$server" 2>/dev/null) && is_ipv4 "$result"; then
			break
		fi
		result="unknown"
	done
else
	for server in $http_servers; do
		if result=$(/usr/sbin/curl -4 -m 5 -sf --interface "$IFACE" "https://$server" 2>/dev/null) && is_ipv4 "$result"; then
			break
		fi
		result="unknown"
	done
fi

is_ipv4 "$result" || result="unknown"

nvram set "vpn_client${INSTANCE}_rip=$result"
