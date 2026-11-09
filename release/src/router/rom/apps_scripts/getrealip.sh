#!/bin/sh
# use STUN to find the external IP.

servers="default stun.l.google.com:19302 stun.cloudflare.com:3478 stun1.l.google.com:19302 stun2.l.google.com:19302 stun3.l.google.com:19302 stun4.l.google.com:19302"
prefixes="wan0_ wan1_"

is_public_ipv4() {
	case "$1" in
		''|*[!0-9.]*|.*|*..*|*.) return 1 ;;
	esac
	old_ifs=$IFS
	IFS=.
	set -- $1
	IFS=$old_ifs
	[ "$#" -eq 4 ] || return 1
	for octet do
		case "$octet" in
			0|[1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]) ;;
			*) return 1 ;;
		esac
	done
	[ "$1" -lt 224 ] || return 1
	case "$1:$2:$3" in
		0:*:*|10:*:*|127:*:*|169:254:*|172:1[6-9]:*|172:2[0-9]:*|172:3[01]:*|192:0:0|192:0:2|192:88:99|192:168:*|198:18:*|198:19:*|198:51:100|203:0:113)
			return 1 ;;
	esac
	if [ "$1" -eq 100 ] && [ "$2" -ge 64 ] && [ "$2" -le 127 ]; then
		return 1
	fi
	return 0
}

which ministun >/dev/null || exit 1

if [ "$(nvram get wans_mode)" = "lb" ] ; then
	primary="0"
	for prefix in $prefixes; do
		state=$(nvram get ${prefix}state_t)
		sbstate=$(nvram get ${prefix}sbstate_t)
		auxstate=$(nvram get ${prefix}auxstate_t)

		# is_wan_connect()
		[ "$state" = "2" ] || continue
		[ "$sbstate" = "0" ] || continue
		[ "$auxstate" = "0" -o "$auxstate" = "2" ] || continue

		# get_wan_ifname()
		proto=$(nvram get ${prefix}proto)
		if [ "$proto" = "pppoe" -o "$proto" = "pptp" -o "$proto" = "l2tp" ] ; then
			ifname=$(nvram get ${prefix}pppoe_ifname)
		else
			ifname=$(nvram get ${prefix}ifname)
		fi

		for server in $servers; do
			[ "$server" = "default" ] && server=
			result=$(ministun -t 1000 -c 1 -i $ifname $server 2>/dev/null)
			[ $? -eq 0 ] && break
			result=
		done
		if [ -z "$result" ] || ! is_public_ipv4 "$result"; then
			state=1
			result=
		else
			state=2
		fi
		nvram set ${prefix}realip_state=$state
		nvram set ${prefix}realip_ip=$result

		wan=`echo $prefix|sed -e "s,_,,"`
		[ -z "$result" ] && echo "$wan failed." || echo "$wan external IP is $result"
	done
else
	for prefix in $prefixes; do
		primary=$(nvram get ${prefix}primary)
		[ "$primary" = "1" ] && break
	done

	[ "$primary" = "1" ] || exit 1

	# get_wan_ifname()
	proto=$(nvram get ${prefix}proto)
	if [ "$proto" = "pppoe" -o "$proto" = "pptp" -o "$proto" = "l2tp" ] ; then
		ifname=$(nvram get ${prefix}pppoe_ifname)
	else
		ifname=$(nvram get ${prefix}ifname)
	fi

	for server in $servers; do
		[ "$server" = "default" ] && server=
		result=$(ministun -t 1000 -c 1 -i $ifname $server 2>/dev/null)
		[ $? -eq 0 ] && break
		result=
	done
	if [ -z "$result" ] || ! is_public_ipv4 "$result"; then
		state=1
		result=
	else
		state=2
	fi
	nvram set ${prefix}realip_state=$state
	nvram set ${prefix}realip_ip=$result

	[ -z "$result" ] && echo "Failed." || echo "External IP is $result"
fi
