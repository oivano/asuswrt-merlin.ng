#!/bin/sh

#GOOGLE DOMAINS RESPONSE DEFINE
RESPONSE_SUCCESS_GOOD="good"       # The update was successful. Followed by a space and the updated IP address. You should not attempt another update until your IP address changes.
RESPONSE_SUCCESS_NOCHG="nochg"     # The supplied IP address is already set for this host. You should not attempt another update until your IP address changes.
RESPONSE_ERROR_NOHOST="nohost"     # The hostname does not exist, or does not have Dynamic DNS enabled.
RESPONSE_ERROR_BADAUTH="badauth"   # The username / password combination is not valid for the specified host.
RESPONSE_ERROR_NOTFQDN="notfqdn"   # The supplied hostname is not a valid fully-qualified domain name.
RESPONSE_ERROR_BADAGENT="badagent" # Your Dynamic DNS client is making bad requests. Ensure the user agent is set in the request, and that you’re only attempting to set an IPv4 address. IPv6 is not supported.
RESPONSE_ERROR_ABUSE="abuse"       # Dynamic DNS access for the hostname has been blocked due to failure to interpret previous responses correctly.
RESPONSE_ERROR_911="911"           # An error happened on our end. Wait 5 minutes and retry.

Successful()
{
	#Code:200, LANHostConfig_x_DDNS_alarm_3=Registration is successful.
	nvram set ddns_return_code=200
	nvram set ddns_return_code_chk=200
	ddns_updated
}

Success_NoChange()
{
	#Code:no_change, LANHostConfig_x_DDNS_alarm_nochange=Both hostname & IP address have not changed since the last update.
	nvram set ddns_return_code=no_change
	nvram set ddns_return_code_chk=no_change
	ddns_updated
}

badauth()
{
	#Code:auth_fail, qis_fail_desc1=Authentication failed.
	nvram set ddns_return_code=auth_fail
	nvram set ddns_return_code_chk=auth_fail
}

unvalid_request()
{
	#Code:401, LANHostConfig_x_DDNS_alarm_10=Unauthorized registration request! 
	nvram set ddns_return_code=401
	nvram set ddns_return_code_chk=401
}

otherfail()
{
	#Code:unknow_error, LANHostConfig_x_DDNS_alarm_2=Request error! Please try again.
	nvram set ddns_return_code=unknown_error
	nvram set ddns_return_code_chk=unknown_error
}

main()
{
	DDNS_USER=$(nvram get ddns_username_x)
	DDNS_PASSWD=$(nvram get ddns_passwd_x)
	NL='
'
	CR=$(printf '\r')
	case "$DDNS_USER$DDNS_PASSWD" in
		*"$NL"*|*"$CR"*)
			unset DDNS_USER DDNS_PASSWD
			otherfail
			return
			;;
	esac

	umask 077
	attempt=0
	while [ "$attempt" -lt 10 ]; do
		wget_dir="/tmp/google-ddns-$$-$attempt"
		if mkdir "$wget_dir" 2>/dev/null; then
			break
		fi
		attempt=$((attempt + 1))
	done
	if [ "$attempt" -ge 10 ]; then
		unset DDNS_USER DDNS_PASSWD
		otherfail
		return
	fi
	wget_config="$wget_dir/wgetrc"
	trap 'rm -f "$wget_config"; rmdir "$wget_dir" 2>/dev/null' 0
	trap 'exit 1' HUP INT TERM
	if ! printf 'httpuser = %s\nhttppassword = %s\n' "$DDNS_USER" "$DDNS_PASSWD" > "$wget_config" ||
	   ! chmod 600 "$wget_config"; then
		unset DDNS_USER DDNS_PASSWD
		otherfail
		return
	fi
	unset DDNS_USER DDNS_PASSWD

	result=$(wget --config="$wget_config" -S "https://domains.google.com/nic/update?hostname=$HOST&myip=$CurrWANIP" -O -)
	rm -f "$wget_config"
	rmdir "$wget_dir" 2>/dev/null
	
	sleep 1;

	if [ "$result" == "${RESPONSE_SUCCESS_GOOD} ${CurrWANIP}" ]; then 
		Successful
	elif [ "$result" == "${RESPONSE_SUCCESS_NOCHG} ${CurrWANIP}" ]; then
		Success_NoChange
	elif [ "$result" == "${RESPONSE_ERROR_BADAUTH}" ]; then
		badauth
	elif [ "$result" == "${RESPONSE_ERROR_NOTFQDN}" ] -o
	     [ "$result" == "${RESPONSE_ERROR_BADAGENT}" ]; then
		unvalid_request
	else 
		otherfail
	fi
}


usage()
{
	echo "Usage: $0 GDNS_Name WANIP"
}

if [ $# != 2 ]; then
	usage
	exit 1
fi
HOST=$1
CurrWANIP=$2
main

