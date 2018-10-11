#!/bin/bash

HONEYPORT="1337"
MTIP="192.168.1.1"
MTUSER="blacklist"
SSHKEY="/home/mtblacklist/mtblacklist_rsa"
TIMEOUT="3d"
COMMENT="Honeypot"
ADDLIST="bad-guys"
WHITELIST=( "192.168.1.100" "192.168.1.1" "127.0.0.1" )
STATSFILE="/var/log/mikrotik-honeyport.log"


#############
# Functions #
#############

containsElement () {
	local e match="$1"
	shift
	for e; do [[ "$e" == "$match" ]] && return 0; done
	return 1
}

validIP () {
	ERROR=0
	oldIFS=$IFS
	IFS=.
	set -f
	set -- $1
	if [ $# -eq 4 ]; then
		for seg; do
			case $seg in
				""|*[!0-9]*) ERROR=1;break ;; ## Segment empty or non-numeric char
				*) [ $seg -gt 255 ] && ERROR=2 ;;
			esac
		done
	else
	  ERROR=3 ## Not 4 segments
	fi
	IFS=$oldIFS
	set +f
	return $ERROR
}

safeToBlacklist () {
	IP="$1"

	if [ $# != 1 ]; then
		echo "[-] Invalid number of arguments ($#) supplied. Must be just one."
		return 1
	fi

	if ! validIP "$IP"; then
	   echo "[-] Supplied argument ($IP) isn't a valid IPv4 address."
	   return 1
	fi

	if containsElement "$IP" "${WHITELIST[@]}"; then
		echo "[-] IP is whitelisted, not doing anything."
		return 1
	fi
	
	return 0
}

blacklist () {
	IP="$1"
	if safeToBlacklist "$IP"; then
		if [ -t 1 ]; then echo "[+] Blacklisting $IP"; fi
		echo "[+] Blacklisting: ${IP} with Mikrotik - $(date)" >> $STATSFILE
		ssh -i "$SSHKEY" $MTUSER@$MTIP ":do {/ip firewall address-list add list=\"$ADDLIST\" timeout=\"$TIMEOUT\" address=\"$IP\" comment=\"$COMMENT\"; /log info \"Honeypot just blacklisted $IP\"} on-error={}"
	fi
}


##################
# Pre-run checks #
##################

# Check for ncat
NCAT=$(which ncat)
if [ "${NCAT}" == "" ]; then
	echo "[-] Can't find ncat (required)."
	exit 1
fi

# Check PORT is not in use
RUNNING=$(/usr/sbin/lsof -i :${HONEYPORT})
if [ -n "$RUNNING" ]; then
	echo "[-] Port $HONEYPORT is already in use."
	exit 1
fi


#############
# Main loop #
#############

echo "[*] Starting Honeyport listener on port $HONEYPORT."
while [ 1 ]; do
	ncat -l -k -n -v -w 5 -c 'echo "HELLO"' 0.0.0.0 1337 3>&1 1>&2 2>&3 1>/dev/null |
	grep --line-buffered "from.*:" |
	grep --line-buffered -Po '[0-9.]{7,15}' |
	while IFS='' read attacker; do
		if [ -t 1 ]; then echo "[+] New connection from $attacker"; fi
		blacklist "$attacker"
	done
done
