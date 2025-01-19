#!/bin/bash

# Tool for parsing /proc/net/tcp, /proc/net/tcp6
# /proc/net/udp, and /proc/net/udp6

# CONSTANTS
declare -r NET_TCP_FILE='/proc/net/tcp'
declare -r NET_TCP6_FILE='/proc/net/tcp6'
declare -r NET_UDP_FILE='/proc/net/udp'
declare -r NET_UDP6_FILE='/proc/net/upd6'
declare -r TCP_STATES=(
    'ESTABLISHED'    # 01
    'SYN_SENT'       # 02
    'SYN_RECV'       # 03
    'FIN_WAIT1'      # 04
    'FIN_WAIT2'      # 05
    'TIME_WAIT'      # 06
    'CLOSE'          # 07
    'CLOSE_WAIT'     # 08
    'LAST_ACK'       # 09
    'LISTEN'         # 0A
    'CLOSING'        # 0B
    'WAIT'           # 0C
    'NEW_SYN_RECV'   # 0D
)
# UDP is a stateless protocol
declare -r UDP_STATES=(
	'ESTABLISHED' #01
	'UNNCONNECT'  #07
)
## Colors
declare -r RED="\033[1;31;40m"
declare -r RESET_COLOR="\033[0m"
# Variables
header_displayed=0 # To control whether the output function was called before \
	#so we do not displayed the column name (Type, State, Local Address, etc) more than once

Help() {
	echo -e "-h, --help\t\tGet help for commands."
	echo -e "-u, --udp\t\tGet udp sockets."
	echo -e "-t, --tcp\t\tGet tcp sockets."
	echo -e "-6, --ipv6\t\tDisplay IP version 6 sockets."
	echo -e "-4, --ipv4\t\tDisplay IP version 4 sockets."
	exit 0
}

HexIPv4Parser() {
	local hex_address=$1
	local ip=''
	local pair
	for pair in $(seq $((${#hex_address}-2)) -2 0)
	do
			local byte=${hex_address:$pair:2}
			ip+="$(printf "%d" "0x$byte")."
	done
	ip=$(echo $ip | sed "s/\.$//")
	echo -n $ip
}

wildcardPort() {
		local local_port=$1
		local remote_port=$2
		if [[ $local_port -eq 0 ]]
		then
			local_port='\*'
		fi

		if [[ $remote_port -eq 0 ]]
		then
			remote_port='\*'
		fi
		echo -n $local_port $remote_port
}

getTCP4Sockets() {
	while read line
	do
		local local_address=$(echo "$line" | awk '{print $2}' | cut -d ':' -f 1)
		local local_port=$(echo "$line" | awk '{print $2}' | cut -d ':' -f 2)
		local remote_address=$(echo "$line" | awk '{print $3}' | cut -d ':' -f 1)
		local remote_port=$(echo "$line" | awk '{print $3}' | cut -d ':' -f 2)
		local socket_status=$(echo "$line" | awk '{print $4}')
		local associated_user=$(echo "$line" | awk '{print $8}')

		# PARSING
		socket_status=$(printf "%d" "0x$socket_status")
		((socket_status--)) # We start indexing at 0
		read local_address <<< $(HexIPv4Parser $local_address)
		read remote_address <<< $(HexIPv4Parser $remote_address)
		local_port=$(printf "%d" "0x$local_port")
		remote_port=$(printf "%d" "0x$remote_port")

		read local_port remote_port <<< $(wildcardPort $local_port $remote_port)
		output "TCP" "${TCP_STATES[$socket_status]}" "$local_address:$local_port" "$remote_address:$remote_port" "$associated_user"
	done < <(tail -n +2 $NET_TCP_FILE)
}

getTCP6Sockets() {
	echo	
}

getUDPSockets() {
	while read line
	do
		local local_address=$(echo "$line" | awk '{print $2}' | cut -d ':' -f 1)
		local local_port=$(echo "$line" | awk '{print $2}' | cut -d ':' -f 2)
		local remote_address=$(echo "$line" | awk '{print $3}' | cut -d ':' -f 1)
		local remote_port=$(echo "$line" | awk '{print $3}' | cut -d ':' -f 2)
		local socket_status=$(echo "$line" | awk '{print $4}')
		local associated_user=$(echo "$line" | awk '{print $8}')

		# PARSING
		socket_status=$(printf "%d" "0x$socket_status")
		if [[ $socket_status -gt 1 ]]
		then
			socket_status=1
		elif [[ $socket_status -eq 1 ]]
		then
			((socket_status--)) # We start indexing at 0
		fi

		read local_address <<< $(HexIPv4Parser $local_address)
		read remote_address <<< $(HexIPv4Parser $remote_address)
		local_port=$(printf "%d" "0x$local_port")
		remote_port=$(printf "%d" "0x$remote_port")

		read local_port remote_port <<< $(wildcardPort $local_port $remote_port)
		output "UDP" "${UDP_STATES[$socket_status]}" "$local_address:$local_port" "$remote_address:$remote_port" "$associated_user"
	done < <(tail -n +2 $NET_UDP_FILE)
}

getUDP6Sockets() {
	echo
}

output() {
	if [[ $header_displayed -eq 0 ]]
	then
		printf "%-23s %-23s %-23s %-23s %-23s\n" "Type" "State" "Local Address" "Remote Address" "uid"
		header_displayed=1
	fi
	printf "%-23s %-23s %-23s %-23s %-23s\n" "$1" "$2" "$3" "$4" "$5"
}

main() {
	# Arguments parsing
	while [[ $# -gt 0 ]]
	do
		case $1 in
			-h| --help) Help;;
			-u| --udp)
				declare -r udp=1;shift;;
			-t| --tcp)
				declare -r tcp=1;shift;;
			-6| --ipv6)
				declare -r ipv6=1;shift;;
			-4| --ipv4)
				declare -r ipv4=1;shift;;
			*) echo -e "Unrecognized option: $1";Help;;
		esac
	done

	# No options supplied
	if [[ (-z $ipv4 && -z $ipv6) || (-z $tcp && -z $udp) ]]
	then
		echo '[+] You must specify both the IP version and the socket type (UDP or TCP)'
		Help
	fi

	# IPv6
	if [[ -n $ipv6 ]]
	then
		if [[ -n $tcp ]]
		then
			#TBD
			echo -e "$RED[+] TCP for IPv6 option is currently under development.$RESET_COLOR"
		fi

		if [[ -n $udp ]]
		then
			#TDB
			echo -e "$RED[+] UDP for IPv6 option is currently under development.$RESET_COLOR"
		fi
	fi

	# IPv4
	if [[ -n $ipv4 ]] 
	then
		if [[ -n $tcp ]] 
		then
			getTCP4Sockets		
		fi
		if [[ -n $udp ]] 
		then
			getUDPSockets
		fi

	fi
}

main "$@"
