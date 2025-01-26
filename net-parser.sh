#!/bin/bash

# Tool for parsing /proc/net/tcp, /proc/net/tcp6
# /proc/net/udp, and /proc/net/udp6

# CONSTANTS
declare -r NET_TCP_FILE='/proc/net/tcp'
declare -r NET_TCP6_FILE='/proc/net/tcp6'
declare -r NET_UDP_FILE='/proc/net/udp'
declare -r NET_UDP6_FILE='/proc/net/udp6'
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

# Reads a specific line from /proc/net tcp or udp files
readProcNetLine() {
	proc_net_file=$1
	line=$2
	local local_address=$(cat $proc_net_file | cut -d $'\n' -f$line | awk '{print $2}' | cut -d ':' -f 1)
	local local_port=$(cat $proc_net_file | cut -d $'\n' -f$line | awk '{print $2}' | cut -d ':' -f 2)
	local remote_address=$(cat $proc_net_file | cut -d $'\n' -f$line | awk '{print $3}' | cut -d ':' -f 1)
	local remote_port=$(cat $proc_net_file | cut -d $'\n' -f $line | awk '{print $3}' | cut -d ':' -f 2)
	local socket_status=$(cat $proc_net_file | cut -d $'\n' -f$line | awk '{print $4}')
	local uid=$(cat $proc_net_file | cut -d $'\n' -f$line | awk '{print $8}')
	echo -n "$local_address" "$local_port" "$remote_address" "$remote_port" "$socket_status" "$uid"
}

hexIPv4Parser() {
	local hex_address=$1
	local ip=''
	local indx
	for indx in $(seq $((${#hex_address}-2)) -2 0)
	do
			local byte=${hex_address:$indx:2}
			ip+="$(printf "%d" "0x$byte")."
	done
	ip=$(echo $ip | sed "s/\.$//")
	echo -n $ip
}

IPv6Parser() {
	local hex_address=$1
	local ip=''
	local indx
	local splitted_hex_address="$(echo $hex_address | grep -Eo '[0-9A-F]{8}' | tr $'\n' ' ')"
	for four_bytes in ${splitted_hex_address[@]}
	do
		local count=0
		for indx in $(seq $((${#four_bytes}-2)) -2 0)
		do
				local byte="${four_bytes:$indx:2}"
				ip+="$byte"
				((count++))
				if (( $count % 2 == 0 ))
				then
					ip+=":"
				fi

		done
	done
	echo -n "$ip" | tr -d ' ' | sed 's/:$//' | tr '[:upper:]' '[:lower:]'
}

wildcardPort() {
	local port=$1
	if [[ $port -eq 0 ]]
	then
		port='\*'
	fi
	echo -n $port
}

IPv6Shortening() {
	local ipv6=$1
	# all interfaces
	if [[ $ipv6 =~ ^(0{4}:){7}0{4}$ ]]
	then
		ipv6='::'
		echo -n $ipv6
		return 0
	fi
	# Single groups of zeros
	ipv6=$(echo $ipv6 | sed -E 's/(0{4})/0/g')

	# leading zeros
	ipv6=$(echo $ipv6 | sed -E 's/0+([1-9a-f]+)/\1/g')

	# Consecutive groups of zeros
	local max_group=7
	while [[ $max_group -gt 0 ]]
	do
		regex="(^(0:){$max_group}|(:0){$max_group})"
		if [[ $ipv6 =~ $regex ]]
		then
			ipv6=$(echo $ipv6 | sed -E "s/$regex/:/")
			break
		fi
		((max_group--))
	done
	echo -n $ipv6
}

getTCPSockets() {
	local n_lines=$(wc -l $NET_TCP_FILE | awk '{print $1}')
	local current_line=2 # We do not read the headers
	while [[ $current_line -le $n_lines ]]
	do
		read local_address local_port remote_address remote_port socket_status uid <<< $(readProcNetLine $NET_TCP_FILE $current_line)
		((current_line++))
		# PARSING
		socket_status=$(printf "%d" "0x$socket_status")
		((socket_status--)) # We start indexing at 0
		read local_address <<< $(hexIPv4Parser $local_address)
		read remote_address <<< $(hexIPv4Parser $remote_address)
		local_port=$(printf "%d" "0x$local_port")
		remote_port=$(printf "%d" "0x$remote_port")

		read local_port <<< $(wildcardPort $local_port)
		read remote_port <<< $(wildcardPort $remote_port)
		output "TCP" "${TCP_STATES[$socket_status]}" "$local_address:$local_port" "$remote_address:$remote_port" "$uid"
	done
}

getTCP6Sockets() {
	local n_lines=$(wc -l $NET_TCP6_FILE | awk '{print $1}')
	local current_line=2 # We do not read the headers
	while [[ $current_line -le $n_lines ]]
	do
		read local_address local_port remote_address remote_port socket_status uid <<< $(readProcNetLine $NET_TCP6_FILE $current_line)
		((current_line++))
		# PARSING
		socket_status=$(printf "%d" "0x$socket_status")
		((socket_status--)) # We start indexing at 0
		read local_address <<< $(IPv6Parser $local_address)
		read remote_address <<< $(IPv6Parser $remote_address)
		local_port=$(printf "%d" "0x$local_port")
		remote_port=$(printf "%d" "0x$remote_port")

		read local_port <<< $(wildcardPort $local_port)
		read remote_port <<< $(wildcardPort $remote_port)
		read local_address <<< $(IPv6Shortening $local_address)
		read remote_address <<< $(IPv6Shortening $remote_address)
		output "TCP" "${TCP_STATES[$socket_status]}" "[$local_address]:$local_port" "[$remote_address]:$remote_port" "$uid"
	done
}

getUDPSockets() {
	local n_lines=$(wc -l $NET_UDP_FILE | awk '{print $1}')
	local current_line=2 # We do not read the headers
	while [[ $current_line -le $n_lines ]]
	do

		read local_address local_port remote_address remote_port socket_status uid <<< $(readProcNetLine $NET_UDP_FILE $current_line)
		((current_line++))
		# PARSING
		socket_status=$(printf "%d" "0x$socket_status")
		if [[ $socket_status -gt 1 ]]
		then
			socket_status=1
		elif [[ $socket_status -eq 1 ]]
		then
			((socket_status--)) # We start indexing at 0
		fi

		read local_address <<< $(hexIPv4Parser $local_address)
		read remote_address <<< $(hexIPv4Parser $remote_address)
		local_port=$(printf "%d" "0x$local_port")
		remote_port=$(printf "%d" "0x$remote_port")

		read local_port <<< $(wildcardPort $local_port)
		read remote_port <<< $(wildcardPort $remote_port)
		output "UDP" "${UDP_STATES[$socket_status]}" "$local_address:$local_port" "$remote_address:$remote_port" "$uid"
	done
}

getUDP6Sockets() {
	local n_lines=$(wc -l $NET_UDP6_FILE | awk '{print $1}')
	local current_line=2 # We do not read the headers
	while [[ $current_line -le $n_lines ]]
	do

		read local_address local_port remote_address remote_port socket_status uid <<< $(readProcNetLine $NET_UDP6_FILE $current_line)
		((current_line++))
		# PARSING
		socket_status=$(printf "%d" "0x$socket_status")
		if [[ $socket_status -gt 1 ]]
		then
			socket_status=1
		elif [[ $socket_status -eq 1 ]]
		then
			((socket_status--)) # We start indexing at 0
		fi

		read local_address <<< $(IPv6Parser $local_address)
		read remote_address <<< $(IPv6Parser $remote_address)
		local_port=$(printf "%d" "0x$local_port")
		remote_port=$(printf "%d" "0x$remote_port")

		read local_port <<< $(wildcardPort $local_port)
		read remote_port <<< $(wildcardPort $remote_port)
		read local_address <<< $(IPv6Shortening $local_address)
		read remote_address <<< $(IPv6Shortening $remote_address)
		output "UDP" "${UDP_STATES[$socket_status]}" "$local_address:$local_port" "$remote_address:$remote_port" "$uid"
	done
}

output() {
	if [[ $header_displayed -eq 0 ]]
	then
		printf "%-17s %-17s %-45s %-45s %-20s\n" "Type" "State" "Local Address" "Remote Address" "uid"
		header_displayed=1
	fi
	printf "%-17s %-17s %-45s %-45s %-20s\n" "$1" "$2" "$3" "$4" "$5"
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

	# IPv4
	if [[ -n $ipv4 ]] 
	then
		if [[ -n $tcp ]] 
		then
			getTCPSockets		
		fi
		if [[ -n $udp ]] 
		then
			getUDPSockets
		fi

	fi
	
	# IPv6
	if [[ -n $ipv6 ]]
	then
		if [[ -n $tcp ]]
		then
			getTCP6Sockets
		fi

		if [[ -n $udp ]]
		then
			#TDB
			getUDP6Sockets
		fi
	fi

}

main "$@"
