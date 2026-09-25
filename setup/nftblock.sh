#!/bin/bash
# from me-asri/nft-block
# CURL arguments
readonly CURL_UA='Mozilla/5.0 nft-block/1.0'
CURL_OPTS=('--fail' '-s' '-L' '-A' "${CURL_UA}")

# Table name used by nft-block
readonly NFT_TABLE_NAME='nft-block'
# Priority used by filter chains
# - Use high enough priority to ensure nft-block takes effect before other other rules
readonly NFT_PRIORITY=-190

# Where nft-block installs itself
readonly INSTALL_DIR='/usr/local/bin'
# Systemd unit files directory
readonly SYSTEMD_UNIT_DIR='/etc/systemd/system/'
# Systemd timer calendar
readonly SYSTEMD_TIMER_CAL='*:0/5' # Every 5 minute

logi()
{
	echo "[*] $1" >&2
}

loge()
{
	echo "[!] $1" >&2
}

get_ip_ver()
{
	local ip="$1"

	if [[ "$ip" =~ ^([a-f0-9:]+)(\/[0-9]+)?$ ]]; then
		return 6
	elif [[ "$ip" =~ ^([0-9]+(\.|$|\/[0-9]+)){4} ]]; then
		return 4
	else
		return 1
	fi
}

load_ip_list()
{
	local url="$1"

	local -n _ipv4_list=$2

	local -n _ipv6_list=$3

	# Set IFS for seperating IP list entries
	local IFS=$'\r\n'

	# Download list
	local list
	if ! list=$(curl "${CURL_OPTS[@]}" "${url}"); then
		return 1
	fi

	# Add IPs to array
	local entry
	for entry in ${list}; do
		# Ignore lines starting with #
		if [[ "${entry:0:1}" == '#' ]]; then
			continue
		fi

		get_ip_ver "${entry}"
		local ip_ver=$?

		if [[ $ip_ver -eq 4 ]]; then
			_ipv4_list+=("${entry}")
		elif [[ $ip_ver -eq 6 ]]; then
			_ipv6_list+=("${entry}")
		else
			loge "Failed to detect IP version for ${entry}"
		fi
	done
}

nft_get_chain()
{
	local name="$1"

	nft list chain inet "${NFT_TABLE_NAME}" "${name}"
}

nft_prepare()
{
	# Create table
	if ! nft add table inet "${NFT_TABLE_NAME}"; then
		loge 'Failed to create table'
		return 1
	fi

	# Create input and output chains
	if ! nft add chain inet "${NFT_TABLE_NAME}" input "{ type filter hook input priority ${NFT_PRIORITY} ; }"; then
		loge 'Failed to create input chain'
		return 1
	fi
	if ! nft add chain inet "${NFT_TABLE_NAME}" output "{ type filter hook output priority ${NFT_PRIORITY} ; }"; then
		loge 'Failed to create input chain'
		return 1
	fi

	# Create IPv4/IPv6 address sets for storing blocked IPs
	if ! nft add set inet "${NFT_TABLE_NAME}" 'blacklist_v4' '{ type ipv4_addr ; flags interval ; }'; then
		loge 'Failed to create IPv4 blacklist set'
		return 1
	fi
	if ! nft add set inet "${NFT_TABLE_NAME}" 'blacklist_v6' '{ type ipv6_addr ; flags interval ; }'; then
		loge 'Failed to create IPv6 blacklist set'
		return 1
	fi

	# Read input and output chain rules
	local in_chain
	if ! in_chain=$(nft_get_chain 'input'); then
		loge 'Failed to read input chain'
		return 1
	fi
	local out_chain
	if ! out_chain=$(nft_get_chain 'output'); then
		loge 'Failed to read output chain'
		return 1
	fi

	# Add IPv4 and IPv6 rules for input chain
	if [[ ! "${in_chain}" =~ '@blacklist_v4'  ]]; then
		if ! nft add rule inet "${NFT_TABLE_NAME}" input ip saddr @blacklist_v4 drop; then
			loge 'Failed to add IPv4 input rule'
			return 1
		fi
	fi
	if [[ ! "${in_chain}" =~ '@blacklist_v6'  ]]; then
		if ! nft add rule inet "${NFT_TABLE_NAME}" input ip6 saddr @blacklist_v6 drop; then
			loge 'Failed to add IPv6 input rule'
			return 1
		fi	
	fi
	# Add IPv4 and IPv6 rules for output chain
	if [[ ! "${out_chain}" =~ '@blacklist_v4'  ]]; then
		if ! nft add rule inet "${NFT_TABLE_NAME}" output ip saddr @blacklist_v4 drop; then
			loge 'Failed to add IPv4 output rule'
			return 1
		fi
	fi
	if [[ ! "${out_chain}" =~ '@blacklist_v6'  ]]; then
		if ! nft add rule inet "${NFT_TABLE_NAME}" output ip6 saddr @blacklist_v6 drop; then
			loge 'Failed to add IPv6 output rule'
			return 1
		fi	
	fi
}

nft_clear_blacklist()
{
	local ip_ver=$1

	nft flush set inet "${NFT_TABLE_NAME}" "blacklist_v${ip_ver}"
}

nft_set_blacklist()
{
	local ip_ver="$1"
	local -n _list=$2

	logi "Adding ${#_list[@]} IPv${ip_ver} addresses to blacklist"

	# It's necessary to break up IP addresses to avoid `too many arguments` error
	local offset=0
	local max=1000
	local list_str
	printf -v list_str '%s,' "${_list[@]:0:${max}}"
	while [[ "${list_str}" != ',' ]]; do
		nft add element inet "${NFT_TABLE_NAME}" "blacklist_v${ip_ver}" "{{${list_str}}}"

		offset=$(( offset + max ))
		printf -v list_str '%s,' "${_list[@]:${offset}:${max}}"
	done
}

nft_delete_rules()
{
	if nft list table inet "${NFT_TABLE_NAME}" >/dev/null 2>&1; then
		nft delete table inet "${NFT_TABLE_NAME}"
	fi
}

nb_install_service()
{
	local nb_path="$1"
	shift
	local nb_args="$*"

	logi 'Creating nft-block service'
	local svc_path="${SYSTEMD_UNIT_DIR}/nft-block.service"
	if ! cat > "${svc_path}"; then
		loge 'Failed to create service file'
		return 1
	fi <<- EOF
		[Unit]
		Description=nft-block service

		[Service]
		Type=oneshot
		User=root
		ExecStart=${nb_path} ${nb_args}
	EOF

	logi 'Creating nft-block timer'
	local timer_path="${SYSTEMD_UNIT_DIR}/nft-block.timer"
	if ! cat > "${timer_path}"; then
		loge 'Failed to create timer file'

		# Clean up
		rm "${svc_path}"
		return 1
	fi <<- EOF
		[Unit]
		Description=nft-block timer

		[Timer]
		OnCalendar=${SYSTEMD_TIMER_CAL}
		Persistent=true

		[Install]
		WantedBy=timers.target
	EOF

	if ! systemctl start nft-block.timer; then
		loge 'Failed to start timer'

		rm "${svc_path}" "${timer_path}"
		return 1
	fi
	if ! systemctl enable nft-block.timer; then
		loge 'Failed to enable timer'

		rm "${svc_path}" "${timer_path}"
		return 1
	fi

	return 0
}

nb_uninstall_service()
{
	local svc_path="${SYSTEMD_UNIT_DIR}/nft-block.service"
	local timer_path="${SYSTEMD_UNIT_DIR}/nft-block.timer"

	if [ -f "${timer_path}" ]; then
		logi 'Removing nft-block timer'

		if ! systemctl stop nft-block.timer; then
			loge 'Failed to stop timer'
		fi
		if ! systemctl disable nft-block.timer; then
			loge 'Failed to disable timer'
		fi

		if ! rm "${timer_path}"; then
			loge 'Failed to remove timer'
		fi
	fi

	if [ -f "${svc_path}" ]; then
		logi 'Removing nft-block service'

		if ! rm "${svc_path}"; then
			loge 'Failed to remove service file'
		fi
	fi
}

nb_install()
{
	local args="$1"

	local bin_path="${INSTALL_DIR}/nft-block"

	if [[ "${bin_path}" == "$0" ]]; then
		loge 'nft-block already installed'
		return 1
	fi

	if ! install -m 0755 -o root -g root "$0" "${bin_path}"; then
		loge "Failed to install nft-block to ${bin_path}"
		return 1
	fi
	logi "Installed nft-block to ${bin_path}"

	if command -v systemctl >/dev/null; then
		logi 'Using systemd timer for persistence'

		if ! nb_install_service "${bin_path}" "${args}"; then
			return $?
		fi
	else
		loge "Persistence timer is supported only on systemd systems"
		logi 'For persistence you can manually add a cron job:'
		logi "Example: */5 * * * * ${bin_path} > /var/log/nft-block.log"
	fi
}

nb_uninstall()
{
	local bin_path="${INSTALL_DIR}/nft-block"

	nb_uninstall_service

	logi "Removing ${bin_path}"
	rm -f "${bin_path}"

	logi "Removing nft-block firewall rules"
	nft_delete_rules
}

apply_blacklists() {
	local -n _blacklists=$1

	logi 'Adding firewall rules'
	if ! nft_prepare; then
		loge 'Failed to add nftables rules'
		return 1
	fi

	local url
	local ipv4_list=()
	local ipv6_list=()
	for url in "${_blacklists[@]}"; do
		logi "Loading blacklist ${url}"
		if ! load_ip_list "${url}" ipv4_list ipv6_list; then
			loge "Failed to download ${url}"
			continue
		fi
	done

	if [[ ${#ipv4_list[@]} -gt 0 ]]; then
		if ! nft_clear_blacklist 4; then
			loge 'Failed to clear IPv4 blacklist'
		fi

		if ! nft_set_blacklist 4 ipv4_list; then
			loge 'Failed to update IPv4 blacklist'
		fi
	fi
	if [[ ${#ipv6_list[@]} -gt 0 ]]; then
		if ! nft_clear_blacklist 6; then
			loge 'Failed to clear IPv6 blacklist'
		fi

		if ! nft_set_blacklist 6 ipv6_list; then
			loge 'Failed to update IPv6 blacklist'
		fi
	fi
}

print_usage()
{
	echo -e "Usage: $0 <options>\n" \
		    "Example:\n" \
			" - Apply blacklist: $0 -l https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt\n" \
			" - Install:         $0 -i -l https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt\n" \
			" - Uninstall:       $0 -u\n" \
			"\n" \
			"Options:\n" \
			"  -l blacklist                : Apply blacklist\n" \
			"                                - Can be specified multiple times to apply as many blacklists as needed\n" \
			"  -x [protocol://]host[:port] : Use specified proxy\n" \
			"  -r                          : Clear nft-block firewall rules\n" \
			"  -i                          : Install to system\n" \
			"  -u                          : Uninstall from system\n"
}

main()
{
	local blacklists=()

	local proxy

	local inst_svc=0
	local uninst_svc=0

	while getopts "l:x:riuh" opt; do
		case "${opt}" in
			l)
				blacklists+=("${OPTARG}")
				;;
			x)
				proxy="${OPTARG}"
				CURL_OPTS+=('-x' "${proxy}")
				;;
			i)
				inst_svc=1
				;;
			r)
				logi "Clearing nft-block firewall rules"
				nft_delete_rules

				return 0;
				;;
			u)
				uninst_svc=1
				;;
			h)
				print_usage
				return 0
				;;
			*)
				print_usage
				return 1
				;;
		esac
	done

	if [[ ${inst_svc} -eq 1 && ${uninst_svc} -eq 1 ]]; then
		loge '-i and -u options are mutually exclusive'
		return 1
	elif [[ ${inst_svc} -eq 1 ]]; then
		logi 'Installing nft-block'

		if [[ ${#blacklists[@]} -eq 0 ]]; then
			loge 'No blacklists specified'
			print_usage
			return 1
		fi

		local args
		printf -v args -- ' -l %s' "${blacklists[@]}"
		if [ -n "${proxy}" ]; then
			args="${args} -x ${proxy}"
		fi

		if ! nb_install "${args}"; then
			loge 'Failed to install nft-block'
			return 1
		fi
	elif [[ ${uninst_svc} -eq 1 ]]; then
		logi 'Uninstalling nft-block'

		nb_uninstall
		return $?
	fi

	if [[ ${#blacklists[@]} -eq 0 ]]; then
		loge 'No blacklists specified'
		print_usage
		return 1
	fi

	apply_blacklists blacklists
	logi 'Done!'
}

if [[ "$USER" != 'root' ]]; then
	loge "Must be root to use this program"
	exit 1
fi

main "$@"
