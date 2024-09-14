#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" != "0" ]; then
	echo "脚本需要root运行." 1>&2
	exit 1
fi

## Text colors and styles
info() {
	echo -e "\e[92m$1\e[0m"
}
info_2() {
	echo -e "\e[94m$1\e[0m"
}
fail() {
	echo -e "\e[91m$1\e[0m" 1>&2
}
seperator() {
	echo -e "\n"
	echo $(printf '%*s' "$(tput cols)" | tr ' ' '=')
}

## Loading animation
BLA_classic=( 0.25 '-' "\\" '|' '/' )
declare -a BLA_active_loading_animation

BLA::play_loading_animation_loop() {
  while true ; do
    for frame in "${BLA_active_loading_animation[@]}" ; do
      printf "\r%s" "${frame}"
      sleep "${BLA_loading_animation_frame_interval}"
    done
  done
}

BLA::start_loading_animation() {
  BLA_active_loading_animation=( "${@}" )
  # Extract the delay between each frame from array BLA_active_loading_animation
  BLA_loading_animation_frame_interval="${BLA_active_loading_animation[0]}"
  unset "BLA_active_loading_animation[0]"
  tput civis # Hide the terminal cursor
  BLA::play_loading_animation_loop &
  BLA_loading_animation_pid="${!}"
}

BLA::stop_loading_animation() {
  kill "${BLA_loading_animation_pid}" &> /dev/null
  printf "\n"
  tput cnorm # Restore the terminal cursor
}
# Run BLA::stop_loading_animation if the script is interrupted
trap BLA::stop_loading_animation SIGINT

## System Info
sysinfo_(){
	#Linux Distro Version
	if [ -f /etc/os-release ]; then
		. /etc/os-release
		os=$NAME
		ver=$VERSION_ID
	elif type lsb_release >/dev/null 2>&1; then
		os=$(lsb_release -si)
		ver=$(lsb_release -sr)
	elif [ -f /etc/lsb-release ]; then
		. /etc/lsb-release
		os=$DISTRIB_ID
		ver=$DISTRIB_RELEASE
	elif [ -f /etc/debian_version ]; then
		os=Debian
		ver=$(cat /etc/debian_version)
	elif [ -f /etc/redhat-release ]; then
		os=Redhat
	else
		os=$(uname -s)
		ver=$(uname -r)
	fi

	#Virtualization Technology
	if [ $(systemd-detect-virt) != "none" ]; then
		virt_tech=$(systemd-detect-virt)
	fi

	#Memory Size
	mem_size=$(free -m | grep Mem | awk '{print $2}')

	#Network interface
	nic=$(ip addr | grep 'state UP' | awk '{print $2}' | sed 's/.$//' | cut -d'@' -f1 | head -1)

	return 0
}

## Update
update_() {
	if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
		apt-get update -y && apt-get upgrade -y
	elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
		yum update -y
	fi
	return 0
}

## Auto update
auto_update_() {
	if [ -z $(which unattended-upgrades) ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get -y install unattended-upgrades apt-listchanges
			if [ $? -ne 0 ]; then
				fail "Unattended-upgrades Installation Failed"
				return 1
			fi
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install unattended-upgrades -y
			if [ $? -ne 0 ]; then
				fail "Unattended-upgrades Installation Failed"
				return 1
			fi
		fi
	fi
	echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
	dpkg-reconfigure -f noninteractive unattended-upgrades
}

## Bandwidth Limit
bandwidth_limit_() {
	# Install vnstat if not already installed
	if ! [ -x "$(command -v vnstat)" ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get install vnstat -y
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install vnstat -y
		fi
	fi
	if ! [ -x "$(command -v vnstat)" ]; then
		fail "vnstat 安装失败"
		return 1
	fi
	# Install bc if	not already installed
	if ! [ -x "$(command -v bc)" ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get install bc -y
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install bc -y
		fi
	fi
	if ! [ -x "$(command -v bc)" ]; then
		fail "bc 安装失败"
		return 1
	fi
	sed -i "s/Interface \"\"/Interface \"$nic\"/" /etc/vnstat.conf
    cat << EOF > /root/.bandwidth_limit.sh
#!/bin/bash

# Set the monthly limit in GiB
monthly_upload_limit=$upload_threshold
monthly_download_limit=$download_threshold
reset_day=$reset_day

while true
do
	# Get the current date and time
	current_year=\$(date +%Y)
	current_month=\$(date +%m)
	current_day=\$(date +%d)

	# Calculate the begin and end dates for vnStat
	if [[ \$current_day -ge \$reset_day ]]; then
		begin_date="\$current_year-\$current_month-\$reset_day"
		next_month=\$(date -d "\$begin_date +1 month" +%m)
		next_year=\$(date -d "\$begin_date +1 month" +%Y)
		end_date="\$next_year-\$next_month-\$reset_day"
	else
		end_date="\$current_year-\$current_month-\$reset_day"
		prev_month=\$(date -d "\$end_date -1 month" +%m)
		prev_year=\$(date -d "\$end_date -1 month" +%Y)
		begin_date="\$prev_year-\$prev_month-\$reset_day"
	fi

	# Get the current usage
	current_upload_usage=\$(vnstat --begin \$begin_date --end \$end_date -i "$nic" --oneline | awk -F\; '{print \$10}')
	current_upload_usage_value=\$(echo \$current_upload_usage| awk '{print \$1}')
	current_upload_usage_unit=\$(echo \$current_upload_usage | awk '{print \$2}')

	current_download_usage=\$(vnstat --begin \$begin_date --end \$end_date -i "$nic" --oneline | awk -F\; '{print \$9}')
	current_download_usage_value=\$(echo \$current_download_usage| awk '{print \$1}')
	current_download_usage_unit=\$(echo \$current_download_usage | awk '{print \$2}')

	# Convert usage to GiB
	case \$current_upload_usage_unit in
		"KiB") current_upload_usage_in_gib=\$(echo "scale=2; \$current_upload_usage_value / 1048576" | bc) ;;
		"MiB") current_upload_usage_in_gib=\$(echo "scale=2; \$current_upload_usage_value / 1024" | bc) ;;
		"GiB") current_upload_usage_in_gib=\$current_upload_usage_value ;;
		"TiB") current_upload_usage_in_gib=\$(echo "scale=2; \$current_upload_usage_value * 1024" | bc) ;;
		*) echo "Unknown unit: \$unit" >&2; exit 1 ;;
	esac
	case \$current_download_usage_unit in
		"KiB") current_download_usage_in_gib=\$(echo "scale=2; \$current_download_usage_value / 1048576" | bc) ;;
		"MiB") current_download_usage_in_gib=\$(echo "scale=2; \$current_download_usage_value / 1024" | bc) ;;
		"GiB") current_download_usage_in_gib=\$current_download_usage_value ;;
		"TiB") current_download_usage_in_gib=\$(echo "scale=2; \$current_download_usage_value * 1024" | bc) ;;
		*) echo "Unknown unit: \$unit" >&2; exit 1 ;;
	esac

	# Check if the current usage exceeds the limit
	if (( \$(echo "\$current_upload_usage_in_gib >= \$monthly_upload_limit" | bc -l) )); then
		shutdown -h now
	fi
	if (( \$(echo "\$current_download_usage_in_gib >= \$monthly_download_limit" | bc -l) )); then
		shutdown -h now
	fi

	sleep 5
done
EOF
	chmod +x .bandwidth_limit.sh
	#Systemd Service
	cat << EOF > /etc/systemd/system/bandwidth_limit.service
[Unit]
Description=Bandwidth Limit
After=network.target

[Service]
Type=simple
ExecStart=/root/.bandwidth_limit.sh
Restart=always
RestartSec=3
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=bandwidth_limit
	
[Install]
WantedBy=multi-user.target
EOF
	systemctl enable bandwidth_limit
	systemctl start bandwidth_limit
	return 0
}

## CPU Abuse shutdown
cpu_abuse_shutdown_() {
	# Install bc if	not already installed
	if ! [ -x "$(command -v bc)" ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get install bc -y
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install bc -y
		fi
	fi
	if ! [ -x "$(command -v bc)" ]; then
		fail "bc 安装失败"
		return 1
	fi
	cat << EOF > /root/.cpu_abuse_shutdown.sh
#!/bin/bash
# Set the CPU usage limit
cpu_limit=$cpu_limit

while true
do
	# Get the current CPU usage
	cpu_usage=\$(top -bn2 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - \$1}' | tail -1)

	# Check if the usage exceeds the limit
	if (( \$(echo "\$cpu_usage >= \$cpu_limit" | bc -l) )); then
		((excess_usage_counter++))
	else
		((excess_usage_counter--))
	fi

	if [[ \$excess_usage_counter -ge 180 ]]; then
		shutdown -h now
	fi
	sleep 10
done
EOF
	chmod +x .cpu_abuse_shutdown.sh
	#Systemd Service
	cat << EOF > /etc/systemd/system/cpu_abuse_shutdown.service
[Unit]
Description=CPU Abuse Shutdown
After=network.target

[Service]
Type=simple
ExecStart=/root/.cpu_abuse_shutdown.sh
Restart=always
RestartSec=3
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=cpu_abuse_shutdown

[Install]
WantedBy=multi-user.target
EOF
	systemctl enable cpu_abuse_shutdown
	systemctl start cpu_abuse_shutdown
	return 0
}

## DDoS Auto Shutdown
ddos_shutdown_() {
	# Install vnstat if not already installed
	if ! [ -x "$(command -v vnstat)" ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get install vnstat -y
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install vnstat -y
		fi
	fi
	if ! [ -x "$(command -v vnstat)" ]; then
		fail "vnstat 安装失败"
		return 1
	fi
	# Install jq if not already installed
	if ! [ -x "$(command -v jq)" ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get install jq -y
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install jq -y
		fi
	fi
	if ! [ -x "$(command -v jq)" ]; then
		fail "jq 安装失败"
		return 1
	fi
	cat << EOF > /root/.ddos_shutdown.sh
#!/bin/bash
byte_limit=\$(($speed_limit * 1000 * 1000 / 8)) 
packet_limit=\$(($packet_limit))

while true
do
	# Get current bandwidth usage
	byte_rate=\$(vnstat -tr 30 --json | jq '.rx.bytespersecond + .tx.bytespersecond')
	# Get current packet rate
	packet_rate=\$(vnstat -tr 30 --json | jq '.rx.packetspersecond + .tx.packetspersecond')

	# Check if the usage exceeds the limit
	if [[ \$byte_rate -gt \$byte_limit ]] || [[ \$packet_rate -gt \$packet_limit ]] ; then
		((excess_usage_counter++))
	else
		excess_usage_counter=0
	fi

	# If the usage exceeds the limit for 10 minutes, shut down the server
	if [[ \$excess_usage_counter -ge 10 ]]; then
		shutdown -h now
	fi
done
EOF
	chmod +x .ddos_shutdown.sh
	#Systemd Service
cat << EOF > /etc/systemd/system/ddos_shutdown.service
[Unit]
Description=DDoS Shutdown
After=network.target

[Service]
Type=simple
ExecStart=/root/.ddos_shutdown.sh
Restart=always
RestartSec=3
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=ddos_shutdown

[Install]
WantedBy=multi-user.target
EOF
	systemctl enable ddos_shutdown
	systemctl start ddos_shutdown

	return 0
}


## SSH Security Settings
ssh_secure_() {
	# Ask for the new SSH port
	read -p "新SSH端口: " new_ssh_port

	# Check if the input is a valid number
	while ! [[ $new_ssh_port =~ ^[0-9]+$ ]]; do
		echo "请输入一个有效的端口号"
		read -p "新SSH端口: " new_ssh_port
	done

	# Add the new SSH port without removing the existing one
	echo "Port $new_ssh_port" >> /etc/ssh/sshd_config

	# Restart SSH service to apply changes
	systemctl restart sshd

	# Make sure the new SSH port is open
	read -p "你能使用新SSH端口登录吗? (y/n): " can_login
	while ! [[ $can_login =~ ^[YyNn]$ ]]; do
		echo "请输入y或n"
		read -p "你能使用新SSH端口登录吗? (y/n): " can_login
	done
	if [[ $can_login =~ ^[Yy]$ ]]; then
		# Removing the original SSH port
		sed -i "0,/Port /s//Old&/" /etc/ssh/sshd_config
		sed -i '/OldPort/d' /etc/ssh/sshd_config

		# Restart SSH service to apply final changes
		systemctl restart sshd
		info_2 "旧SSH端口已关闭"
	else
		# Revert the changes
		sed -i ':a;N;$!ba;s/\(.*\)Port /\1OldPort /' /etc/ssh/sshd_config
		sed -i '/OldPort/d' /etc/ssh/sshd_config
		systemctl restart sshd
		fail "新SSH端口 $new_ssh_port 未打开"
		fail "旧SSH端口未关闭"
		return 1
	fi

	#Disble Root Password Login
	keys="/root/.ssh/authorized_keys"

	if ! [ -s "$keys" ]; then
		fail "SSH 钥匙不存在"
		return 1
	else
		sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
		sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
		unset can_login
		read -p "你能使用SSH密钥登录吗? (y/n): " can_login
		while ! [[ $can_login =~ ^[YyNn]$ ]]; do
			echo "请输入y或n"
			read -p "你能使用SSH密钥登录吗? (y/n): " can_login
		done
		if [[ $can_login =~ ^[Yy]$ ]]; then
			# Disable password login
			sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
			sed -i 's/^PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
			sed -i 's/^PermitRootLogin without-password/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
			systemctl restart sshd
			info_2 "Root密码登录已禁用"
		else
			fail "SSH密钥登录未启用"
			return 1
		fi
	fi
	return 0
}

## Fail2ban
fail2ban_() {
	if [ -z $(which fail2ban-client) ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get install fail2ban -y
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install fail2ban -y
		fi
	fi
	if [ -z $(which fail2ban-client) ]; then
		fail "Fail2ban installation failed"
		return 1
	fi
	if [ -z $(which iptables) ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get install iptables -y
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install iptables -y
		fi
	fi
	if [ -z $(which iptables) ]; then
		fail "iptables installation failed"
		return 1
	fi
	# Check current ssh port
	ssh_port=$(ss -tlnp | grep sshd | awk '{print $4}' | cut -d':' -f2 | head -1)
	touch /etc/fail2ban/jail.local
	cat << EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
filter = sshd
mode   = aggressive
port    = $ssh_port
logpath = %(sshd_log)s
backend=systemd
banaction = iptables-multiport
bantime = -1
maxretry = 3
findtime = 24h
EOF
	systemctl restart fail2ban
	# Check if fail2ban is running
	if [ -z $(ps -ef | grep fail2ban | grep -v grep) ]; then
		fail "Fail2ban failed to start"
		return 1
	fi
	return 0
}

## System tuning
#Install Tuned
tuned_() {
    if [ -z $(which tuned) ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get install tuned -y
			if [ $? -ne 0 ]; then
				fail "Tuned Installation Failed"
				return 1
			fi
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install tuned -y
			if [ $? -ne 0 ]; then
				fail "Tuned Installation Failed"
				return 1
			fi
		fi
	fi
	return 0
}
#File Open Limit
set_file_open_limit_() {

    cat << EOF >> /etc/security/limits.conf
## Hard limit for max opened files
* soft nofile 655360
## Soft limit for max opened files
* hard nofile 655360
EOF
	return 0
}
#Ring Buffer
set_ring_buffer_() {
	if [ -z $(which ethtool) ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get -y install ethtool
			if [ $? -ne 0 ]; then
				fail "Ethtool Installation Failed"
				return 1
			fi
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install ethtool -y
			if [ $? -ne 0 ]; then
				fail "Ethtool Installation Failed"
				return 1
			fi
		fi
	fi
    ethtool -G $nic rx 1024
	if [ $? -ne 0 ]; then
		fail "Ring Buffer Setting Failed"
		return 1
	fi
    sleep 1
    ethtool -G $nic tx 2048
	if [ $? -ne 0 ]; then
		fail "Ring Buffer Setting Failed"
		return 1
	fi
    sleep 1
	return 0
}
#Disable TSO
disable_tso_() {
	if [ -z $(which ethtool) ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get -y install ethtool
			if [ $? -ne 0 ]; then
				fail "Ethtool Installation Failed"
				return 1
			fi
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install ethtool -y
			if [ $? -ne 0 ]; then
				fail "Ethtool Installation Failed"
				return 1
			fi
		fi
	fi
	ethtool -K $nic tso off gso off gro off
	sleep 1
	return 0
}
#TCP Queue Length
set_txqueuelen_() {
	if [ -z $(which net-tools) ]; then
		if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
			apt-get install net-tools -y
			if [ $? -ne 0 ]; then
				fail "Net-tools Installation Failed"
				return 1
			fi
		elif [[ $os =~ "CentOS" ]] || [[ $os =~ "Redhat" ]]; then
			yum install net-tools -y
			if [ $? -ne 0 ]; then
				fail "Net-tools Installation Failed"
				return 1
			fi
		fi
	fi
    ifconfig $nic txqueuelen 10000
    sleep 1
	return 0
}
#Initial Congestion Window
set_initial_congestion_window_() {
    iproute=$(ip -o -4 route show to default)
    ip route change $iproute initcwnd 100 initrwnd 100
	return 0
}
#Kernel Settings
kernel_settings_() {
	# Set variables based on memory size
	if [ $mem_size -le 128 ]; then	# 128MB or less
		adv_win_scale=3
		rmem_default=262144
		rmem_max=16777216
		tcp_rmem="8192 $rmem_default $rmem_max"
		wmem_default=262144
		wmem_max=16777216
		tcp_wmem="8192 $wmem_default $wmem_max"
		background_ratio=5
		dirty_ratio=20
		writeback_centisecs=100
		expire_centisecs=100
		swappiness=80
	elif [ $mem_size -le 512 ]; then	# 512MB or less
		adv_win_scale=2
		rmem_default=262144
		rmem_max=16777216
		tcp_rmem="8192 $rmem_default $rmem_max"
		wmem_default=262144
		wmem_max=16777216
		tcp_wmem="8192 $wmem_default $wmem_max"
		background_ratio=5
		dirty_ratio=20
		writeback_centisecs=100
		expire_centisecs=500
		swappiness=60
	elif [ $mem_size -le 1024 ]; then	# 1GB or less
		adv_win_scale=1
		rmem_default=262144
		rmem_max=33554432
		tcp_rmem="8192 $rmem_default $rmem_max"
		wmem_default=262144
		wmem_max=33554432
		tcp_wmem="8192 $wmem_default $wmem_max"
		background_ratio=5
		dirty_ratio=30
		writeback_centisecs=100
		expire_centisecs=1000
		swappiness=20
	else	# 1GB or more
		adv_win_scale=1
		rmem_default=262144
		rmem_max=33554432
		tcp_rmem="8192 $rmem_default $rmem_max"
		wmem_default=262144
		wmem_max=33554432
		tcp_wmem="8192 $wmem_default $wmem_max"
		background_ratio=5
		dirty_ratio=30
		writeback_centisecs=100
		expire_centisecs=1000
		swappiness=10
	fi
	
	cat << EOF > /etc/sysctl.conf
#### Network Security Settings
# Turn on Source Address Verification in all interfaces to prevent some spoofing attacks
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.rp_filter=1

# Protect a server against SYN flood attacks
#Enable TCP/IP SYN cookies to 
net.ipv4.tcp_syncookies=1
#Increase the maximum queue length of completely established sockets waiting to be accepted
# The net.core.somaxconn parameter is the maximum queue length of completely established sockets waiting to be accepted.
net.core.somaxconn=10000
#Increase the maximum queue length of incomplete sockets i.e. half-open connection
# The net.ipv4.tcp_max_syn_backlog parameter is the maximum queue length of incomplete sockets.
# NOTE: THis value should not be above "net.core.somaxconn", since that is also a hard open limit of maximum queue length of incomplete sockets/
# Kernel will take the lower one out of two as the maximum queue length of incomplete sockets
net.ipv4.tcp_max_syn_backlog=10000
#Increase the maximal number of TCP sockets not attached to any user file handle (i.e. orphaned connections), held by system.
# NOTE: each orphan eats up to ~64K of unswappable memory
# The net.ipv4.tcp_max_orphans parameter is the maximum number of TCP sockets not attached to any user file handle.
net.ipv4.tcp_max_orphans=10000
#Quickly Discard locally closed TCP connection
net.ipv4.tcp_orphan_retries = 2

# Protect a server against ack loop" DoS attacks
net.ipv4.tcp_invalid_ratelimit=500

# Disable packet forwarding
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0

# Do not accept ICMP redirects (prevent MITM attacks)
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Do not send ICMP redirects (we are not a router)
net.ipv4.conf.all.send_redirects = 0

# Do not accept IP source route packets (we are not a router)
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martian Packets
net.ipv4.conf.all.log_martians = 1

# Protect Against TCP TIME-WAIT Assassination
net.ipv4.tcp_rfc1337 = 0


### SoftIRQ Misses
# SoftIRQs are used for tasks that are not time-critical, such as network packet processing.
# Check the number of softIRQ misses
# cat /proc/net/softnet_stat
# Pay close attention to the following columns:
# Column-01: packet_process: Packet processed by each CPU.
# Column-02: packet_drop: Packets dropped.
# Column-03: time_squeeze: net_rx_action.

# Column-02: packet_drop: Packets dropped.
# Packet_drop indicates that the NIC is dropping packets due to a lack of backlog space.
# Solution 1. : Increase the size of the NIC’s backlog
# The backlog is the number of packets that the NIC can store in its backlog queue.
# Increase the backlog size to 10000
net.core.netdev_max_backlog=10000

# Column-03: time_squeeze: net_rx_action
# Time_squeeze: net_rx_action counter indicates the number of times the CPU has to return prematurely without draining the queue.
# This is most likely weak causing by weak CPU in a high-traffic environment.
# Solution 2. : Increasing net.core.netdev_budget and net.core.netdev_budget_usecs
# The netdev_budget parameter is the maximum number of packets that the kernel will process in a single softIRQ.
# The netdev_budget_usecs parameter is the maximum amount of time that the kernel will spend processing packets in a single softIRQ.
# To increase the netdev_budget and netdev_budget_usecs values, you can use the sysctl command.
net.core.netdev_budget=50000
net.core.netdev_budget_usecs=8000
# NOTE: Setting a high number might cause CPU to stall and end in poor overall performance
# NOTE: Increasing the number of Query Channels (RSS) can also help with the issue.

# Low latency busy poll timeout for socket reads
# NOTE: Not supported by most NIC
#net.core.busy_read=50
# Low latency busy poll timeout for poll and select
# NOTE: Not supported by most NIC
#net.core.busy_poll=50


### Socket buffer size
#Congestion window
# The congestion window is the amount of data that the sender can send before it must wait for an acknowledgment from the receiver.
# The congestion window is limited by 2 things. 
#   The receiver’s advertised window size, which is the amount of data that the receiver is willing to accept
#   And also the size of the sending socket buffer on the sender’s end.

#How to determine the optimal congestion window
# The optimal congestion window size is determined by the bandwidth-delay product (BDP) of the network.
# The BDP is the amount of data that can be in transit in the network at any given time.
# It is calculated by multiplying the bandwidth of the network by the round-trip time (RTT) of the network.
# The optimal congestion window size is the BDP of the network.
# You can use this site to calculate the BDP of your network: https://www.speedguide.net/bdp.php

#How to determine the Optimal Receive socket Buffer Size
# The optimal socket buffer size is determined by optimal congestion window and, in turn, also determined by the bandwidth-delay product (BDP) of the network.
# We have to make sure the advertised window size is not smaller than BDP to prevent underutilization of the network.
# The receive socket buffer space is shared between the application and kernel. /
#   TCP maintains part of the buffer as the TCP window, this is the size of the receive window advertised to the other end.  /
#   The rest of the space is used as the "application" buffer, used to isolate the network from scheduling and application latencies.
# The total receive socket buffer space is determined by net.ipv4.tcp_rmem and the portion of which is allocated as "application" buffer is determined by net.ipv4.tcp_adv_win_scale.
net.ipv4.tcp_adv_win_scale=$adv_win_scale
net.core.rmem_default=$rmem_default
net.core.rmem_max=$rmem_max
net.ipv4.tcp_rmem=$tcp_rmem

#How to determine the Optimal Send socket Buffer Size
# Send socket buffer size determine the maximum amount of data that the application can send before needing to wait for an acknowledgment (ACK) from the receiver
# As you may have recalled, it is bascially the definition of congestion window
# Therefore it is important to make sure the send buffer space is not smaller than BDP to prevent underutilization of the network.

# You can set send socket buffer size using the sysctl command.
net.core.wmem_default=$wmem_default
net.core.wmem_max=$wmem_max
net.ipv4.tcp_wmem=$tcp_wmem

#Relationship between net.core.r/wmem and net.ipv4.tcp_r/wmem
# net.core.r/wmem is the default buffer size for all protocols, including TCP
# And net.ipv4.tcp_r/wmem is the buffer size for TCP only

#net.ipv4.tcp_rmem = tcp_rmem_min tcp_rmem_default tcp_rmem_max
# Vector of 3 INTEGERs: min, default, max
#	min: Minimal size of receive buffer used by TCP sockets.
#	It is guaranteed to each TCP socket, even under moderate memory
#	pressure.
#
#	default: initial size of receive buffer used by TCP sockets.
#	This value overrides net.core.rmem_default used by other protocols.
#
#	max: maximal size of receive buffer allowed for automatically
#	selected receiver buffers for TCP socket. This value does not override
#	net.core.rmem_max.  Calling setsockopt() with SO_RCVBUF disables
#	automatic tuning of that socket's receive buffer size, in which
#	case this value is ignored.

#net.ipv4.tcp_wmem = tcp_wmem_min tcp_wmem_default tcp_wmem_max
# Vector of 3 INTEGERs: min, default, max
#	min: Amount of memory reserved for send buffers for TCP sockets.
#	Each TCP socket has rights to use it due to fact of its birth.
#
#	default: initial size of send buffer used by TCP sockets.  This
#	value overrides net.core.wmem_default used by other protocols.
#	It is usually lower than net.core.wmem_default.
#
#	max: Maximal amount of memory allowed for automatically tuned
#	send buffers for TCP sockets. This value does not override
#	net.core.wmem_max.  Calling setsockopt() with SO_SNDBUF disables
#	automatic tuning of that socket's send buffer size, in which case
#	this value is ignored.

# Because of the varying internet condition, not every connection is going to reach the optimal congestion window size, and that’s okay.
# To prevent slow link from using more than necessary amount of memory, we can use the following sysctl settings to enable receive buffer auto-tuning
net.ipv4.tcp_moderate_rcvbuf = 1


# Allows the use of a large window (> 64 kB) on a TCP connection, this is the default settings for most modern kernel
net.ipv4.tcp_window_scaling = 1

# Set maximum window size to MAX_TCP_WINDOW i.e. 32767 in times there is no received window scaling option
net.ipv4.tcp_workaround_signed_windows = 1


### MTU Discovery
# Allow Path MTU Discovery
net.ipv4.ip_no_pmtu_disc = 0

# Enable TCP Packetization-Layer Path, and use initial MSS of tcp_base_mss
net.ipv4.tcp_mtu_probing = 2

# Starting MSS used in Path MTU discovery
net.ipv4.tcp_base_mss = 1460

#  Minimum MSS used in connection, cap it to this value even if advertised ADVMSS option is even lower
net.ipv4.tcp_min_snd_mss = 536

# Maximum memory used to reassemble IP fragments
net.ipv4.ipfrag_high_thresh = 8388608


### Account for a high RTT lossy network
# Enable selective acknowledgments 
net.ipv4.tcp_sack = 1

# Allows TCP to send "duplicate" SACKs
net.ipv4.tcp_dsack = 1

# Enable Early Retransmit. ER lowers the threshold for triggering fast retransmit when the amount of outstanding data is small and when no previously unsent data can be transmitted
net.ipv4.tcp_early_retrans = 3

# Disable ECN to survive in a congested network
net.ipv4.tcp_ecn = 0

# Reordering level of packets in a TCP stream
# Initial reordering level of packets in a TCP stream. TCP stack can then dynamically adjust flow reordering level between this initial value and tcp_max_reordering
net.ipv4.tcp_reordering = 10
# Maximal reordering level of packets in a TCP stream
net.ipv4.tcp_max_reordering = 1000
# NOTE: An attempt to reduce the number of retransmissions due to packet reordering in a network. Which is common in a lossy network

# Enable F-RTO (Forward RTO-Recovery). Beneficial in networks where the RTT fluctuates 
net.ipv4.tcp_frto = 2

# Enable TCP Auto Corking
# When enabled, the TCP stack will automatically cork the socket when the application is not sending data fast enough
net.ipv4.tcp_autocorking = 1

# TCP Retry
# The number of times to retry before killing an alive TCP connection
net.ipv4.tcp_retries1 = 5
net.ipv4.tcp_retries2 = 20

# TCP Keepalive
# After $tcp_keepalive_time seconds of inactivity, TCP will send a keepalive probe every $tcp_keepalive_intvl to the other end. /
# After $tcp_keepalive_probes failed attempts, the connection will be closed
# In seconds, time default value for connections to keep alive
net.ipv4.tcp_keepalive_time = 7200
# In seconds, how frequently the probes are send out
net.ipv4.tcp_keepalive_intvl = 120
# How many keepalive probes TCP sends out, until it decides that the connection is broken
net.ipv4.tcp_keepalive_probes = 15

# SYN 
# Number of times SYNACKs for a passive TCP connection attempt will be retransmitted
net.ipv4.tcp_synack_retries = 10
# Number of times initial SYNs for an active TCP connection attempt	will be retransmitted
net.ipv4.tcp_syn_retries = 7


### To support more connections
#Solution 1. : Increase the maximum number of file descriptors
# The maximum number of connections that a server can handle is determined by the maximum number of file descriptors that the server can open.
#fs.file-max=655360
#fs.nr_open=655360

#Solution 2. : Increase the number of port that the kernel can allocate for outgoing connections
# The net.ipv4.ip_local_port_range parameter is the range of port numbers that the kernel can allocate for outgoing connections.
net.ipv4.ip_local_port_range=1024 65535

#Solution 3. : Increase the maximum number of sockets in TIME_WAIT state
# The net.ipv4.tcp_max_tw_buckets parameter is the maximum number of sockets in TIME_WAIT state.
net.ipv4.tcp_max_tw_buckets=10000

#Solution 4. : Quickly discard sockets in the state FIN-WAIT-2
# The net.ipv4.tcp_fin_timeout parameter is the maximum time that a connection in the FIN-WAIT-2 state will stay open.
net.ipv4.tcp_fin_timeout=10


### Miscellaneous
# Enable TCP Fast Open
# TCP Fast Open (TFO) is an extension to speed up the opening of successive TCP connections between two endpoints
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fastopen_blackhole_timeout_sec = 0

# The maximum amount of unsent bytes in TCP socket write queue, this is on top of the congestion window
net.ipv4.tcp_notsent_lowat = 131072

# Avoid falling back to slow start after a connection goes idle
net.ipv4.tcp_slow_start_after_idle = 0

# Disable timestamps
net.ipv4.tcp_timestamps = 0

# Save cache metrics on closing connections
net.ipv4.tcp_no_metrics_save = 0

## ARP table settings
# The maximum number of bytes which may be used by packets queued for each unresolved address by other network layers
net.ipv4.neigh.default.unres_qlen_bytes = 16777216

# Controls a per TCP socket cache of one socket buffer
# net.ipv4.tcp_rx_skb_cache=1


### Buffer and cache management
# Percentage of total system memory that can be filled with dirty pages /
# before the system starts writing them to disk in the background
vm.dirty_background_ratio = $background_ratio
# Percentage of total system memory that can be filled with dirty pages 
# before the system blocks any further writes /
# and forces the process that is generating dirty pages to write them to disk.
vm.dirty_ratio = $dirty_ratio

# The interval of when writes of dirty in-memory data are written out to disk. 
# It is expressed in centiseconds
vm.dirty_writeback_centisecs = $writeback_centisecs
# when dirty in-memory data is old enough to be eligible for writeout by the kernel flusher threads. 
# It is also expressed in centiseconds. 
vm.dirty_expire_centisecs = $expire_centisecs

# Avoid using swap as much as possible
vm.swappiness = $swappiness


### Congestion Control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
	sysctl -p
	return 0
}
tune_() {
	tuned_
	# set_file_open_limit_
	kernel_settings_

	if [ -z "$virt_tech" ]; then		#If not a virtual machine
		set_ring_buffer_
	else
		disable_tso_
	fi

	if [ -z "$virt_tech" ] || [ "$virt_tech" != "lxc" ]; then		#If not a LXC container
		set_txqueuelen_
		set_initial_congestion_window_
	fi

	boot_script_
	return 0
}

## Configue Boot Script
boot_script_() {
	touch /root/.boot-script.sh && chmod +x /root/.boot-script.sh
	cat << EOF > /root/.boot-script.sh
#!/bin/bash
sleep 120s
source <(wget -qO- https://raw.githubusercontent.com/yuju520/YujuToolBox/main/tune.sh)
# Check if Seedbox Components is successfully loaded
if [ \$? -ne 0 ]; then
	exit 1
fi

sysinfo_
if [ -z "\$virt_tech" ]; then		#If not a virtual machine
	set_ring_buffer_
else
	disable_tso_
fi

if [ "\$virt_tech" != "lxc" ]; then		#If not a LXC container
	set_txqueuelen_
	set_initial_congestion_window_
fi
EOF
# Configure the script to run during system startup
cat << EOF > /etc/systemd/system/boot-script.service
[Unit]
Description=boot-script
After=network.target

[Service]
Type=simple
ExecStart=/root/.boot-script.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF
	systemctl enable boot-script.service
	return 0
}


## BBR
install_bbrx_() {
	if [[ "$os" =~ "Debian" ]]; then
		if [ $(uname -m) == "x86_64" ]; then
			apt-get -y install linux-image-amd64 linux-headers-amd64
			if [ $? -ne 0 ]; then
				fail "BBR installation failed"
				return 1
			fi
		elif [ $(uname -m) == "aarch64" ]; then
			apt-get -y install linux-image-arm64 linux-headers-arm64
			if [ $? -ne 0 ]; then
				fail "BBR installation failed"
				return 1
			fi
		fi
	elif [[ "$os" =~ "Ubuntu" ]]; then
		apt-get -y install linux-image-generic linux-headers-generic
		if [ $? -ne 0 ]; then
			fail "BBR installation failed"
			return 1
		fi
	else
		fail "Unsupported OS"
		return 1
	fi
	wget https://raw.githubusercontent.com/yuju520/YujuToolBox/main/BBRx.sh -O /root/BBRx.sh && chmod +x /root/BBRx.sh
	# Check if download fail
	if [ ! -f BBRx.sh ]; then
		fail "BBR download failed"
		return 1
	fi
    ## Install tweaked BBR automatically on reboot
    cat << EOF > /etc/systemd/system/bbrinstall.service
[Unit]
Description=BBRinstall
After=network.target

[Service]
Type=oneshot
ExecStart=/root/BBRx.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable bbrinstall.service
	return 0
}

install_bbrv3_() {
	if [ $(uname -m) == "x86_64" ]; then
		wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRv3/x86_64/linux-headers-6.4.0+-amd64.deb -O /root/linux-headers-6.4.0+-amd64.deb
		if [ ! -f /root/linux-headers-6.4.0+-amd64.deb ]; then
			fail "BBRv3 download failed"
			return 1
		fi
		wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRv3/x86_64/linux-image-6.4.0+-amd64.deb -O /root/linux-image-6.4.0+-amd64.deb
		if [ ! -f /root/linux-image-6.4.0+-amd64.deb ]; then
			fail "BBRv3 download failed"
			rm /root/linux-headers-6.4.0+-amd64.deb
			return 1
		fi
		wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRv3/x86_64/linux-libc-dev_-6.4.0-amd64.deb -O /root/linux-libc-dev_-6.4.0-amd64.deb
		if [ ! -f /root/linux-libc-dev_-6.4.0-amd64.deb ]; then
			fail "BBRv3 download failed"
			rm /root/linux-headers-6.4.0+-amd64.deb /root/linux-image-6.4.0+-amd64.deb
			return 1
		fi
		apt install /root/linux-headers-6.4.0+-amd64.deb /root/linux-image-6.4.0+-amd64.deb /root/linux-libc-dev_-6.4.0-amd64.deb
		# Clean up
		rm /root/linux-headers-6.4.0+-amd64.deb /root/linux-image-6.4.0+-amd64.deb /root/linux-libc-dev_-6.4.0-amd64.deb
	elif [ $(uname -m) == "aarch64" ]; then
		wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRv3/ARM64/linux-headers-6.4.0+-arm64.deb -O /root/linux-headers-6.4.0+-arm64.deb
		if [ ! -f /root/linux-headers-6.4.0+-arm64.deb ]; then
			fail "BBRv3 download failed"
			return 1
		fi
		wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRv3/ARM64/linux-image-6.4.0+-arm64.deb -O /root/linux-image-6.4.0+-arm64.deb
		if [ ! -f /root/linux-image-6.4.0+-arm64.deb ]; then
			fail "BBRv3 download failed"
			rm /root/linux-headers-6.4.0+-arm64.deb
			return 1
		fi
		wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRv3/ARM64/linux-libc-dev_-6.4.0-arm64.deb -O /root/linux-libc-dev_-6.4.0-arm64.deb
		if [ ! -f /root/linux-libc-dev_-6.4.0-arm64.deb ]; then
			fail "BBRv3 download failed"
			rm /root/linux-headers-6.4.0+-arm64.deb linux-image-6.4.0+-arm64.deb
			return 1
		fi
		apt install /root/linux-headers-6.4.0+-arm64.deb /root/linux-image-6.4.0+-arm64.deb /root/linux-libc-dev_-6.4.0-arm64.deb
		# Clean up
		rm /root/linux-headers-6.4.0+-arm64.deb /root/linux-image-6.4.0+-arm64.deb /root/linux-libc-dev_-6.4.0-arm64.deb
	else
		fail "$(uname -m) is not supported"
	fi
	return 0
}


## Main
sysinfo_
update_
clear
while getopts "abcdstx3h" opt; do
	case ${opt} in
		a )
		seperator
			info "自动更新"
			BLA::start_loading_animation "${BLA_classic[@]}"
			auto_update_ &> /dev/null
			if [ $? -eq 0 ]; then
				auto_update_success=1
			else
				auto_update_success=0
			fi
			BLA::stop_loading_animation
			if [ $auto_update_success -eq 1 ]; then
				info "自动更新设置成功"
			else
				fail "自动更新设置失败"
			fi
			;;
		b )
			seperator
			# Set the bandwidth threshold in GB
			info "设置每月带宽上限"
			info_2 "输入每月带宽上传上限 （以GB为单位）："
			read upload_threshold
			while true
			do
				if ! [[ "$upload_threshold" =~ ^[0-9]+$ ]]; then
					fail "请输入数字"
					info_2 "输入每月带宽上限 （以GB为单位）："
					read upload_threshold
				else
					break
				fi
			done
			info_2 "输入每月带宽下载上限 （以GB为单位）："
			read download_threshold
			while true
			do
				if ! [[ "$download_threshold" =~ ^[0-9]+$ ]]; then
					fail "请输入数字"
					info_2 "输入每月带宽下载上限 （以GB为单位）："
					read download_threshold
				else
					break
				fi
			done
			# Set the bandwidth reset day
			info_2 "输入带宽刷新日 (01-31): " 
			read reset_day
			while true
			do
				if ! [[ $reset_day =~ ^[0-9]{1,2}$ ]] || [ $reset_day -lt 1 ] || [ $reset_day -gt 31 ]; then
					fail "请输入01-31之间的数字"
					info_2 "输入带宽刷新日 (01-31): " 
					read reset_day
				else
					break
				fi
			done
			# Add leading zero if necessary
			reset_day=$(printf "%02d" $reset_day)
			BLA::start_loading_animation "${BLA_classic[@]}"
			bandwidth_limit_ &> /dev/null
			if [ $? -eq 0 ]; then
				bandwidth_limit_success=1
			else
				bandwidth_limit_success=0
			fi
			BLA::stop_loading_animation
			if [ $bandwidth_limit_success -eq 1 ]; then
				info "每月带宽上限设置成功"
			else
				fail "每月带宽上限设置失败"
			fi
			;;
		c )
			seperator
			info "CPU滥用关机"
			info_2 "输入CPU滥用阈值 (0-100%):"
			read cpu_limit
			while true
			do
				if ! [[ "$cpu_limit" =~ ^[0-9]+$ ]]; then
					fail "请输入数字"
					info_2 "输入CPU滥用阈值 (0-100%):"
					read cpu_limit
				else
					break
				fi
			done
			BLA::start_loading_animation "${BLA_classic[@]}"
			cpu_abuse_shutdown_ &> /dev/null
			if [ $? -eq 0 ]; then
				cpu_shutdown_success=1
			else
				cpu_shutdown_success=0
			fi
			BLA::stop_loading_animation
			if [ $cpu_shutdown_success -eq 1 ]; then
				info "CPU滥用关机设置成功"
			else
				fail "CPU滥用关机设置失败"
			fi
			;;

		d )
			seperator
			info "DDoS 自动关机"
			info_2 "输入DDoS攻击阈值 (Mbps):"
			read speed_limit
			while true
			do
				if ! [[ "$speed_limit" =~ ^[0-9]+$ ]]; then
					fail "请输入数字"
					info_2 "输入DDoS攻击阈值 (Mbps):"
					read speed_limit
				else
					break
				fi
			done
			
			info_2 "输入DDoS攻击阈值 (pps):"
			read packet_limit
			while true
			do
				if ! [[ "$packet_limit" =~ ^[0-9]+$ ]]; then
					fail "请输入数字"
					info_2 "输入DDoS攻击阈值 (pps):"
					read packet_limit
				else
					break
				fi
			done
			BLA::start_loading_animation "${BLA_classic[@]}"
			ddos_shutdown_ &> /dev/null
			if [ $? -eq 0 ]; then
				ddos_shutdown_success=1
			else
				ddos_shutdown_success=0
			fi
			BLA::stop_loading_animation
			if [ $ddos_shutdown_success -eq 1 ]; then
				info "DDoS 自动关机设置成功"
			else
				fail "DDoS 自动关机设置失败"
			fi
			;;
		s )
			seperator
			info "SSH登录安全設定"
			ssh_secure_
			if [ $? -eq 0 ]; then
				ssh_secure_success=1
			else
				ssh_secure_success=0
			fi
			if [ $ssh_secure_success -eq 1 ]; then
				info "SSH登录安全設定成功"
			else
				fail "SSH登录安全設定失败"
			fi
			BLA::start_loading_animation "${BLA_classic[@]}"
			fail2ban_ &> /dev/null
			if [ $? -eq 0 ]; then
				fail2ban_success=1
			else
				fail2ban_success=0
			fi
			BLA::stop_loading_animation
			if [ $fail2ban_success -eq 1 ]; then
				info "Fail2ban安装成功"
			else
				fail "Fail2ban安装失败"
			fi
			;;
		t )
			seperator
			info "调整系统参数"
			BLA::start_loading_animation "${BLA_classic[@]}"
			tune_ &> /dev/null
			if [ $? -eq 0 ]; then
				tune_success=1
			else
				tune_success=0
			fi
			BLA::stop_loading_animation
			if [ $tune_success -eq 1 ]; then
				info "系统参数调整成功"
			else
				fail "系统参数调整失败"
			fi
			;;
		x )
			seperator
			info "安装BBRx"
			if [[ "$virt_tech" =~ "LXC" ]] || [[ "$virt_tech" =~ "lxc" ]]; then
				fail "不支持LXC"
				exit 1
			fi
			#Only support Debian and Ubuntu
			if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
				BLA::start_loading_animation "${BLA_classic[@]}"
				install_bbrx_ &> /dev/null
				if [ $? -eq 0 ]; then
					bbrx_success=1
				else
					bbrx_success=0
				fi
				BLA::stop_loading_animation
				if [ $bbrx_success -eq 1 ]; then
					info "重启系统以启用BBRx"
				else
					fail "BBRx安装失败"
				fi
			else
				fail "不支持此系统"
			fi
			;;
		3 )
			seperator
			info "安装BBRv3"
			if [[ "$virt_tech" =~ "LXC" ]] || [[ "$virt_tech" =~ "lxc" ]]; then
				fail "不支持LXC"
				exit 1
			fi
			#Only support Debian and Ubuntu
			if [[ $os =~ "Ubuntu" ]] || [[ $os =~ "Debian" ]]; then
				BLA::start_loading_animation "${BLA_classic[@]}"
				install_bbrv3_ &> /dev/null
				if [ $? -eq 0 ]; then
					bbrv3_success=1
				else
					bbrv3_success=0
				fi
				BLA::stop_loading_animation
				if [ $bbrv3_success -eq 1 ]; then
					info "重启系统以启用BBRv3"
				else
					fail "BBRv3安装失败"
				fi
			else
				fail "不支持此系统"
			fi
			;;
		h )
			info "用法： ./tune.sh [选项]"
			info "选项："
			info "  -b  设置每月带库上限"
			info "  -d  DDoS 自动关机"
			info "  -s  SSH登录安全設定"
			info "  -t  调整系统参数"
			info "  -x  安装BBRx"
			info "  -3  安装BBRv3"
			info "  -h  显示此帮助信息"
			exit 0
			;;
		\? )
			info "Invalid Option: -$OPTARG" 1>&2
			exit 1
			;;
	esac

done