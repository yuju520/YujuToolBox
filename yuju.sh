#!/bin/bash
#版本信息
version="0.0.1"
#region //定义颜色
white='\033[0m'
green='\033[0;32m'
blue='\033[0;34m'
red='\033[31m'
yellow='\033[33m'
grey='\e[37m'
pink='\033[38;5;218m'
cyan='\033[96m'
#endregion

#复制脚本到/usr/local/bin/yuju
cp ./yuju.sh /usr/local/bin/yuju > /dev/null 2>&1

#region //授权监测
#初始化授权状态
user_authorization="false"

authorization_check() {
    if grep -q '^user_authorization="true"' /usr/local/bin/yuju > /dev/null 2>&1; then
        sed -i 's/^user_authorization="false"/user_authorization="true"/' ./yuju.sh
    fi
}

authorization_check

authorization_false() {
    if grep -q '^user_authorization="false"' /usr/local/bin/yuju > /dev/null 2>&1; then
        user_agreement
    fi
}

# 提示用户协议
user_agreement() {
    clear
    echo -e "${pink}欢迎使用yuju一键工具${white}"
    echo "此脚本基于自用开发"
    echo -e "${red}请尽量通过选择脚本选项退出${white}"
    echo "如有问题，后果自负"
    echo -e "${pink}============================${white}"
    read -r -p "是否同意？(y/n): " user_input


    if [ "$user_input" = "y" ] || [ "$user_input" = "Y" ]; then
        echo "已同意"
        sed -i 's/^user_authorization="false"/user_authorization="true"/' ./yuju.sh
        sed -i 's/^user_authorization="false"/user_authorization="true"/' /usr/local/bin/yuju
    else
        echo "已拒绝"
        exit 1
    fi
}

authorization_false
#endregion

#region //操作完成提示
break_end() {
      echo -e "${green}执行完成${white}"
      echo -e "${green}按任意键返回菜单...${white}"
      read -n 1 -s -r -p ""
      echo ""
      clear
}
#endregion

#region //快捷指令
yuju_sh() {
            yuju
            exit
}
#endregion

#region //root用户检测
root_test(){
    clear
    [ "$EUID" -ne 0 ] && echo -e "${red}提示: ${bai}该功能需要root用户才能运行！" && break_end && yuju_sh
}
#endregion

#1. 系统相关
#region //1.1 系统信息查询

system_info() {

    clear

    ipv4_address=$(curl -s --max-time 1 ipv4.ip.sb)
    ipv6_address=$(curl -s --max-time 1 ipv6.ip.sb)
    cpu_info=$(lscpu | awk -F': +' '/Model name:/ {print $2; exit}')
    cpu_usage_percent=$(awk '{u=$2+$4; t=$2+$4+$5; if (NR==1){u1=u; t1=t;} else printf "%.0f\n", (($2+$4-u1) * 100 / (t-t1))}' \
        <(grep 'cpu ' /proc/stat) <(sleep 1; grep 'cpu ' /proc/stat))

    cpu_cores=$(nproc)
    mem_info=$(free -b | awk 'NR==2{printf "%.2f/%.2f MB (%.2f%%)", $3/1024/1024, $2/1024/1024, $3*100/$2}')
    disk_info=$(df -h | awk '$NF=="/"{printf "%s/%s (%s)", $3, $2, $5}')
    ipinfo=$(curl -s ipinfo.io)
    country=$(echo "$ipinfo" | grep 'country' | awk -F': ' '{print $2}' | tr -d '",')
    city=$(echo "$ipinfo" | grep 'city' | awk -F': ' '{print $2}' | tr -d '",')
    isp_info=$(echo "$ipinfo" | grep 'org' | awk -F': ' '{print $2}' | tr -d '",')
    cpu_arch=$(uname -m)
    hostname=$(hostname)
    kernel_version=$(uname -r)
    congestion_algorithm=$(sysctl -n net.ipv4.tcp_congestion_control)
    queue_algorithm=$(sysctl -n net.core.default_qdisc)
    os_info=$(grep PRETTY_NAME /etc/os-release | cut -d '=' -f2 | tr -d '"')
    output=$(awk 'BEGIN { rx_total = 0; tx_total = 0 }
        NR > 2 { rx_total += $2; tx_total += $10 }
        END {
            rx_units = "Bytes";
            tx_units = "Bytes";
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "KB"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "MB"; }
            if (rx_total > 1024) { rx_total /= 1024; rx_units = "GB"; }

            if (tx_total > 1024) { tx_total /= 1024; tx_units = "KB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "MB"; }
            if (tx_total > 1024) { tx_total /= 1024; tx_units = "GB"; }

            printf("总接收: %.2f %s\n总发送: %.2f %s\n", rx_total, rx_units, tx_total, tx_units);
        }' /proc/net/dev)

    current_time=$(date "+%Y-%m-%d %I:%M %p")
    swap_info=$(free -m | awk 'NR==3{used=$3; total=$2; if (total == 0) {percentage=0} else {percentage=used*100/total}; printf "%dMB/%dMB (%d%%)", used, total, percentage}')
    runtime=$(cat /proc/uptime | awk -F. '{run_days=int($1 / 86400);run_hours=int(($1 % 86400) / 3600);run_minutes=int(($1 % 3600) / 60); if (run_days > 0) printf("%d天 ", run_days); if (run_hours > 0) printf("%d时 ", run_hours); printf("%d分\n", run_minutes)}')
    timezone=$(timedatectl | grep "Time zone" | awk '{print $3}')


    echo ""
    echo "系统信息查询"
    echo -e "${pink}============机器信息============${white}"
    echo "主机名: $hostname"
    echo "运营商: $isp_info"
    echo -e "${pink}============版本信息============${white}"
    echo "系统版本: $os_info"
    echo "Linux版本: $kernel_version"
    echo -e "${pink}============CPU 信息============${white}"
    echo "CPU架构: $cpu_arch"
    echo "CPU型号: $cpu_info"
    echo "CPU核心数: $cpu_cores"
    echo -e "${pink}============占用信息============${white}"
    echo "CPU占用: $cpu_usage_percent%"
    echo "物理内存: $mem_info"
    echo "虚拟内存: $swap_info"
    echo "硬盘占用: $disk_info"
    echo -e "${pink}============流量信息============${white}"
    echo "$output"
    echo -e "${pink}============算法信息============${white}"
    echo "网络拥堵算法: $congestion_algorithm $queue_algorithm"
    echo -e "${pink}============ IP 信息============${white}"
    echo "公网IPv4地址: $ipv4_address"
    echo "公网IPv6地址: $ipv6_address"
    echo -e "${pink}============时区信息============${white}"
    echo "地理位置: $country $city"
    echo "系统时区: $timezone"
    echo "系统时间: $current_time"
    echo -e "${pink}============运行时长============${white}"
    echo "系统运行时长: $runtime"
    echo

}
#endregion

#region //1.2 更新系统软件包
system_update(){
    clear
    apt update -y && apt upgrade -y
    clear
    echo "系统软件包更新完毕"
}
#endregion

#region //1.3 系统清理
system_clean(){
clear
# 确保脚本以root权限运行
if [[ $EUID -ne 0 ]]; then
   echo "此脚本必须以root权限运行"
   exit 1
fi
start_space=$(df / | tail -n 1 | awk '{print $3}')
echo -e "${huang}正在进行系统清理...${bai}"
# 检测并设置包管理器变量
if command -v apt-get > /dev/null; then
    PKG_MANAGER="apt"
    CLEAN_CMD="apt-get autoremove -y && apt-get clean"
    PKG_UPDATE_CMD="apt-get update"
    INSTALL_CMD="apt-get install -y"
    PURGE_CMD="apt-get purge -y"
elif command -v dnf > /dev/null; then
    PKG_MANAGER="dnf"
    CLEAN_CMD="dnf autoremove -y && dnf clean all"
    PKG_UPDATE_CMD="dnf update"
    INSTALL_CMD="dnf install -y"
    PURGE_CMD="dnf remove -y"
elif command -v apk > /dev/null; then
    PKG_MANAGER="apk"
    CLEAN_CMD="apk cache clean"
    PKG_UPDATE_CMD="apk update"
    INSTALL_CMD="apk add"
    PURGE_CMD="apk del"
else
    echo "不支持的包管理器"
    exit 1
fi

# 正在更新依赖
echo "正在更新依赖..."
if [ "$PKG_MANAGER" = "apt" ] && [ ! -x /usr/bin/deborphan ]; then
    $PKG_UPDATE_CMD > /dev/null 2>&1
    $INSTALL_CMD deborphan > /dev/null 2>&1
fi

# 安全删除旧内核（只适用于使用apt和dnf的系统）
echo "正在删除未使用的内核..."
if [[ "$PKG_MANAGER" == "apt" || "$PKG_MANAGER" == "dnf" ]]; then
    current_kernel=$(uname -r)
    if [[ "$PKG_MANAGER" == "apt" ]]; then
        kernel_packages=$(dpkg --list | grep -E '^ii  linux-(image|headers)-[0-9]+' | awk '{ print $2 }' | grep -v "$current_kernel")
    else
        kernel_packages=$(rpm -qa | grep -E '^kernel-(core|modules|devel)-[0-9]+' | grep -v "$current_kernel")
    fi
    if [ ! -z "$kernel_packages" ]; then
        echo "找到旧内核，正在删除：$kernel_packages"
        $PURGE_CMD $kernel_packages > /dev/null 2>&1
        [[ "$PKG_MANAGER" == "apt" ]] && update-grub > /dev/null 2>&1
    else
        echo "没有旧内核需要删除。"
    fi
fi

# 清理系统日志文件
echo "正在清理系统日志文件..."
find /var/log -type f -name "*.log" -exec truncate -s 0 {} \; > /dev/null 2>&1
find /root -type f -name "*.log" -exec truncate -s 0 {} \; > /dev/null 2>&1
find /home -type f -name "*.log" -exec truncate -s 0 {} \; > /dev/null 2>&1
find /ql -type f -name "*.log" -exec truncate -s 0 {} \; > /dev/null 2>&1

# 清理缓存目录
echo "正在清理缓存目录..."
find /tmp -type f -mtime +1 -exec rm -f {} \;
find /var/tmp -type f -mtime +1 -exec rm -f {} \;
for user in /home/* /root; do
  cache_dir="$user/.cache"
  if [ -d "$cache_dir" ]; then
    rm -rf "$cache_dir"/* > /dev/null 2>&1
  fi
done

# 清理Docker（如果使用Docker）
if command -v docker &> /dev/null
then
    echo "正在清理Docker镜像、容器和卷..."
    docker system prune -a -f --volumes > /dev/null 2>&1
fi

# 清理孤立包（仅apt）
if [ "$PKG_MANAGER" = "apt" ]; then
    echo "正在清理孤立包..."
    deborphan --guess-all | xargs -r apt-get -y remove --purge > /dev/null 2>&1
fi

# 清理包管理器缓存
echo "正在清理包管理器缓存..."
$CLEAN_CMD > /dev/null 2>&1

end_space=$(df / | tail -n 1 | awk '{print $3}')
cleared_space=$((start_space - end_space))
echo "系统清理完成，清理了 $((cleared_space / 1024))M 空间！"
}
#endregion

#region //1.4 系统配置调优
system_optimization(){
    bash <(wget -qO- https://raw.githubusercontent.com/jerry048/Tune/main/tune.sh) -t
	}
#endregion

#region //1.5 将时区改为上海
system_time(){
    sudo timedatectl set-timezone Asia/Shanghai
    echo "已成功将时区改为上海"
}
#endregion

#region //1.6 BBRx
system_bbr(){
    bash <(wget -qO- https://raw.githubusercontent.com/jerry048/Tune/main/tune.sh) -x
	}
#endregion

#region //1.7 SWAP
system_swap(){
    #root权限
    root_need(){
        if [[ $EUID -ne 0 ]]; then
            echo -e "${red}Error:This script must be run as root!${white}"
            exit 1
        fi
    }
    
    #检测ovz
    ovz_no(){
        if [[ -d "/proc/vz" ]]; then
            echo -e "${red}Your VPS is based on OpenVZ，not supported!${white}"
            exit 1
        fi
    }
    
    add_swap(){
    echo -e "${green}请输入需要添加的swap，建议为内存的2倍！${white}"
    read -p "请输入swap数值:" swapsize
    
    #检查是否存在swapfile
    grep -q "swapfile" /etc/fstab
    
    #如果不存在将为其创建swap
    if [ $? -ne 0 ]; then
    	echo -e "${green}swapfile未发现，正在为其创建swapfile${white}"
    	fallocate -l ${swapsize}M /swapfile
    	chmod 600 /swapfile
    	mkswap /swapfile
    	swapon /swapfile
    	echo '/swapfile none swap defaults 0 0' >> /etc/fstab
             echo -e "${green}swap创建成功，并查看信息：${white}"
             cat /proc/swaps
             cat /proc/meminfo | grep Swap
    else
    	echo -e "${red}swapfile已存在，swap设置失败，请先运行脚本删除swap后重新设置！${white}"
    fi
    }
    
    del_swap(){
    #检查是否存在swapfile
    grep -q "swapfile" /etc/fstab
    
    #如果存在就将其移除
    if [ $? -eq 0 ]; then
    	echo -e "${green}swapfile已发现，正在将其移除...${white}"
    	sed -i '/swapfile/d' /etc/fstab
    	echo "3" > /proc/sys/vm/drop_caches
    	swapoff -a
    	rm -f /swapfile
        echo -e "${green}swap已删除！${white}"
    else
    	echo -e "${red}swapfile未发现，swap删除失败！${white}"
    fi
    }
    
    #开始菜单
    main(){
    root_need
    ovz_no
    clear
    echo -e "———————————————————————————————————————"
    echo -e "${green}Linux VPS一键添加/删除swap脚本${white}"
    echo -e "${green}1、添加swap${white}"
    echo -e "${green}2、删除swap${white}"
    echo -e "${green}0、返回主菜单${white}"
    echo -e "———————————————————————————————————————"
    read -p "请输入数字 [0-2]:" num
    case "$num" in
        1)
        add_swap
        ;;
        2)
        del_swap
        ;;
        0)
        clear
        yuju_menu
        ;;
        *)
        clear
        echo -e "${green}请输入正确数字 [0-2]${white}"
        main
        ;;
        esac
    }
    main
    }
#endregion

#region //1.8 修改SSH端口
system_ssh(){
    # 提示用户输入端口号，默认值为55520
    read -p "请输入要设置的SSH端口号（按Enter使用默认端口55520）: " PORT
    
    # 如果用户直接按Enter键，设置端口为默认值55520
    PORT=${PORT:-55520}
    
    # 修改sshd配置文件中的端口号
    sudo sed -i "s/^#\?Port .*/Port $PORT/g" /etc/ssh/sshd_config
    
    # 重启SSH服务以应用更改
    sudo systemctl restart sshd
    
    # 输出成功信息
    echo "SSH端口已修改为 $PORT"
}

#endregion

#region //1.9 安装fail2ban
system_fail2ban(){
    apt install fail2ban
    sudo bash -c 'cat <<EOF > /etc/fail2ban/jail.local
[DEFAULT]
#忽略的IP列表,不受设置限制（白名单）
ignoreip = 127.0.0.1

#允许ipv6
allowipv6 = auto

#日志修改检测机制（gamin、polling和auto这三种）
backend = systemd

#针对各服务的检查配置，如设置bantime、findtime、maxretry和全局冲突，服务优先级大于全局设置

[sshd]

#是否激活此项（true/false）
enabled = true

#过滤规则filter的名字，对应filter.d目录下的sshd.conf
filter = sshd

#ssh端口
port = ssh

#动作的相关参数
action = iptables[name=SSH, port=ssh, protocol=tcp]

#检测的系统的登陆日志文件
logpath = /var/log/secure

#屏蔽时间，单位：秒
bantime = 86400

#这个时间段内超过规定次数会被ban掉
findtime = 86400

#最大尝试次数
maxretry = 3
EOF'

    sudo systemctl enable fail2ban
    sudo systemctl restart fail2ban
    clear
    echo "已成功安装fail2ban"
}
#endregion

#region //1.10 密钥登录
system_keygen(){
# 创建SSH Key
    if [ -f ~/.ssh/id_rsa ]; then
        echo "SSH Key已经存在"
    else
        echo "创建SSH Key..."
        ssh-keygen -t rsa -f ~/.ssh/id_rsa -q -N ""
    fi
    
    # 授权密钥
    cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
    chmod 600 ~/.ssh/authorized_keys
    chmod 700 ~/.ssh
    
    # 修改SSH相关配置
    sudo sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
    sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/g' /etc/ssh/sshd_config
    
    # 重启SSH服务
    sudo systemctl restart sshd
    
    # 输出生成的私钥
    echo "密码登录已关闭！"
    echo "密钥登录已开启！"
    echo "您的SSH Key为，请牢记！"
    cat ~/.ssh/id_rsa
}
#endregion

#region //1.11 OpenSSH升级
system_openssh(){
    clear
    apt install --only-upgrade openssh-server
    clear
    echo "OpenSSH已升级"
}
#endregion

#region //1.12 将默认编码修改为UTF-8
system_utf(){
    clear
    # 检查当前的编码设置
    current_locale=$(locale | grep LANG)
    echo "当前系统编码设置: $current_locale"
    
    # 设置系统locale为UTF-8
    sudo localectl set-locale LANG=en_US.UTF-8
    
    # 更新环境变量
    source /etc/environment
    
    # 显示当前locale设置
    echo "当前系统locale设置为:"
    locale
    echo "默认编码已成功更改为UTF-8。请重新启动终端或注销并重新登录以应用更改。"
}
#endregion

#2. 测试脚本
#region //2.1 SpeedTest带宽测速
bandwidth_test(){
    clear
    # 获取当前系统的国家代码
    country=$(curl -s ipinfo.io/country)

    # 判断国家是否为中国（CN）
    if [ "$country" == "CN" ]; then
        # 检查是否已经存在 taierspeed-cli
        if [ ! -f ./taierspeed-cli ]; then
            echo "taierspeed-cli 不存在，正在下载..."
            
            # 获取系统架构
            arch=$(uname -m)
        
            # 根据系统架构设置对应的下载URL
            case "$arch" in
                x86_64)
                    # 64位系统
                    url="https://mirror.ghproxy.com/https://github.com/ztelliot/taierspeed-cli/releases/download/v1.7.2/taierspeed-cli_1.7.2_linux_amd64"
                    ;;
                arm64|aarch64)
                    # ARM 64位系统
                    url="https://mirror.ghproxy.com/https://github.com/ztelliot/taierspeed-cli/releases/download/v1.7.2/taierspeed-cli_1.7.2_linux_arm64"
                    ;;
                armv7l|armhf)
                    # ARM 32位系统
                    url="https://mirror.ghproxy.com/https://github.com/ztelliot/taierspeed-cli/releases/download/v1.7.2/taierspeed-cli_1.7.2_linux_armv7"
                    ;;
                *)
                    echo "未识别的系统架构: $arch"
                    exit 1
                    ;;
            esac
        
            # 下载并设置执行权限
            wget -O taierspeed-cli "$url" && chmod +x taierspeed-cli
        else
            echo "taierspeed-cli 已存在，跳过下载步骤。"
            clear
        fi

        # 安装jq和bc解析json信息
        sudo apt-get install -y jq bc > /dev/null 2>&1 &
        clear
        echo "本机器地理位置为中国，使用taierspeed-cli测速..."
        echo "测速中，请等待..."
        # 运行speedtest并获取JSON输出
        json_output=$(./taierspeed-cli --json)
        
        # 提取测试时间
        timestamp=$(echo "$json_output" | jq -r '.results[0].timestamp')
        
        # 提取区域信息
        location=$(echo "$json_output" | jq -r '.client.city')
        
        # 提取下载速度并转换为MB/s
        download_bandwidth=$(echo "$json_output" | jq -r '.results[0].download')
        download_speed=$(echo "scale=2; $download_bandwidth / 8" | bc)
        
        # 提取上传速度并转换为MB/s
        upload_bandwidth=$(echo "$json_output" | jq -r '.results[0].upload')
        upload_speed=$(echo "scale=2; $upload_bandwidth / 8" | bc)

        # 输出信息
        echo "测试时间: $timestamp"
        echo "区域信息: $location"
        echo "下载速度: $download_speed MB/s"
        echo "上传速度: $upload_speed MB/s"

    else
        clear

        # 检查是否已经安装speedtest-cli
        if ! command -v speedtest &> /dev/null; then
            echo "speedtest-cli 未安装，正在安装..."
            sudo apt-get install curl -y > /dev/null 2>&1 &
            curl -s https://packagecloud.io/install/repositories/ookla/speedtest-cli/script.deb.sh | sudo bash
            sudo apt-get install speedtest -y
        else
            echo "speedtest-cli 已安装，跳过安装步骤。"
        fi
        
        # 安装jq和bc解析json信息
        sudo apt-get install -y jq bc > /dev/null 2>&1 &
        clear
        echo "本机器地理位置不在中国，使用speedtest-cli测速..."
        echo "测速中，请等待..."
        
        # 运行speedtest并获取JSON输出
        json_output=$(speedtest -f json-pretty)
        
        # 提取测试时间
        timestamp=$(echo "$json_output" | jq -r '.timestamp')
        
        # 提取区域信息
        location=$(echo "$json_output" | jq -r '.server.location')
        
        # 提取下载速度并转换为MB/s
        download_bandwidth=$(echo "$json_output" | jq -r '.download.bandwidth')
        download_speed=$(echo "scale=2; $download_bandwidth / 1000 / 1000" | bc)
        
        # 提取上传速度并转换为MB/s
        upload_bandwidth=$(echo "$json_output" | jq -r '.upload.bandwidth')
        upload_speed=$(echo "scale=2; $upload_bandwidth / 1000 / 1000" | bc)
        
        # 提取测试结果URL
        result_url=$(echo "$json_output" | jq -r '.result.url')
        
        # 输出信息
        echo "测试时间: $timestamp"
        echo "区域信息: $location"
        echo "下载速度: $download_speed MB/s"
        echo "上传速度: $upload_speed MB/s"
        echo "测试结果链接: $result_url"
    fi
}
#endregion

#region //2.2 xykt_IP质量体检脚本
ip_test(){
    clear
    echo "IP质量检测中..."
    bash <(curl -Ls IP.Check.Place)
}
#endregion

#region //2.3 nxtrace快速回程测试脚本
router_test(){
    clear
    curl nxtrace.org/nt |bash
    nexttrace --fast-trace --tcp
}
#endregion

#region //2.4 yabs性能测试
performance_test(){
    clear
    wget -qO- yabs.sh | bash
}
#endregion

#region //2.5 IPv4/IPv6优先级测试
ip_priority_test(){
    clear
    
    # 测试 IPv4 和 IPv6 的连接
    ipv4_test="ipv4.test-ipv6.com"
    ipv6_test="ipv6.test-ipv6.com"
    
    # 使用 curl 尝试连接 IPv4 和 IPv6
    ipv4_output=$(curl -4 -s --max-time 5 $ipv4_test > /dev/null && echo "IPv4正常工作" || echo "IPv4连接失败")
    ipv6_output=$(curl -6 -s --max-time 5 $ipv6_test > /dev/null && echo "IPv6正常工作" || echo "IPv6连接失败")
    
    echo "测试连通性:"
    echo "$ipv4_output"
    echo "$ipv6_output"
    echo ""
    
    # 检查系统配置
    echo "优先级测试:"
    ipv6_priority=$(cat /etc/gai.conf | grep "precedence ::ffff:0:0/96" | grep -v "#" | wc -l)
    
    
    # 最终判断
    if [[ "$ipv6_output" == "IPv6正常工作" && "$ipv4_output" == "IPv4正常工作" ]]; then
        if [ $ipv6_priority -gt 0 ]; then
            echo "IPv4的优先级更高"
        else
            echo "IPv6的优先级更高"
        fi
    elif [[ "$ipv6_output" == "IPv6正常工作" ]]; then
        echo "只有IPv6正常工作, 因此IPv6优先级更高"
    elif [[ "$ipv4_output" == "IPv4正常工作" ]]; then
        echo "只有IPv4正常工作, 因此IPv4优先级更高"
    else
        echo "IPv4 和 IPv6 似乎都无法正常工作。"
    fi
}
#endregion

#region //2.6 硬盘I/O测试
io_test() {
    (LANG=C dd if=/dev/zero of=test_$$ bs=64k count=16k conv=fdatasync && rm -f test_$$ ) 2>&1 | awk -F, '{io=$NF} END { print io}' | sed 's/^[ \t]*//;s/[ \t]*$//'
}

io_info()
{
    echo "开始测试IO性能..."
	#获得相关数据
	io1=$( io_test )
	echo "硬盘I/O (第一次测试) : $io1"
	io2=$( io_test )
	echo "硬盘I/O (第二次测试) : $io2"
	io3=$( io_test )
	echo "硬盘I/O (第三次测试) : $io3"
	ioraw1=$( echo $io1 | awk 'NR==1 {print $1}' )
	[ "`echo $io1 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw1=$( awk 'BEGIN{print '$ioraw1' * 1024}' )
	ioraw2=$( echo $io2 | awk 'NR==1 {print $1}' )
	[ "`echo $io2 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw2=$( awk 'BEGIN{print '$ioraw2' * 1024}' )
	ioraw3=$( echo $io3 | awk 'NR==1 {print $1}' )
	[ "`echo $io3 | awk 'NR==1 {print $2}'`" == "GB/s" ] && ioraw3=$( awk 'BEGIN{print '$ioraw3' * 1024}' )
	ioall=$( awk 'BEGIN{print '$ioraw1' + '$ioraw2' + '$ioraw3'}' )
	ioavg=$( awk 'BEGIN{print '$ioall'/3}' )
	echo "硬盘I/O (平均值) : $ioavg MB/s"
}
#endregion

#3. 常用工具下载
#region //3.1 curl下载工具
download_curl(){
    clear
    apt install curl -y
    echo "curl安装完成"
}
#endregion

#region //3.2 wget下载工具
download_wget(){
    clear
    apt install wget -y
    echo "wget安装完成"
}
#endregion

#region //3.3 nano文档工具
download_nano(){
    clear
    apt install nano -y
    echo "nano安装完成"
}
#endregion

#region //3.4 unzip解压缩工具
download_unzip(){
    clear
    apt install unzip -y
    echo "unzip安装完成"
}
#endregion

#region //3.5 tar解压缩工具
download_tar(){
    clear
    apt install tar -y
    echo "tar安装完成"
}
#endregion

#region //3.6 tmux后台工具
download_tmux(){
    clear
    apt install tmux -y
    echo "tmux安装完成"
}
#endregion

#region //3.7 iftop网络流量监控工具
download_iftop(){
    clear
    apt install iftop -y
    echo "iftop安装完成"
}
#endregion

#region //3.8 btop现代化监控工具
download_btop(){
    clear
    apt install btop -y
    echo "btop安装完成"
}
#endregion

#region //3.9 gdu磁盘占用查看工具
download_gdu(){
    clear
    apt install gdu -y
    echo "gdu安装完成"
}
#endregion

#region //3.10 fzf文件管理工具
download_fzf(){
    clear
    apt install fzf -y
    echo "fzf安装完成"
}
#endregion

#region //3.11 zsh+ohmyzsh终端美化工具
download_zsh(){
    clear
    apt install zsh -y && apt install curl -y
	chsh -s $(which zsh)
    curl -sS https://starship.rs/install.sh | sh
    echo 'eval "$(starship init zsh)"' >> ~/.zshrc
    echo "zsh+Starship安装完成,重新登录终端即可启用"
}
#endregion

#region //3.12 一键安装所有
download_all(){
    clear
    apt install curl wget nano unzip tar tmux iftop btop gdu fzf -y
    download_zsh
    echo "已全部安装"
}
#endregion

#4. docker管理
#region //4.1 安装Docker环境
docker_install(){
    clear

    # 检查Docker是否已经安装
    if command -v docker &> /dev/null; then
        echo "Docker已经安装。"
        return 0
    fi

    # 获取当前系统的国家代码
    country=$(curl -s ipinfo.io/country)

    # 判断国家是否为中国（CN）
    if [ "$country" == "CN" ]; then
        echo "本机器地理位置为中国，正在使用国内安装脚本..."
        curl https://install.1panel.live/docker-install -o docker-install
        sudo bash ./docker-install
        rm -f ./docker-install
        echo "Docker安装完成，正在切换镜像源（由1panel提供）..."
        touch /etc/docker/daemon.json
        cat > /etc/docker/daemon.json << EOF
{
    "registry-mirrors": ["https://docker.1panel.live"]
}
EOF
    else
        echo "本机器地理位置不在中国，正在使用官方Docker安装脚本..."
        wget -qO- get.docker.com | bash
        touch /etc/docker/daemon.json
    fi

    echo "Docker安装过程完成。"
}

#endregion

#region //4.2 查看Docker全局状态
docker_status(){
    # 检查 Docker 是否安装
    if ! command -v docker &> /dev/null; then
        echo "Docker 环境不存在，请确保 Docker 已安装并配置。"
        return 1
    fi

    echo "Docker版本"
    docker -v
    docker compose version
    echo ""
    
    echo "Docker镜像列表"
    docker image ls
    echo ""
    
    echo "Docker容器列表"
    docker ps -a
    echo ""
    
    echo "Docker卷列表"
    docker volume ls
    echo ""
    
    echo "Docker网络列表"
    docker network ls
    echo ""

    if [ -f /etc/docker/daemon.json ]; then
        mirrors=$(jq -r '.["registry-mirrors"][]' /etc/docker/daemon.json 2>/dev/null)
        
        if [ -n "$mirrors" ]; then
            echo "镜像源地址"
            echo "$mirrors"
        else
            echo "未配置镜像源"
        fi
    else
        echo ""
    fi

}

#endregion

#region //4.3 Docker清理无用的镜像容器网络
docker_clean(){
    clear
    read -p "$(echo -e "${huang}提示: ${bai}将清理无用的镜像容器网络，包括停止的容器，确定清理吗？(Y/N): ")" choice
    case "$choice" in
      [Yy])
        docker system prune -af --volumes
        ;;
      [Nn])
        ;;
      *)
        echo "无效的选择，请输入 Y 或 N。"
        ;;
    esac
}
#endregion

#region //4.4 更换Docker源
docker_mirrors(){
    # Docker daemon.json 文件路径
    docker_daemon="/etc/docker/daemon.json"

    # 检查 daemon.json 是否存在
    if [ ! -f "$docker_daemon" ]; then
        echo "文件 $docker_daemon 不存在，请确保 Docker 已安装并配置。"
        exit 1
    fi

    # 定义一个函数用来处理用户输入和验证
    get_mirror_input() {
        while true; do
            read -p "请输入镜像源地址（含http://或https://），输入'q'退出: " new_mirror

            # 检查用户是否输入了'q'来退出
            if [ "$new_mirror" = "q" ]; then
                echo "操作已取消。"
                docker_manage
            fi

            # 检查输入的地址是否包含 http:// 或 https:// 前缀
            if [[ "$new_mirror" =~ ^https?:// ]]; then
                break
            else
                echo "错误：镜像源地址必须以 http:// 或 https:// 开头，请重新输入。"
            fi
        done
    }

    # 查找 registry-mirrors 参数
    if grep -q '"registry-mirrors"' "$docker_daemon"; then
        # 如果存在 registry-mirrors 参数，则提示输入新的 https 地址
        echo "检测到已有镜像源地址。"
        get_mirror_input

        # 使用 sed 命令替换 registry-mirrors 的值
        sudo sed -i 's|"registry-mirrors":\s*\[[^]]*\]|"registry-mirrors": ["'"$new_mirror"'"]|' "$docker_daemon"
        
        echo "镜像源地址已更新为: $new_mirror"
    else
        # 如果不存在 registry-mirrors 参数，则提示输入 https 地址进行添加
        echo "未检测到镜像源地址。"
        get_mirror_input

        # 使用 cat 添加 registry-mirrors 参数
        sudo cat > "$docker_daemon" << EOF
{
    "registry-mirrors": ["$new_mirror"]
}
EOF
        
        echo "registry-mirrors 已添加为: $new_mirror"
    fi
    
    # 重启 Docker 服务以应用更改
    echo "正在重启 Docker 服务以应用更改..."
    sudo systemctl restart docker
    
    echo "修改完成！"
}
#endregion

#region //4.5 开启Docker IPv6
docker_ipv6_on(){
    mkdir -p /etc/docker &>/dev/null
    
    cat > /etc/docker/daemon.json << EOF
    
    {
      "ipv6": true,
      "fixed-cidr-v6": "2001:db8:1::/64"
    }
    
EOF
    
    systemctl restart docker
    
    echo "Docker已开启v6访问"
}
#endregion

#region //4.6 关闭Docker IPv6
docker_ipv6_off(){
    rm -rf etc/docker/daemon.json &>/dev/null

    systemctl restart docker

    echo "Docker已关闭v6访问"
}

#endregion

#region //4.9 卸载Docker环境
docker_uninstall(){
    clear
    read -p "$(echo -e "${hong}注意: ${bai}确定卸载docker环境吗？(Y/N): ")" choice
    case "$choice" in
      [Yy])
        docker rm $(docker ps -a -q) && docker rmi $(docker images -q) && docker network prune
        sudo apt-get purge -y docker-engine docker docker.io docker-ce docker-ce-cli
        sudo rm -rf /var/lib/docker
        sudo rm -rf /etc/docker
        sudo rm -rf /var/run/docker.sock

       ;;
      [Nn])
        ;;
      *)
        echo "无效的选择，请输入 Y 或 N。"
        ;;
    esac
}
#endregion

#region //1. 系统相关选项
system_related() {

  while true; do
      clear
    echo -e "${pink}========================${white}"
      echo "1. 系统信息查询"
      echo "2. 更新系统软件包"
      echo "3. 系统清理"
      echo "4. 系统配置调优"
      echo "5. 将时区改为改成上海"
      echo "6. 安装BBRx"
      echo "7. 修改SWAP"
      echo "8. 修改SSH端口"
      echo "9. 安装fail2ban"
      echo "10. 密钥登录"
      echo "11. OpenSSH升级"
      echo "12. 将默认编码修改为UTF-8"
    echo -e "${pink}========================${white}"
      echo "0. 返回主菜单"
    echo -e "${pink}========================${white}"
      read -p "请输入你的选择: " sub_choice
      case $sub_choice in
          1)
            clear
            system_info
              ;;
          2)
            clear
            system_update
              ;;
          3)
            clear
            system_clean
              ;;
          4)
            clear
            system_optimization
              ;;
          5)
            clear
            system_time
              ;;
          6)
            clear
            system_bbr
              ;;
          7)
            clear
            system_swap
              ;;
          8)
            clear
            system_ssh
              ;;
          9)
            clear
            system_fail2ban
              ;;
          10)
            clear
            system_keygen
              ;;
          11)
            clear
            system_openssh
              ;;
          12)
            clear
            system_utf
              ;;
          0)
            yuju_menu
              ;;

          *)
              echo "无效的输入!"
              ;;
        esac
            break_end
        done

        }

#endregion

#region //2. 测试脚本
test_script() {

  while true; do
      clear
      echo -e "${pink}========================${white}"
      echo "1. SpeedTest带宽测速"
      echo "2. xykt_IP质量体检脚本"
      echo "3. nxtrace快速回程测试脚本"
      echo "4. yabs性能测试"
      echo "5. IPv4/IPv6优先级测试"
      echo "6. 硬盘I/O测试"
      echo -e "${pink}========================${white}"
      echo "0. 返回主菜单"
      echo -e "${pink}========================${white}"
      read -p "请输入你的选择: " sub_choice
      case $sub_choice in
          1)
            clear
            bandwidth_test
              ;;
          2)
            clear
            ip_test
              ;;
          3)
            clear
            router_test
              ;;
          4)
            clear
            performance_test
              ;;
          5)
            clear
            ip_priority_test
              ;;
          6)
            clear
            io_info
              ;;
          0)
            yuju_menu
              ;;

          *)
              echo "无效的输入!"
              ;;
        esac
            break_end
        done

        }
#endregion

#region //3. 常用工具下载
useful_tools(){
  while true; do
      clear
      echo -e "${pink}========================${white}"
      echo "1. curl下载工具"
      echo "2. wget下载工具"
      echo "3. nano文档工具"
      echo "4. unzip解压缩工具"
      echo "5. tar解压缩工具"
      echo "6. tmux后台工具"
      echo "7. iftop网络流量监控工具"
      echo "8. btop现代化监控工具"
      echo "9. gdu磁盘占用查看工具"
      echo "10. fzf文件管理工具"
      echo "11. zsh+Starship终端美化工具"
      echo -e "${pink}========================${white}"
      echo "12. 一键安装所有"
      echo -e "${pink}========================${white}"
      echo "0. 返回主菜单"
      echo -e "${pink}========================${white}"
      read -p "请输入你的选择: " sub_choice
      case $sub_choice in
          1)
            clear
            download_curl
              ;;
          2)
            clear
            download_wget
              ;;
          3)
            clear
            download_nano
              ;;
          4)
            clear
            download_unzip
              ;;
          5)
            clear
            download_tar
              ;;
          6)
            clear
            download_tmux
              ;;
          7)
            clear
            download_iftop
              ;;
          8)
            clear
            download_btop
              ;;
          9)
            clear
            download_gdu
              ;;
          10)
            clear
            download_fzf
              ;;
          11)
            clear
            download_zsh
              ;;
          12)
            clear
            download_all
              ;;
          0)
            yuju_menu
              ;;

          *)
              echo "无效的输入!"
              ;;
        esac
            break_end
        done
}

#endregion

#region //4. Docker管理
docker_manage(){
    while true; do
      clear
      echo -e "${pink}========================${white}"
      echo -e "1. 安装Docker环境"
      echo -e "2. 查看Docker全局状态"
      echo -e "3. Docker清理无用的镜像容器网络"
      echo "4. 更换Docker源"
      echo "5. 开启Docker-ipv6访问"
      echo "6. 关闭Docker-ipv6访问"
      echo -e "${pink}========================${white}"
      echo "9. 卸载Docker环境"
      echo -e "${pink}========================${white}"
      echo "0. 返回主菜单"
      echo -e "${pink}========================${white}"
      read -p "请输入你的选择: " sub_choice

      case $sub_choice in
          1)
            clear
            docker_install

              ;;
          2)
            clear
            docker_status

              ;;
          3)
            clear
            docker_clean
              ;;
          4)
            clear
            docker_mirrors
              ;;

          5)
            clear
            docker_ipv6_on
              ;;

          6)
            clear
            docker_ipv6_off
              ;;

          9)
            clear
            docker_uninstall
              ;;
          8)
              clear
              bash <(curl -sSL https://linuxmirrors.cn/docker.sh)
              ;;

          9)
              clear
              install nano
              mkdir -p /etc/docker && nano /etc/docker/daemon.json
              restart docker
              ;;

          0)
              yuju_menu
              ;;
          *)
              echo "无效的输入!"
              ;;
      esac
      break_end


    done


}

#endregion

#region //9. 一键优化
onekey_optimization(){
    root_test
    echo "一键优化"
    echo -e "${pink}============================${white}"
    echo "优化内容如下："
    echo "- 更新系统软件包"
    echo "- 系统清理"
    echo -e "- OpenSSH升级"
    echo -e "- 设置时区到${huang}上海${bai}"
    echo -e "- 设置虚拟内存${huang}物理内存的2倍${bai}"
    echo -e "- 设置SSH端口号为${huang}55520${bai}"
    echo -e "- 安装fail2ban"
    echo -e "- 修改为密钥登录"
    echo -e "- 安装${huang}所有常用工具${bai}"
    echo -e "- 系统配置参数调优"
    echo -e "- 开启${huang}BBRx${bai}加速"
    echo -e "${pink}============================${white}"
    read -p "确定一键优化吗？(Y/N): " choice
    
    case "$choice" in
      [Yy])
        clear
        echo -e "${pink}============================${white}"
        system_update
        echo -e "[${lv}OK${bai}] 1/11. 更新系统到最新"
    
        echo -e "${pink}============================${white}"
        system_clean
        echo -e "[${lv}OK${bai}] 2/11. 清理系统垃圾文件"
    
        echo -e "${pink}============================${white}"
        system_openssh
        echo -e "[${lv}OK${bai}] 3/11. OpenSSH升级"
    
        echo -e "${pink}============================${white}"
        system_time
        echo -e "[${lv}OK${bai}] 4/11. 设置时区到${huang}上海${bai}"
    
        echo -e "${pink}============================${white}"
        # 确保脚本以root权限运行
        if [[ $EUID -ne 0 ]]; then
            echo -e "\e[31mError: This script must be run as root!\e[0m"
            exit 1
        fi
        
        # 检测是否为OpenVZ虚拟化环境
        if [[ -d "/proc/vz" ]]; then
            echo -e "\e[31mYour VPS is based on OpenVZ, not supported!\e[0m"
            exit 1
        fi
        
        # 删除现有的swap文件（如果存在）
        grep -q "swapfile" /etc/fstab
        if [ $? -eq 0 ]; then
            echo -e "\e[32m发现现有的swapfile，正在删除...\e[0m"
            sed -i '/swapfile/d' /etc/fstab
            swapoff /swapfile
            rm -f /swapfile
            echo -e "\e[32m现有的swapfile已删除。\e[0m"
        else
            echo -e "\e[33m未发现现有的swapfile。\e[0m"
        fi
        
        # 获取物理内存大小 (单位：MB)
        mem_size=$(free -m | awk '/^Mem:/{print $2}')
        
        # 计算需要的swap大小为物理内存的2倍
        swapsize=$((mem_size * 2))
        
        # 创建新的swap文件
        echo -e "\e[32m将创建大小为物理内存2倍（${swapsize}MB）的swap文件。\e[0m"
        fallocate -l ${swapsize}M /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap defaults 0 0' >> /etc/fstab
        
        # 显示swap信息
        echo -e "\e[32mswap创建成功，当前swap信息如下：\e[0m"
        cat /proc/swaps
        cat /proc/meminfo | grep Swap
        echo -e "[${lv}OK${bai}] 5/11. 设置虚拟内存${huang}物理内存的2倍${bai}"
    
        echo -e "${pink}============================${white}"
        # 修改sshd配置文件中的端口号
        sudo sed -i "s/^#\?Port .*/Port 55520/g" /etc/ssh/sshd_config
        
        # 重启SSH服务以应用更改
        sudo systemctl restart sshd
        
        # 输出成功信息
        echo "SSH端口已修改为 55520"
        echo -e "[${lv}OK${bai}] 6/11. 设置SSH端口号为${huang}55520${bai}"
        echo -e "${pink}============================${white}"
    
        echo -e "${pink}============================${white}"
        system_fail2ban
        echo -e "[${lv}OK${bai}] 7/11. 安装fail2ban"
    
        echo -e "${pink}============================${white}"
        system_keygen
        echo -e "[${lv}OK${bai}] 8/11. 修改为密钥登录"
    
        echo -e "${pink}============================${white}"
        download_all
        docker_install
        echo -e "[${lv}OK${bai}] 9/11. 安装${huang}Docker等常用工具${bai}"
    
        echo -e "${pink}============================${white}"
        system_optimization
        echo -e "[${lv}OK${bai}] 10/11. 系统配置参数调优"
    
        echo -e "${pink}============================${white}"
        system_bbr
        echo -e "[${lv}OK${bai}] 11/11. bbrx已安装，重启生效"
    
        clear
        echo -e "${lv}一键优化已完成，BBRx在重启后生效${bai}"
        echo "您现在的SSH端口为55520，您的SSH Key如下，请牢记："
        cat ~/.ssh/id_rsa

        ;;
      [Nn])
        echo "已取消"
        ;;
      *)
        echo "无效的选择，请输入 Y 或 N。"
        ;;
    esac
}
#endregion

#region //脚本主界面
yuju_menu() {
while true; do
clear

echo -e "${pink}\   /  |    |     |   |    | "
echo " \ /   |    |     |   |    | "
echo "  |    |    |     |   |    | "
echo "  |    |____|  ___|   |____| "
echo "                                "
echo -e "${pink}yuju工具箱 【v$version】 LinuxDo站首发！"
echo -e "【该工具箱仅适配Ubuntu/Debian系统】"
echo -e "----输入${red}yuju${pink}可再次快速启动此脚本----${white}"
echo -e "${pink}============================${white}"
echo "1. 系统相关->"
echo "2. 测试脚本->"
echo "3. 常用工具下载->"
echo "4. Docker管理->"
echo -e "${pink}============================${white}"
echo "9. 一键优化"
echo -e "${pink}============================${white}"
echo "555. 卸载脚本"
echo -e "${pink}============================${white}"
echo "0. 退出脚本"
echo -e "${pink}============================${white}"
read -p "请输入你的选择: " choice

case $choice in
  1)
    clear
    system_related
    ;;

  2)
    clear
    test_script
    ;;

  3)
    clear
    useful_tools
    ;;

  4)
    clear
    docker_manage
    ;;

  9)
    clear
    onekey_optimization
    ;;

  555)
    clear
    echo "卸载yuju工具箱"
    echo -e "${pink}============================${white}"
    echo "将彻底卸载yuju工具箱，不影响已安装的功能"
    read -p "确定继续吗？(Y/N): " confirm
    if [[ "$confirm" == "Y" || "$confirm" == "y" ]]; then
        # 执行删除操作
        clear
        rm -f /usr/local/bin/yuju
        rm ./yuju.sh
        echo "脚本已卸载，祝您生活愉快！"
        exit
    else
        echo "操作已取消。"
    fi
    ;;

  0)
    clear
    exit
    ;;

  *)
    echo -e "无效的输入!"
    ;;
esac
    break_end
done

}


if [ "$#" -eq 0 ]; then
#如果没有参数，运行交互式逻辑
    yuju_menu
else
#如果有参数，执行相应函数
    echo -e "无效参数"
fi
#endregion
