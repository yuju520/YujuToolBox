#!/bin/bash
sleep 60s
## Installing BBR
cd $HOME

## This part of the script is modified from https://github.com/KozakaiAya/TCP_BBR
#Install dkms if not installed
if [ ! -x /usr/sbin/dkms ]; then
	apt-get -y install dkms
    if [ ! -x /usr/sbin/dkms ]; then
		echo "Error: dkms is not installed" >&2
		exit 1
	fi
fi
#Ensure there is header file
if [ ! -f /usr/src/linux-headers-$(uname -r)/.config ]; then
	if [[ -z $(apt-cache search linux-headers-$(uname -r)) ]]; then
		echo "Error: linux-headers-$(uname -r) not found" >&2
		exit 1
	fi
	apt-get -y install linux-headers-$(uname -r)
	if [ ! -f /usr/src/linux-headers-$(uname -r)/.config ]; then
		echo "Error: linux-headers-$(uname -r) is not installed" >&2
		exit 1
	fi
fi

#BBRx
wget https://raw.githubusercontent.com/jerry048/Seedbox-Components/main/BBR/BBRx/tcp_bbrx.c
if [ ! -f $HOME/tcp_bbrx.c ]; then
	echo "Error: Download failed! Exiting." >&2
	exit 1
fi
kernel_ver=5.15.0
algo=bbrx

# Compile and install
bbr_file=tcp_$algo
bbr_src=$bbr_file.c
bbr_obj=$bbr_file.o

mkdir -p $HOME/.bbr/src
cd $HOME/.bbr/src

mv $HOME/$bbr_src $HOME/.bbr/src/$bbr_src

# Create Makefile
cat > ./Makefile << EOF
obj-m:=$bbr_obj

default:
	make -C /lib/modules/\$(shell uname -r)/build M=\$(PWD)/src modules

clean:
	-rm modules.order
	-rm Module.symvers
	-rm .[!.]* ..?*
	-rm $bbr_file.mod
	-rm $bbr_file.mod.c
	-rm *.o
	-rm *.cmd
EOF

    # Create dkms.conf
    cd ..
    cat > ./dkms.conf << EOF
MAKE="'make' -C src/"
CLEAN="make -C src/ clean"
BUILT_MODULE_NAME=$bbr_file
BUILT_MODULE_LOCATION=src/
DEST_MODULE_LOCATION=/updates/net/ipv4
PACKAGE_NAME=$algo
PACKAGE_VERSION=$kernel_ver
REMAKE_INITRD=yes
EOF

# Start dkms install
cp -R . /usr/src/$algo-$kernel_ver

dkms add -m $algo -v $kernel_ver
if [ ! $? -eq 0 ]; then
    dkms remove -m $algo/$kernel_ver --all
    exit 1
fi

dkms build -m $algo -v $kernel_ver
if [ ! $? -eq 0 ]; then
    dkms remove -m $algo/$kernel_ver --all
    exit 1
fi

dkms install -m $algo -v $kernel_ver
if [ ! $? -eq 0 ]; then
    dkms remove -m $algo/$kernel_ver --all
    exit 1
fi

# Test loading module
modprobe $bbr_file
if [ ! $? -eq 0 ]; then
    exit 1
fi

# Auto-load kernel module at system startup
echo $bbr_file | sudo tee -a /etc/modules
sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control = $algo" >> /etc/sysctl.conf
sysctl -p > /dev/null

cd $HOME
rm -r $HOME/.bbr

## Clear
systemctl disable bbrinstall.service
rm /etc/systemd/system/bbrinstall.service
rm /root/BBRx.sh
