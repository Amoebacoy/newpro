#!/bin/bash
# initializing var
#export DEBIAN_FRONTEND=noninteractive
#OS=`uname -m`;
#MYIP=$(wget -qO- ipv4.icanhazip.com);
#MYIP2="s/xxxxxxxxx/$MYIP/g";
#ANU=$(ip -o $ANU -4 route show to default | awk '{print $5}');

#detail nama perusahaan
#country=ID
#state=Indonesia
#locality=Indonesia
#organization=PandaEver
#organizationalunit=PandaEver
#commonname=PandaEver
#email=JustPandaEvers@gmail.com

# simple password minimal
#wget -O /etc/pam.d/common-password "https://raw.githubusercontent.com/JustPandaEver/ssh/master/common-password-deb9"
#chmod +x /etc/pam.d/common-password

# go to root
cd
# Installing Service ws ws-ovpn
#wget -O /usr/local/bin/ws-ovpn "https://raw.githubusercontent.com/syapik96/aws/main/lain2/ovpn.py"
#chmod +x /usr/local/bin/ws-ovpn

# Create system Service ws ws-ovpn
#cat > /etc/systemd/system/ws-ovpn.service <<END
#[Unit]
#Description=OpenVpn Over Websocket Python
#Documentation=https://github.com/syapik96/aws
#After=network.target nss-lookup.target

#[Service]
#Type=simple
#User=root
#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
#AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
#NoNewPrivileges=true
#ExecStart=/usr/bin/python -O /usr/local/bin/ws-ovpn 2099
#Restart=on-failure

#[Install]
#WantedBy=multi-user.target
#END

# Installing Service ws-dropbear
wget -O /usr/local/bin/ws-dropbear "https://raw.githubusercontent.com/syapik96/aws/main/websocket-python/ws-dropbear.py"
chmod +x /usr/local/bin/ws-dropbear

# Create system Service ws-dropbear
cat > /etc/systemd/system/ws-dropbear.service <<END
[Unit]
Description=Dropbear Over Websocket Python
Documentation=https://github.com/syapik96/aws
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python -O /usr/local/bin/ws-dropbear
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

# Installing Service ws-stunnel
wget -O /usr/local/bin/ws-stunnel "https://raw.githubusercontent.com/syapik96/aws/main/websocket-python/ws-stunnel.py"
chmod +x /usr/local/bin/ws-stunnel

# Create system Service ws-stunnel
cat > /etc/systemd/system/ws-stunnel.service <<END
[Unit]
Description=Ssl/tls Proxy Over Websocket Python
Documentation=https://github.com/syapik96/aws
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python -O /usr/local/bin/ws-stunnel
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

# Installing Service ws-openssh
wget -O /usr/local/bin/ws-openssh "https://raw.githubusercontent.com/syapik96/aws/main/lain2/edu-openssh.py"
chmod +x /usr/local/bin/ws-openssh

# Create system Service ws-openssh
cat > /etc/systemd/system/ws-openssh.service <<END
[Unit]
Description=OpenSSH Over Websocket Python
Documentation=https://github.com/syapik96/aws
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python -O /usr/local/bin/ws-openssh
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

# ENABLE & START/RESTART SERVICE
systemctl daemon-reload
#systemctl enable ws-ovpn
#systemctl restart ws-ovpn
systemctl enable ws-dropbear
systemctl restart ws-dropbear
systemctl enable ws-stunnel
systemctl restart ws-stunnel
systemctl enable ws-openssh
systemctl restart ws-openssh

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#update
apt-get update -y

# install wget and curl
apt-get -y install wget curl

# remove unnecessary files
apt -y autoremove
apt -y autoclean
apt -y clean
apt-get -y remove --purge unscd

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# install webserver
apt-get -y install nginx

# install neofetch
apt-get update -y
apt-get -y install gcc
apt-get -y install make
apt-get -y install cmake
apt-get -y install git
apt-get -y install screen
apt-get -y install unzip
apt-get -y install curl
git clone https://github.com/dylanaraps/neofetch
cd neofetch
make install
make PREFIX=/usr/local install
make PREFIX=/boot/home/config/non-packaged install
make -i install
apt-get -y install neofetch
cd
echo "clear" >> .profile
echo "neofetch" >> .profile

# install webserver
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/JustPandaEver/ssh/master/nginx.conf"
mkdir -p /home/vps/public_html
echo "<pre>Setup by PandaEver</pre>" > /home/vps/public_html/index.html
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/JustPandaEver/ssh/master/vps.conf"
/etc/init.d/nginx restart

# install badvpn
cd
apt-get install cmake make gcc -y
cd
wget https://raw.githubusercontent.com/janda09/private/master/badvpn-1.999.128.tar.bz2
tar xf badvpn-1.999.128.tar.bz2
mkdir badvpn-build
cd badvpn-build
cmake ~/badvpn-1.999.128 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
make install
echo 'badvpn-udpgw --listen-addr 127.0.0.1:Badvpn_Port1 > /dev/nul &' >> /etc/rc.local
badvpn-udpgw --listen-addr 127.0.0.1:Badvpn_Port1 > /dev/nul &
echo 'badvpn-udpgw --listen-addr 127.0.0.1:Badvpn_Port2 > /dev/nul &' >> /etc/rc.local
badvpn-udpgw --listen-addr 127.0.0.1:Badvpn_Port2 > /dev/nul &
# setting port ssh
sed -i 's/Port 22/Port 22/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin no/PermitRootLogin yes/g' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin no/PermitRootLogin yes/g' /etc/ssh/sshd_config
sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
echo "DROPBEAR_PORT=80" >> /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 110 -p 109 -p 456"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart

# install squid
cd
apt-get -y install squid3
wget -O /etc/squid/squid.conf "https://raw.githubusercontent.com/JustPandaEver/ssh/master/squid3.conf"
sudo sed -i $MYIP2 /etc/squid/squid.conf

# setting vnstat
apt-get -y install vnstat
vnstat -u -i $ANU
service vnstat restart 


# install stunnel
cd /root/
wget -q "https://raw.githubusercontent.com/wunuit/1/main/stunnel5.zip"
unzip stunnel5.zip
cd /root/stunnel
chmod +x configure
./configure
make
make install
cd /root
rm -r -f stunnel
rm -f stunnel5.zip
rm -fr /etc/stunnel5
mkdir -p /etc/stunnel5
chmod 644 /etc/stunnel5
# Download Config Stunnel5
cat > /etc/stunnel5/stunnel5.conf <<-END
cert = /etc/xray/xray.crt
key = /etc/xray/xray.key
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 447
connect = 127.0.0.1:109

[openssh]
accept = 777
connect = 127.0.0.1:22

[openvpn]
accept = 442
connect = 127.0.0.1:1194

END

# make a certificate
#openssl genrsa -out key.pem 2048
#openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
#-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
#cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# konfigurasi stunnel
#sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
#/etc/init.d/stunnel4 restart

# Service Stunnel5 systemctl restart stunnel5
rm -fr /etc/systemd/system/stunnel5.service
cat > /etc/systemd/system/stunnel5.service << END
[Unit]
Description=Stunnel5 Service
Documentation=https://stunnel.org
Documentation=https://nekopoi.care
After=syslog.target network-online.target

[Service]
ExecStart=/usr/local/bin/stunnel5 /etc/stunnel5/stunnel5.conf
Type=forking

[Install]
WantedBy=multi-user.target
END

# Service Stunnel5 /etc/init.d/stunnel5
rm -fr /etc/init.d/stunnel5
wget -q -O /etc/init.d/stunnel5 "https://raw.githubusercontent.com/wunuit/1/main/stunnel5.init"

# Ubah Izin Akses
#chmod 600 /etc/stunnel5/stunnel5.pem
chmod +x /etc/init.d/stunnel5
cp -r /usr/local/bin/stunnel /usr/local/bin/stunnel5
#mv /usr/local/bin/stunnel /usr/local/bin/stunnel5

# Remove File
rm -r -f /usr/local/share/doc/stunnel/
rm -r -f /usr/local/etc/stunnel/
rm -f /usr/local/bin/stunnel
rm -f /usr/local/bin/stunnel3
rm -f /usr/local/bin/stunnel4
#rm -f /usr/local/bin/stunnel5

# Restart Stunnel5
systemctl daemon-reload >/dev/null 2>&1
systemctl enable stunnel5 >/dev/null 2>&1
systemctl start stunnel5 >/dev/null 2>&1
systemctl restart stunnel5 >/dev/null 2>&1

# Install bbr
sleep 1
echo -e "[ ${GREEN}INFO$NC ] Install bbr"
#Optimasi Speed Mod By Akhir Zaman
Add_To_New_Line(){
	if [ "$(tail -n1 $1 | wc -l)" == "0"  ];then
		echo "" >> "$1"
	fi
	echo "$2" >> "$1"
}

Check_And_Add_Line(){
	if [ -z "$(cat "$1" | grep "$2")" ];then
		Add_To_New_Line "$1" "$2"
	fi
}

Install_BBR(){
echo "#############################################"
echo "Install TCP_BBR..."
if [ -n "$(lsmod | grep bbr)" ];then
echo "TCP_BBR sudah diinstall."
echo "#############################################"
return 1
fi
echo "Mulai menginstall TCP_BBR..."
modprobe tcp_bbr
Add_To_New_Line "/etc/modules-load.d/modules.conf" "tcp_bbr"
Add_To_New_Line "/etc/sysctl.conf" "net.core.default_qdisc = fq"
Add_To_New_Line "/etc/sysctl.conf" "net.ipv4.tcp_congestion_control = bbr"
sysctl -p
if [ -n "$(sysctl net.ipv4.tcp_available_congestion_control | grep bbr)" ] && [ -n "$(sysctl net.ipv4.tcp_congestion_control | grep bbr)" ] && [ -n "$(lsmod | grep "tcp_bbr")" ];then
	echo "TCP_BBR Install Success."
else
	echo "Gagal menginstall TCP_BBR."
fi
echo "#############################################"
}

Optimize_Parameters(){
echo "#############################################"
echo "Optimasi Parameters..."
Check_And_Add_Line "/etc/security/limits.conf" "* soft nofile 51200"
Check_And_Add_Line "/etc/security/limits.conf" "* hard nofile 51200"
Check_And_Add_Line "/etc/security/limits.conf" "root soft nofile 51200"
Check_And_Add_Line "/etc/security/limits.conf" "root hard nofile 51200"
Check_And_Add_Line "/etc/sysctl.conf" "fs.file-max = 51200"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.rmem_max = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.wmem_max = 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.netdev_max_backlog = 250000"
Check_And_Add_Line "/etc/sysctl.conf" "net.core.somaxconn = 4096"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_syncookies = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_tw_reuse = 1"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_fin_timeout = 30"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_keepalive_time = 1200"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.ip_local_port_range = 10000 65000"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_syn_backlog = 8192"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_max_tw_buckets = 5000"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_fastopen = 3"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_mem = 25600 51200 102400"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_rmem = 4096 87380 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_wmem = 4096 65536 67108864"
Check_And_Add_Line "/etc/sysctl.conf" "net.ipv4.tcp_mtu_probing = 1"
echo "Optimasi Parameters Selesai."
echo "#############################################"
}
Install_BBR
Optimize_Parameters
sleep 1
echo -e "[ ${GREEN}INFO$NC ] Install successfully..."

#OpenVPN
wget https://raw.githubusercontent.com/JustPandaEver/ssh/master/vpn.sh &&  chmod +x vpn.sh && bash vpn.sh

# install fail2ban
cdLEDinstall fail2ban
apt-get -y install fail2ban

# Instal DDOS Flate
rm -fr /usr/local/ddos
mkdir -p /usr/local/ddos >/dev/null 2>&1
#clear
sleep 1
echo -e "[ ${GREEN}INFO$NC ] Install DOS-Deflate"
sleep 1
echo -e "[ ${GREEN}INFO$NC ] Downloading source files..."
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos  >/dev/null 2>&1
sleep 1
echo -e "[ ${GREEN}INFO$NC ] Create cron script every minute...."
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
sleep 1
echo -e "[ ${GREEN}INFO$NC ] Install successfully..."
sleep 1
echo -e "[ ${GREEN}INFO$NC ] Config file at /usr/local/ddos/ddos.conf"

# xml parser
cd
apt-get install -y libxml-parser-perl

# Banner /etc/issue.net
rm -fr /etc/issue.net
rm -fr /etc/issue.net.save
sleep 1
echo -e "[ ${GREEN}INFO$NC ] Settings banner"
wget -q -O /etc/issue.net "https://raw.githubusercontent.com/wunuit/1/main/issue.net"
chmod +x /etc/issue.net
echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear

# Blokir Torrent
echo -e "[ ${GREEN}INFO$NC ] Set iptables"
sleep 1
sudo iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
sudo iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
sudo iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
sudo iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
sudo iptables-save > /etc/iptables.up.rules
sudo iptables-restore -t < /etc/iptables.up.rules
sudo netfilter-persistent save >/dev/null 2>&1
sudo netfilter-persistent reload >/dev/null 2>&1

# remove unnecessary files
sleep 1
echo -e "[ ${GREEN}INFO$NC ] Clearing trash"
apt autoclean -y >/dev/null 2>&1

if dpkg -s unscd >/dev/null 2>&1; then
apt -y remove --purge unscd >/dev/null 2>&1
fi

# apt-get -y --purge remove samba* >/dev/null 2>&1
# apt-get -y --purge remove apache2* >/dev/null 2>&1
# apt-get -y --purge remove bind9* >/dev/null 2>&1
# apt-get -y remove sendmail* >/dev/null 2>&1
# apt autoremove -y >/dev/null 2>&1
# finishing
cd
echo -e "[ ${GREEN}ok${NC} ] Restarting openvpn"
/etc/init.d/cron restart >/dev/null 2>&1
sleep 1
echo -e "[ ${GREEN}ok${NC} ] Restarting cron"
/etc/init.d/ssh restart >/dev/null 2>&1
sleep 1
echo -e "[ ${GREEN}ok${NC} ] Restarting ssh"
/etc/init.d/dropbear restart >/dev/null 2>&1
sleep 1
echo -e "[ ${GREEN}ok${NC} ] Restarting dropbear"
/etc/init.d/fail2ban restart >/dev/null 2>&1
sleep 1
echo -e "[ ${GREEN}ok${NC} ] Restarting fail2ban"
/etc/init.d/stunnel5 restart >/dev/null 2>&1
sleep 1
echo -e "[ ${GREEN}ok${NC} ] Restarting stunnel5"
/etc/init.d/vnstat restart >/dev/null 2>&1
sleep 1
echo -e "[ ${GREEN}ok${NC} ] Restarting squid "
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500 >/dev/null 2>&1
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500 >/dev/null 2>&1
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500 >/dev/null 2>&1
history -c
echo "unset HISTFILE" >> /etc/profile

cd
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
sleep 1
yellow "SSH & OVPN install successfully"
sleep 5
clear
rm -fr /root/key.pem >/dev/null 2>&1
rm -fr /root/cert.pem >/dev/null 2>&1
rm -fr /root/ssh-vpn.sh >/dev/null 2>&1
rm -fr /root/rampak.sh >/dev/null 2>&1

# finihsing
clear
neofetch
netstat -ntlp
