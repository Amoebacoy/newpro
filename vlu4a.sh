clear
#Minacantik
export LANG='en_US.UTF-8'
export LANGUAGE='en_US.UTF-8'
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export LIGHT='\033[0;37m'
export NC='\033[0m'
BIRed='\033[1;91m'
red='\e[1;31m'
bo='\e[1m'
red='\e[1;31m'
green='\e[0;32m'
yell='\e[1;33m'
tyblue='\e[1;36m'
purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
export EROR="[${RED} ERROR ${NC}]"
export INFO="[${YELLOW} INFO ${NC}]"
export OKEY="[${GREEN} OKEY ${NC}]"
export PENDING="[${YELLOW} PENDING ${NC}]"
export SEND="[${YELLOW} SEND ${NC}]"
export RECEIVE="[${YELLOW} RECEIVE ${NC}]"
export BOLD="\e[1m"
export WARNING="${RED}\e[5m"
export UNDERLINE="\e[4m"
if [ "${EUID}" -ne 0 ]; then
echo -e "${EROR} Please Run This Script As Root User !"
exit 1
fi
export IP=$( curl -s https://ipinfo.io/ip/ )
export NETWORK_IFACE="$(ip route show to default | awk '{print $5}')"
if [[ -r /etc/xray/domain ]]; then
clear
echo -e "${INFO} Having Script Detected !"
echo -e "${INFO} If You Replacing Script, All Client Data On This VPS Will Be Cleanup !"
read -p "Are You Sure Wanna Replace Script ? (Y/N) " lanjutkan
if [[ $lanjutkan == "Y" ]]; then
clear
echo -e "${INFO} Starting Replacing Script !"
elif [[ $lanjutkan == "y" ]]; then
clear
echo -e "${INFO} Starting Replacing Script !"
rm -rf /var/lib/scrz-prem
elif [[ $lanjutkan == "N" ]]; then
echo -e "${INFO} Action Canceled !"
exit 1
elif [[ $lanjutkan == "n" ]]; then
echo -e "${INFO} Action Canceled !"
exit 1
else
echo -e "${EROR} Your Input Is Wrong !"
exit 1
fi
clear
fi
echo -e "${GREEN}Starting Installation............${NC}"
cd /root/
apt update -y
apt-get --reinstall --fix-missing install -y sudo dpkg psmisc socat jq ruby wondershaper python2 tmux nmap bzip2 gzip coreutils wget screen rsyslog iftop htop net-tools zip unzip wget vim net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential gcc g++ automake make autoconf perl m4 dos2unix dropbear libreadline-dev zlib1g-dev libssl-dev dirmngr libxml-parser-perl neofetch git lsof iptables iptables-persistent
apt-get --reinstall --fix-missing install -y libreadline-dev zlib1g-dev libssl-dev python2 screen curl jq bzip2 gzip coreutils rsyslog iftop htop zip unzip net-tools sed gnupg gnupg1 bc sudo apt-transport-https build-essential dirmngr libxml-parser-perl neofetch screenfetch git lsof openssl easy-rsa fail2ban tmux vnstat dropbear libsqlite3-dev socat cron bash-completion ntpdate xz-utils sudo apt-transport-https gnupg2 gnupg1 dnsutils lsb-release chrony
gem install lolcat
sleep 1
echo -e "[ ${green}INFO$NC ] Disable ipv6"
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 >/dev/null 2>&1
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local >/dev/null 2>&1
apt update -y
apt upgrade -y
apt dist-upgrade -y
clear
clear && clear && clear
clear;clear;clear
read -p "Input Your Domain : " domain
if [[ $domain == "" ]]; then
clear
echo -e "${EROR} No Input Detected !"
exit 1
fi
apt purge nginx nginx-common nginx-core -y
mkdir -p /usr/bin
rm -fr /usr/local/bin/xray
rm -fr /usr/local/bin/stunnel
rm -fr /usr/local/bin/stunnel5
rm -fr /etc/nginx
rm -fr /var/lib/scrz-prem/
rm -fr /usr/bin/xray
rm -fr /etc/xray
rm -fr /usr/local/etc/xray
mkdir -p /etc/nginx
mkdir -p /var/lib/scrz-prem/
mkdir -p /usr/bin/xray
mkdir -p /etc/xray
mkdir -p /usr/local/etc/xray
echo "$domain" > /etc/domain.txt
echo "IP=$domain" > /var/lib/scrz-prem/ipvps.conf
echo "$domain" > /root/domain
domain=$(cat /root/domain)
cp -r /root/domain /etc/xray/domain
clear
echo -e "[ ${GREEN}INFO${NC} ] Starting renew cert... "
sleep 2
echo -e "${OKEY} Starting Generating Certificate"
rm -fr /root/.acme.sh
mkdir -p /root/.acme.sh
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
echo -e "${OKEY} Your Domain : $domain"
sleep 2
#install jembot
echo -e "$white\033[0;34m+-----------------------------------------+${NC}"
echo -e " \E[41;1;39m           ? Install Jembot ?            \E[0m$NC"
echo -e "$white\033[0;34m+-----------------------------------------+${NC}"
sleep 1 
wget -q https://raw.githubusercontent.com/Amoebacoy/private/main/janggut.sh && chmod +x janggut.sh && ./janggut.sh
#install ssh-vpn
echo -e "$white\033[0;34m+-----------------------------------------+${NC}"
echo -e " \E[41;1;39m          ? Install SSH / WS ?           \E[0m$NC"
echo -e "$white\033[0;34m+-----------------------------------------+${NC}"
sleep 1
wget -q https://raw.githubusercontent.com/Amoebacoy/newpro/main/ssh-vpn.sh && chmod +x ssh-vpn.sh && ./ssh-vpn.sh
#install ins-xray
echo -e "$white\033[0;34m+-----------------------------------------+${NC}"
echo -e " \E[41;1;39m            ? Install Xray ?             \E[0m$NC"
echo -e "$white\033[0;34m+-----------------------------------------+${NC}"
sleep 1 
wget -q https://raw.githubusercontent.com/Amoebacoy/newpro/main/ins-xray.sh && chmod +x ins-xray.sh && ./ins-xray.sh
IP=$(echo $SSH_CLIENT | awk '{print $1}')
TMPFILE='/tmp/ipinfo-$DATE_EXEC.txt'
curl http://ipinfo.io/$IP -s -o $TMPFILE
ORG=$(cat $TMPFILE | jq '.org' | sed 's/"//g')
domain=$(cat /etc/xray/domain)
LocalVersion=$(cat /root/versi)
IPVPS=$(curl -s ipinfo.io/ip )
ISPVPS=$( curl -s ipinfo.io/org )
token=5922026926:AAE5t2CXnOOT57zWdua2wfHKKG9URGEQdP0
chatid=1106186898
ttoday="$(vnstat | grep today | awk '{print $8" "substr ($9, 1, 3)}' | head -1)"
tmon="$(vnstat -m | grep `date +%G-%m` | awk '{print $8" "substr ($9, 1 ,3)}' | head -1)"
DATE_EXEC="$(date "+%d %b %Y %H:%M")"
CITY=$(cat $TMPFILE | jq '.city' | sed 's/"//g')
REGION=$(cat $TMPFILE | jq '.region' | sed 's/"//g')
COUNTRY=$(cat $TMPFILE | jq '.country' | sed 's/"//g')
curl -s -X POST "https://api.telegram.org/bot$token/sendMessage" -d chat_id="$chatid" -d text="$IPVPS domain $domain telah install XrayCol pada $DATE_EXEC di $CITY, $REGION via $ORG" > /dev/null 2>&1
clear
# // Download Data
echo -e "${GREEN}Download Data${NC}"
wget -q -O /usr/bin/add-ws "https://raw.githubusercontent.com/Amoebacoy/newpro/main/add-ws.sh"
wget -q -O /usr/bin/add-ssws "https://raw.githubusercontent.com/Amoebacoy/newpro/main/add-ssws.sh"
#wget -q -O /usr/bin/add-socks "https://raw.githubusercontent.com/Amoebacoy/newpro/main/add-socks.sh"
wget -q -O /usr/bin/add-vless "https://raw.githubusercontent.com/Amoebacoy/newpro/main/add-vless.sh"
wget -q -O /usr/bin/add-tr "https://raw.githubusercontent.com/Amoebacoy/newpro/main/add-tr.sh"
#wget -q -O /usr/bin/add-trgo "https://raw.githubusercontent.com/Amoebacoy/newpro/main/add-trgo.sh"
wget -q -O /usr/bin/autoreboot "https://raw.githubusercontent.com/Amoebacoy/newpro/main/autoreboot.sh"
wget -q -O /usr/bin/restart "https://raw.githubusercontent.com/Amoebacoy/newpro/main/restart.sh"
wget -q -O /usr/bin/tendang "https://raw.githubusercontent.com/Amoebacoy/newpro/main/tendang.sh"
wget -q -O /usr/bin/clearlog "https://raw.githubusercontent.com/Amoebacoy/newpro/main/clearlog.sh"
wget -q -O /usr/bin/running "https://raw.githubusercontent.com/Amoebacoy/newpro/main/running.sh"
wget -q -O /usr/bin/cek-trafik "https://raw.githubusercontent.com/Amoebacoy/newpro/main/cek-trafik.sh"
wget -q -O /usr/bin/cek-speed "https://raw.githubusercontent.com/Amoebacoy/newpro/main/speedtes_cli.py"
wget -q -O /usr/bin/cek-bandwidth "https://raw.githubusercontent.com/Amoebacoy/newpro/main/cek-bandwidth.sh"
#wget -q -O /usr/bin/cek-ram "https://raw.githubusercontent.com/Amoebacoy/newpro/main/ram.sh"
wget -q -O /usr/bin/limit-speed "https://raw.githubusercontent.com/Amoebacoy/newpro/main/limit-speed.sh"
wget -q -O /usr/bin/menu-vless "https://raw.githubusercontent.com/Amoebacoy/newpro/main/menu-vless.sh"
wget -q -O /usr/bin/menu-vmess "https://raw.githubusercontent.com/Amoebacoy/newpro/main/menu-vmess.sh"
#wget -q -O /usr/bin/menu-socks "https://raw.githubusercontent.com/Amoebacoy/newpro/main/menu-socks.sh"
wget -q -O /usr/bin/menu-ss "https://raw.githubusercontent.com/Amoebacoy/newpro/main/menu-ss.sh"
wget -q -O /usr/bin/menu-trojan "https://raw.githubusercontent.com/Amoebacoy/newpro/main/menu-trojan.sh"
#wget -q -O /usr/bin/menu-trgo "https://raw.githubusercontent.com/Amoebacoy/newpro/main/menu-trgo.sh"
wget -q -O /usr/bin/menu-ssh "https://raw.githubusercontent.com/Amoebacoy/newpro/main/menu-ssh.sh"
#wget -q -O /usr/bin/menu-bckp "https://raw.githubusercontent.com/Amoebacoy/newpro/main/menu-bckp-telegram.sh"
wget -q -O /usr/bin/menu-bckp "https://raw.githubusercontent.com/Amoebacoy/newpro/main/menu-bckp-github.sh"
#wget -q -O /usr/bin/bckp "https://raw.githubusercontent.com/Amoebacoy/newpro/main/bckpbot.sh"
wget -q -O /usr/bin/usernew "https://raw.githubusercontent.com/Amoebacoy/newpro/main/usernew.sh"
wget -q -O /usr/bin/menu "https://raw.githubusercontent.com/Amoebacoy/newpro/main/menu.sh"
wget -q -O /usr/bin/wbm "https://raw.githubusercontent.com/Amoebacoy/newpro/main/webmin.sh"
wget -q -O /usr/bin/xp "https://raw.githubusercontent.com/Amoebacoy/newpro/main/xp.sh"
#wget -q -O /usr/bin/update "https://raw.githubusercontent.com/Amoebacoy/newpro/main/update.sh"
chmod +x /usr/bin/add-ws
chmod +x /usr/bin/add-ssws
#chmod +x /usr/bin/add-socks
chmod +x /usr/bin/add-vless
chmod +x /usr/bin/add-tr
#chmod +x /usr/bin/add-trgo
chmod +x /usr/bin/usernew
chmod +x /usr/bin/autoreboot
chmod +x /usr/bin/restart
chmod +x /usr/bin/tendang
chmod +x /usr/bin/clearlog
chmod +x /usr/bin/running
chmod +x /usr/bin/cek-trafik
chmod +x /usr/bin/cek-speed
chmod +x /usr/bin/cek-bandwidth
#chmod +x /usr/bin/cek-ram
chmod +x /usr/bin/limit-speed
chmod +x /usr/bin/menu-vless
chmod +x /usr/bin/menu-vmess
chmod +x /usr/bin/menu-ss
#chmod +x /usr/bin/menu-socks
chmod +x /usr/bin/menu-trojan
#chmod +x /usr/bin/menu-trgo
chmod +x /usr/bin/menu-ssh
chmod +x /usr/bin/menu-bckp
chmod +x /usr/bin/menu
#chmod +x /usr/bin/bckp
chmod +x /usr/bin/wbm
chmod +x /usr/bin/xp
#chmod +x /usr/bin/update
cat > /etc/cron.d/xp_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/bin/xp
END
cat > /etc/cron.d/cl_otm <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 1 * * * root /usr/bin/clearlog
END
echo "59 * * * * root killall /bin/bash /usr/bin/menu" >> /etc/crontab
cat > /home/re_otm <<-END
7
END
service cron restart >/dev/null 2>&1
service cron reload >/dev/null 2>&1
clear
cat> /root/.profile << END
if [ "$BASH" ]; then
if [ -f ~/.bashrc ]; then
. ~/.bashrc
fi
fi
mesg n || true
clear
menu
END
chmod 644 /root/.profile
if [ -f "/root/log-install.txt" ]; then
rm -fr /root/log-install.txt
fi
if [ -f "/etc/afak.conf" ]; then
rm -fr /etc/afak.conf
fi
if [ ! -f "/etc/log-create-user.log" ]; then
echo "Log All Account " > /etc/log-create-user.log
fi
history -c
aureb=$(cat /home/re_otm)
b=11
if [ $aureb -gt $b ]
then
gg="PM"
else
gg="AM"
fi
cd
echo "1.1" >> /home/.ver
rm -fr /root/limit
curl -sS ifconfig.me > /etc/myipvps
echo " "
echo "=====================-[ Kenn Hiroyuki Premium ]-===================="
echo ""
echo "------------------------------------------------------------"
echo ""
echo ""
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH                 : 22"  | tee -a log-install.txt
echo "   - SSH Websocket           : 80" | tee -a log-install.txt
echo "   - SSH SSL Websocket       : 443" | tee -a log-install.txt
echo "   - Stunnel5                : 447, 777" | tee -a log-install.txt
echo "   - Dropbear                : 109, 143" | tee -a log-install.txt
echo "   - Badvpn                  : 7100-7300" | tee -a log-install.txt
echo "   - Nginx                   : 81" | tee -a log-install.txt
echo "   - XRAY  Vmess TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vmess None TLS    : 80" | tee -a log-install.txt
echo "   - XRAY  Vless TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vless None TLS    : 80" | tee -a log-install.txt
echo "   - Trojan GRPC             : 443" | tee -a log-install.txt
echo "   - Trojan WS               : 443" | tee -a log-install.txt
echo "   - Trojan GO               : 443" | tee -a log-install.txt
#echo "   - Trojan GFW              : 443" | tee -a log-install.txt
echo "   - Sodosok WS/GRPC         : 443" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone                : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban                : [ON]"  | tee -a log-install.txt
echo "   - Dflate                  : [ON]"  | tee -a log-install.txt
echo "   - IPtables                : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot             : [ON]"  | tee -a log-install.txt
echo "   - IPv6                    : [OFF]"  | tee -a log-install.txt
echo "   - Autoreboot Off          : $aureb:00 $gg GMT +7" | tee -a log-install.txt
echo "   - Autobackup Data" | tee -a log-install.txt
echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Fully automatic script" | tee -a log-install.txt
echo "   - VPS settings" | tee -a log-install.txt
echo "   - Admin Control" | tee -a log-install.txt
echo "   - Change port" | tee -a log-install.txt
echo "   - Restore Data" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo ""
echo ""
echo "------------------------------------------------------------"
echo ""
echo "===============-[ Script Created By Kenn Hiroyuki ]-==============="
echo -e ""
echo ""
echo "" | tee -a log-install.txt
rm -fr /root/weleh.sh 
rm -fr /root/jembot.sh 
rm -fr /root/ssh-vpn.sh
rm -fr /root/ins-xray.sh
rm -fr /root/setup.sh
rm -fr /root/domain
history -c
secs_to_human "$(($(date +%s) - ${start}))"
echo -e "${YB}[ WARNING ] reboot now ? (Y/N)${NC} "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
exit 0
else
reboot
fi