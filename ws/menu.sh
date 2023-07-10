#!/bin/bash
# Menu For Script
# Edition : Stable Edition V1.0
# Auther  : 
# (C) Copyright 2021-2022
# =========================================
BIBlack='\033[1;90m'      # Black
BIRed='\033[1;91m'        # Red
BIGREEN='\033[1;92m'      # GREEN
BIYellow='\033[1;93m'     # Yellow
BIBlue='\033[1;94m'       # Blue
BIPurple='\033[1;95m'     # Purple
BICdyan='\033[1;96m'       # Cyan
BIWhite='\033[1;97m'      # White
UWhite='\033[4;37m'       # White
On_IPurple='\033[0;105m'  #
On_IRed='\033[0;101m'
IBlack='\033[0;90m'       # Black
IRed='\033[0;91m'         # Red
IGREEN='\033[0;92m'       # GREEN
IYellow='\033[0;93m'      # Yellow
IBlue='\033[0;94m'        # Blue
IPurple='\033[0;95m'      # Purple
ICyan='\033[0;96m'        # Cyan
IWhite='\033[0;97m'       # White
NC='\e[0m'

# // Export Color & Information
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export LIGHT='\033[0;37m'
export NC='\033[0m'

# // Export Banner Status Information
export EROR="[${RED} EROR ${NC}]"
export INFO="[${YELLOW} INFO ${NC}]"
export OKEY="[${GREEN} OKEY ${NC}]"
export PENDING="[${YELLOW} PENDING ${NC}]"
export SEND="[${YELLOW} SEND ${NC}]"
export RECEIVE="[${YELLOW} RECEIVE ${NC}]"

# // Export Align
export BOLD="\e[1m"
export WARNING="${RED}\e[5m"
export UNDERLINE="\e[4m"

# // Exporting URL Host
export Server_URL="raw.githubusercontent.com/wunuit/test/main"
export Server1_URL="raw.githubusercontent.com/wunuit/limit/main"
export Server_Port="443"
export Server_IP="underfined"
export Script_Mode="Stable"
export Auther=".geovpn"

# // Root Checking
if [ "${EUID}" -ne 0 ]; then
		echo -e "${EROR} Please Run This Script As Root User !"
		exit 1
fi

# // Exporting IP Address
export IP=$( curl -s https://ipinfo.io/ip/ )

# // Clear
clear
clear && clear && clear
clear;clear;clear
cek=$(service ssh status | grep active | cut -d ' ' -f5)
if [ "$cek" = "active" ]; then
stat=-f5
else
stat=-f7
fi
ssh=$(service ssh status | grep active | cut -d ' ' $stat)
if [ "$ssh" = "active" ]; then
ressh="${GREEN}ON${NC}"
else
ressh="${red}OFF${NC}"
fi
sshstunel=$(service stunnel5 status | grep active | cut -d ' ' $stat)
if [ "$sshstunel" = "active" ]; then
resst="${GREEN}ON${NC}"
else
resst="${red}OFF${NC}"
fi
sshws=$(service ws-stunnel status | grep active | cut -d ' ' $stat)
if [ "$sshws" = "active" ]; then
ressshws="${GREEN}ON${NC}"
else
ressshws="${red}OFF${NC}"
fi
ngx=$(service nginx status | grep active | cut -d ' ' $stat)
if [ "$ngx" = "active" ]; then
resngx="${GREEN}ON${NC}"
else
resngx="${red}OFF${NC}"
fi
dbr=$(service dropbear status | grep active | cut -d ' ' $stat)
if [ "$dbr" = "active" ]; then
resdbr="${GREEN}ON${NC}"
else
resdbr="${red}OFF${NC}"
fi
v2r=$(service xray status | grep active | cut -d ' ' $stat)
if [ "$v2r" = "active" ]; then
resv2r="${GREEN}ON${NC}"
else
resv2r="${red}OFF${NC}"
fi
function addhost(){
clear
echo -e "\033[0;34m----------------------------------\033[0m"
echo ""
read -rp "Domain/Host: " -e host
echo ""
if [ -z $host ]; then
echo "????"
echo -e "\033[0;34m----------------------------------\033[0m"
read -n 1 -s -r -p "Press any key to back on menu"
setting-menu
else
rm -fr /etc/xray/domain
echo "IP=$host" > /var/lib/scrz-prem/ipvps.conf
echo $host > /etc/xray/domain
echo -e "\033[0;34m----------------------------------\033[0m"
echo "Dont forget to renew gen-ssl"
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
fi
}
function genssl(){
clear
systemctl stop nginx
systemctl stop xray
domain=$(cat /var/lib/scrz-prem/ipvps.conf | cut -d'=' -f2)
Cek=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
if [[ ! -z "$Cek" ]]; then
sleep 1
echo -e "[ ${red}WARNING${NC} ] Detected port 80 used by $Cek " 
systemctl stop $Cek
sleep 2
echo -e "[ ${GREEN}INFO${NC} ] Processing to stop $Cek " 
sleep 1
fi
echo -e "[ ${GREEN}INFO${NC} ] Starting renew gen-ssl... " 
sleep 2
/root/.acme.sh/acme.sh --upgrade
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
echo -e "[ ${GREEN}INFO${NC} ] Renew gen-ssl done... " 
sleep 2
echo -e "[ ${GREEN}INFO${NC} ] Starting service $Cek " 
sleep 2
echo $domain > /etc/xray/domain
systemctl start nginx
systemctl start xray
echo -e "[ ${GREEN}INFO${NC} ] All finished... " 
sleep 0.5
echo ""
read -n 1 -s -r -p "Press any key to back on menu"
menu
}
export sem=$( curl -s https://raw.githubusercontent.com/wunuit/test/main/versions)
export pak=$( cat /home/.ver)
IPVPS=$(curl -s ipinfo.io/ip )
ISPVPS=$( curl -s ipinfo.io/org )
export Server_URL="raw.githubusercontent.com/wunuit/test/main"
License_Key=$(cat /etc/${Auther}/license.key)
export Nama_Issued_License=$( curl -s https://${Server_URL}/validated-registered-license-key.txt | grep -w $License_Key | cut -d ' ' -f 7-100 | tr -d '\r' | tr -d '\r\n')
clear
echo -e "\033[0;34m┌─────────────────────────────────────────────────────┐${NC}"
echo -e "\033[0;34m│                  ${BIWhite}${UWhite}Server Informations${NC}"
echo -e "\033[0;34m│"
echo -e "\033[0;34m│  ${BIGREEN}Use Core        :  ${BIPurple}XRAY-CORE${NC}"
echo -e "\033[0;34m│  ${BIGREEN}Current Domain  :  ${BIPurple}$(cat /etc/xray/domain)${NC}"
echo -e "\033[0;34m│  ${BIGREEN}IP-VPS          :  ${BIYellow}$IPVPS${NC}"
echo -e "\033[0;34m│  ${BIGREEN}ISP-VPS         :  ${BIYellow}$ISPVPS${NC}"
echo -e "\033[0;34m└─────────────────────────────────────────────────────┘${NC}"
echo -e "\033[0;34m┌─────────────────────────────────────────────────────┐${NC}"
echo -e "\033[0;34m│ $NC${BIWhite} SSH ${NC}: $ressh"" ${BIWhite} NGINX ${NC}: $resngx"" ${BIWhite}  XRAY ${NC}: $resv2r"" ${BIWhite} TROJAN ${NC}: $resv2r\E[0m\033[0;34m      │"
echo -e "\033[0;34m│ $NC${BIWhite}          DROPBEAR ${NC}: $resdbr" "${BIWhite} SSH-WS ${NC}: $ressshws \E[0m\033[0;34m               │"
echo -e "\033[0;34m└─────────────────────────────────────────────────────┘${NC}"
echo -e "\033[0;34m┌─────────────────────────────────────────────────────┐${NC}"
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}01${BIGREEN}] ${NC}SSH & OpenVPN MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}             ${BIGREEN}[${BIWhite}13${BIGREEN}] ${NC}Settings (Pengaturan) ${BIGREEN}${BIYellow}${BIGREEN}${NC}" 
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}02${BIGREEN}] ${NC}XRAY VMESS MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}          ${BIGREEN}[${BIWhite}14${BIGREEN}] ${NC}copyrepo (Salin Repo Script Mantap) ${BIGREEN}${BIYellow}${BIGREEN}${NC}" 
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}03${BIGREEN}] ${NC}XRAY VLESS MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}          ${BIGREEN}[${BIWhite}15${BIGREEN}] ${NC}menuinfo (Untuk Mendapatkan Informasi) ${BIGREEN}${BIYellow}${BIGREEN}${NC}" 
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}04${BIGREEN}] ${NC}XRAY TROJAN MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}         ${BIGREEN}[${BIWhite}16${BIGREEN}] ${NC}Shadowsocks Plugin (Buat Akun) ${BIGREEN}${BIYellow}${BIGREEN}${NC}"
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}05${BIGREEN}] ${NC}SHADOWSOCKS MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}    ${BIGREEN}[${BIWhite}17${BIGREEN}] ${NC}L2TP MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}"
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}06${BIGREEN}] ${NC}XRAY GRPC MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}           ${BIGREEN}[${BIWhite}18${BIGREEN}] ${NC}PPTP MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}"
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}07${BIGREEN}] ${NC}TROJAN GO MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}      ${BIGREEN}[${BIWhite}19${BIGREEN}] ${NC}SSTP MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}"
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}08${BIGREEN}] ${NC}SLOWDNS MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}           ${BIGREEN}[${BIWhite}20${BIGREEN}] ${NC}WIREGUARD MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}" 
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}09${BIGREEN}] ${NC}CEK SEMUA IP PORT ${BIGREEN}${BIYellow}${BIGREEN}${NC}          ${BIGREEN}[${BIWhite}21${BIGREEN}] ${NC}SHADOWSOCKSR MENU ${BIGREEN}${BIYellow}${BIGREEN}${NC}" 
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}10${BIGREEN}] ${NC}CEK SEMUA SERVICE ${BIGREEN}${BIYellow}${BIGREEN}${NC}         ${BIGREEN}[${BIWhite}xx${BIGREEN}] ${NC} Exit (Keluar) ${BIGREEN}${BIYellow}${BIGREEN}${NC}"  
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}11${BIGREEN}] ${NC}UPDATE MENU (Update) ${BIGREEN}${BIYellow}${BIGREEN}${NC}" 
echo -e "\033[0;34m│ $NC${BIGREEN}[${BIWhite}12${BIGREEN}] ${NC}sl-fix (Perbaiki Error SSLH+WS-TLS setelah reboot) ${BIGREEN}${BIYellow}${BIGREEN}${NC}"
echo -e "\033[0;34m└─────────────────────────────────────────────────────┘${NC}"
echo -e "\033[0;34m┌─────────────────────────────────────────────────────┐${NC}"
echo -e "\033[0;34m│ $NC Version      ${NC} : $sem Last Update"
echo -e "\033[0;34m│ $NC User         ${NC} : FABUMI${NC}"
echo -e "\033[0;34m│ $NC Expiry script${NC} : UNLIMITED${NC} Days"
echo -e "\033[0;34m└─────────────────────────────────────────────────────┘${NC}"
echo
read -p " Select menu : " opt
echo -e ""
case $menu in
1)
clear
sshovpnmenu
;;
2)
clear
vmessmenu
;;
3)
clear
vlessmenu
;;
4)
clear
trmenu
;;
5)
clear
ssmenu
;;
6)
clear
grpcmenu
;;
7)
clear
trgomenu
;;
8)
clear
slowdnsmenu
;;
9)
clear
ipsaya
;;
10)
clear
running
;;
11)
clear
updatemenu
;;
12)
clear
sl-fix
;;
13)
clear
setmenu
;;
14)
clear
copyrepo
;;
15)
clear
menuinfo
;;
16)
clear
addss-p
;;
17)
clear
l2tpmenu
;;
18)
clear
pptpmenu
;;
19)
clear
sstpmenu
;;
20)
clear
wgmenu
;;
21)
clear
ssrmenu
;;
*)
clear
menu
;;
esac
0 | 00) clear ; menu ;;
x | xx) exit ;;
*) echo -e "" ; echo "Press any key to back exit" ; sleep 1 ; exit ;;
esac
