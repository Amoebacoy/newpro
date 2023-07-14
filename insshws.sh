#!/bin/bash
# Proxy For Connection Over WebSocket-Python
# ====================================
# UPDATED 22-1-28
# Installing Service ws ws-ovpn
wget -O /usr/local/bin/ws-ovpn "https://raw.githubusercontent.com/Amoebacoy/newpro/main/ovpn.py"
chmod +x /usr/local/bin/ws-ovpn
# Create system Service ws ws-ovpn
wget -O /etc/systemd/system/ws-ovpn.service "https://raw.githubusercontent.com/Amoebacoy/newpro/main/ws/ovpn.service"

# Installing Service ws-dropbear
wget -O /usr/local/bin/ws-dropbear "https://raw.githubusercontent.com/Amoebacoy/newpro/main/ws-dropbear.py"
chmod +x /usr/local/bin/ws-dropbear
# Create system Service ws-dropbear
wget -O /etc/systemd/system/ws-dropbear.service "https://raw.githubusercontent.com/Amoebacoy/newpro/main/ws/ws-dropbear.service"

# Installing Service ws-stunnel
wget -O /usr/local/bin/ws-stunnel "https://raw.githubusercontent.com/Amoebacoy/newpro/main/ws-stunnel.py"
chmod +x /usr/local/bin/ws-stunnel
# Create system Service ws-stunnel
wget -O /etc/systemd/system/ws-stunnel.service "https://raw.githubusercontent.com/Amoebacoy/newpro/main/ws/ws-stunnel.service"

# Installing Service ws-openssh
wget -O /usr/local/bin/ws-openssh "https://raw.githubusercontent.com/Amoebacoy/newpro/main/ws-openssh.py"
chmod +x /usr/local/bin/ws-openssh
# Create system Service ws-openssh
wget -O /etc/systemd/system/ws-openssh.service "https://raw.githubusercontent.com/Amoebacoy/newpro/main/ws/ws-openssh.service"
# ENABLE & START/RESTART SERVICE
systemctl daemon-reload
systemctl enable ws-ovpn
systemctl restart ws-ovpn
systemctl enable ws-dropbear
systemctl restart ws-dropbear
systemctl enable ws-stunnel
systemctl restart ws-stunnel
systemctl enable ws-openssh
systemctl restart ws-openssh
