#!/bin/bash

# Script to activate an Access Point (AP) on Kali Linux
# Requires three parameters: AP name, input interface, and output interface

# Request parameters if not provided as arguments
AP_NAME="$1"
iIN="$2"
iOUT="$3"

# Function to show usage
function show_usage {
    echo "Usage: $0 <AP_NAME> <INPUT_INTERFACE> <OUTPUT_INTERFACE>"
    echo "Example: $0 MyAP wlan0 eth0"
    echo "Parameters:"
    echo "  AP_NAME          - Name of the Access Point (SSID)"
    echo "  INPUT_INTERFACE  - Interface to use as AP (e.g., wlan0)"
    echo "  OUTPUT_INTERFACE - Interface for internet access (e.g., eth0)"
}

# Check if all parameters are provided
if [ -z "$AP_NAME" ] || [ -z "$iIN" ] || [ -z "$iOUT" ]; then
    echo -e "\n[i] Error: Missing required parameters."
    show_usage
    exit 1
fi

echo -e "\n[i] Starting AP setup with:"
echo "  AP name: $AP_NAME"
echo "  Input interface: $iIN"
echo "  Output interface: $iOUT"


# Check if dnsmasq is running
echo -e "\n[i]Checking if dnsmasq is running..."
if pgrep dnsmasq > /dev/null; then
    echo "dnsmasq is running. Stopping dnsmasq..."
    sudo systemctl stop dnsmasq
    echo "dnsmasq stopped."
else
    echo "dnsmasq is not running."
fi

echo ""

# Check if hostapd is running
echo -e "\n[i] Checking if hostapd is running..."
if pgrep hostapd > /dev/null; then
    echo "hostapd is running. Stopping hostapd..."
    sudo systemctl stop hostapd
    echo "hostapd stopped."
else
    echo "hostapd is not running."
fi

# 1. Install necessary packages if not installed
echo -e "\n[i] Checking and installing required packages..."
dpkg -s hostapd dnsmasq &> /dev/null
if [ $? -ne 0 ]; then
    sudo apt update
    sudo apt install -y hostapd dnsmasq
else
    echo -e "\n[i] hostapd and dnsmasq are already installed."
fi

# 2. Set static IP for input interface
echo -e "\n[i] Configuring static IP on interface $iIN..."
INTERFACES_FILE="/etc/network/interfaces"
BACKUP_FILE="/etc/network/interfaces.bak"

if [ -f "$INTERFACES_FILE" ]; then
    echo -e "\n[i] Backing up existing $INTERFACES_FILE to $BACKUP_FILE..."
    sudo rm -f "$BACKUP_FILE"
    sudo mv "$INTERFACES_FILE" "$BACKUP_FILE"
fi

echo -e "\n[i] Creating new $INTERFACES_FILE..."
sudo bash -c "cat > $INTERFACES_FILE" <<EOL
auto $iIN
iface $iIN inet static
    address 192.168.10.1
    netmask 255.255.255.0
EOL

# 3. Disable NetworkManager control of interfaces
echo -e "\n[i] Configuring NetworkManager..."
NM_CONF="/etc/NetworkManager/NetworkManager.conf"
if [ -f "$NM_CONF" ]; then
    sudo sed -i '/^\[ifupdown\]/,${s/managed=.*/managed=false/}' "$NM_CONF"
else
    echo "[ifupdown]" | sudo tee "$NM_CONF" > /dev/null
    echo "managed=false" | sudo tee -a "$NM_CONF" > /dev/null
fi

# 4. Create hostapd configuration file
echo -e "\n[i] Configuring hostapd..."
HOSTAPD_CONF="/etc/hostapd/hostapd.conf"
HOSTAPD_BAK="/etc/hostapd/hostapd.conf.bak"
if [ -f "$HOSTAPD_CONF" ]; then
    sudo rm -f "$HOSTAPD_BAK"
    sudo mv "$HOSTAPD_CONF" "$HOSTAPD_BAK"
fi

sudo bash -c "cat > $HOSTAPD_CONF" <<EOL
# Which interface to use and which bridge to join
interface=$iIN
driver=nl80211
# 802.11 mode and channel, pretty self-explanatory
hw_mode=g
channel=11
# Set and broadcast the SSID. Stupid double-negatives...
ssid=$AP_NAME
ignore_broadcast_ssid=0
# 802.11N stuff - Try 40 MHz channels, fall back to 20 MHz
ieee80211n=1
ht_capab=[HT40-][SHORT-GI-20][SHORT-GI-40]
# WPA Authentication
auth_algs=1
wpa=2
wpa_passphrase=ForzaParma!
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
# Don't use a MAC ACL
macaddr_acl=0
EOL

# 5. Create dnsmasq configuration file
echo -e "\n[i] Configuring dnsmasq..."
DNSMASQ_CONF="/etc/dnsmasq.conf"
DNSMASQ_BAK="/etc/dnsmasq.conf.bak"
if [ -f "$DNSMASQ_CONF" ]; then
    sudo rm -f "$DNSMASQ_BAK"
    sudo mv "$DNSMASQ_CONF" "$DNSMASQ_BAK"
fi

sudo bash -c "cat > $DNSMASQ_CONF" <<EOL
# DHCP
interface=$iIN      # Use interface $iIN
dhcp-range=192.168.10.50,192.168.10.150,12h  # DHCP range for clients
# GATEWAY
dhcp-option=3,192.168.10.1  # Default gateway for clients
# DNS
dhcp-option=6,8.8.8.8,8.8.4.4  # DNS servers (Google DNS)
# Optional proxy activation (clients may not accept proxy)
# dhcp-option=252,"http://192.168.10.1/proxy.pac"  # URL of PAC file
EOL

# 6. Restart networking services
echo -e "\n[i] Restarting networking services..."
sudo systemctl restart NetworkManager
sudo systemctl restart networking

# 7. Enable IP forwarding
echo -e "\n[i] Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv6.conf.all.forwarding=1
sudo sysctl -w net.ipv4.conf.all.send_redirects=0

# 8. Configure iptables for traffic forwarding and NAT
echo -e "\n[i] IPtables backup"
sudo iptables-save > ~/iptables-backup-$(date +%F-%T).rules
echo -e "\n[i] reset iptables rules"
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t mangle -F
sudo iptables -X
sudo iptables -t nat -X
sudo iptables -t mangle -X
echo -e "\n[i] Setting up iptables rules..."
sudo iptables -t nat -A POSTROUTING -o "$iOUT" -j LOG --log-prefix "Traffic: masquerade"
sudo iptables -t nat -A POSTROUTING -o "$iOUT" -j MASQUERADE
sudo iptables -A FORWARD -i "$iOUT" -o "$iIN" -m conntrack --ctstate RELATED,ESTABLISHED -j LOG --log-prefix "Traffic: $iOUT->$iIN"
sudo iptables -A FORWARD -i "$iOUT" -o "$iIN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i "$iIN" -o "$iOUT" -j LOG --log-prefix "Traffic: $iIN->$iOUT"
sudo iptables -A FORWARD -i "$iIN" -o "$iOUT" -j ACCEPT

# 9. Start hostapd and dnsmasq services
echo -e "\n[i] Starting hostapd and dnsmasq..."
echo "start hostapd"
sudo hostapd /etc/hostapd/hostapd.conf &
echo "start dnsmasq"
sudo dnsmasq -C /etc/dnsmasq.conf &
echo "restart hostapd"
# sudo systemctl restart hostapd

echo -e "\n[i] Access Point setup is complete."
