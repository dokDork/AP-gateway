#!/bin/bash
# AP setup script with working traps for CTRL+C (SIGINT) and CTRL+Z (SIGTSTP)
set -euo pipefail

### 0. SIGNAL HANDLERS
#      ctrl+x e ctrl+c stop services and restore the situation to before the program started
cleanup_all() {
    echo -e "\n[!] Cleanup started due to user interrupt..."

    NM_CONF="/etc/NetworkManager/NetworkManager.conf"

    echo "[i] Restoring NetworkManager settings..."
    # If managed= exists, replace it. If [ifupdown] exists but managed not present, add it after that header.
    if sudo grep -q '^managed=' "$NM_CONF" 2>/dev/null; then
        sudo sed -i 's/^managed=.*/managed=true/' "$NM_CONF"
    else
        if sudo grep -q '^\[ifupdown\]' "$NM_CONF" 2>/dev/null; then
            # add managed=true after [ifupdown] if not present
            if ! sudo sed -n '/^\[ifupdown\]/,/:/p' "$NM_CONF" 2>/dev/null | grep -q '^managed='; then
                sudo sed -i '/^\[ifupdown\]/a managed=true' "$NM_CONF"
            fi
        else
            # add the section at end
            echo -e "\n[ifupdown]\nmanaged=true" | sudo tee -a "$NM_CONF" >/dev/null
        fi
    fi

    echo "[i] Restarting NetworkManager..."
    sudo systemctl restart NetworkManager || echo "[!] Warning: NetworkManager restart failed"

    echo "[i] Stopping Access Point services..."
    # Try graceful stop first, then pkill as fallback
    sudo systemctl stop hostapd dnsmasq >/dev/null 2>&1 || true
    sudo pkill hostapd >/dev/null 2>&1 || true
    sudo pkill dnsmasq >/dev/null 2>&1 || true

    # If hostapd/dnsmasq were started manually (with sudo ... &), try to kill remaining PIDs
    sleep 0.5
    pids=$(pgrep -f "hostapd /etc/hostapd/hostapd.conf" || true)
    if [ -n "$pids" ]; then
        echo "[i] Killing hostapd PIDs: $pids"
        sudo kill $pids >/dev/null 2>&1 || true
    fi
    pids=$(pgrep -f "dnsmasq -C /etc/dnsmasq.conf" || true)
    if [ -n "$pids" ]; then
        echo "[i] Killing dnsmasq PIDs: $pids"
        sudo kill $pids >/dev/null 2>&1 || true
    fi

    echo "[i] Removing any 'address=' entries from /etc/dnsmasq.conf..."
    if sudo grep -q '^address=' /etc/dnsmasq.conf 2>/dev/null; then
        sudo sed -i '/^address=/d' /etc/dnsmasq.conf
        echo "[i] Removed all address= overrides from dnsmasq.conf"
    else
        echo "[i] No address= entries found"
    fi

    echo "[i] Flushing iptables rules..."
    # flush all standard tables
    sudo iptables --flush || echo "[!] iptables --flush failed"
    sudo iptables -t nat --flush || true
    sudo iptables -t mangle --flush || true
    sudo iptables -X || true
    sudo iptables -t nat -X || true
    sudo iptables -t mangle -X || true

    echo "[i] Cleanup completed. Exiting now."
}

handle_ctrl_c() {
    echo -e "\n[!] You pressed CTRL+C (SIGINT)."
    cleanup_all
    exit 130
}

handle_ctrl_z() {
    # SIGTSTP handler - avoid suspension
    echo -e "\n[!] You pressed CTRL+Z (SIGTSTP). Suspension is blocked."
    logger "User attempted CTRL+Z during AP operation."
    # continue execution in case shell attempted to stop
    kill -CONT $$
}

# Also handle termination signals
handle_term() {
    echo -e "\n[!] Received termination signal."
    cleanup_all
    exit 143
}

trap handle_ctrl_c SIGINT
trap handle_ctrl_z SIGTSTP
trap handle_term SIGTERM SIGQUIT

### ===================================================================

# Script to activate an Access Point (AP) on Kali Linux
echo ""
echo ""
echo '  /$$$$$$  /$$$$$$$                               /$$     '
echo ' /$$__  $$| $$__  $$                             | $$     '
echo '| $$  \ $$| $$  \ $$         /$$$$$$   /$$$$$$  /$$$$$$    /$$$$$$  /$$  /$$  /$$  /$$$$$$  /$$   /$$'
echo '| $$$$$$$$| $$$$$$$//$$$$$$ /$$__  $$ |____  $$|_  $$_/   /$$__  $$| $$ | $$ | $$ |____  $$| $$  | $$'
echo '| $$__  $$| $$____/|______/| $$  \ $$  /$$$$$$$  | $$    | $$$$$$$$| $$ | $$ | $$  /$$$$$$$| $$  | $$'
echo '| $$  | $$| $$             | $$  | $$ /$$__  $$  | $$ /$$| $$_____/| $$ | $$ | $$ /$$__  $$| $$  | $$'
echo '| $$  | $$| $$             |  $$$$$$$|  $$$$$$$  |  $$$$/|  $$$$$$$|  $$$$$/$$$$/|  $$$$$$$|  $$$$$$$'
echo '|__/  |__/|__/              \____  $$ \_______/   \___/   \_______/ \_____/\___/  \_______/ \____  $$'
echo '                            /$$  \ $$                                                       /$$  | $$'
echo '                           |  $$$$$$/                                                      |  $$$$$$/'
echo '                            \______/                                                        \______/ '
echo -e ""
echo -e "version 1.0.0"

# Request parameters if not provided as arguments
AP_NAME="${1:-}"
PWD="${2:-}"
iIN="${3:-}"
iOUT="${4:-}"
REDIRECT="${5:-}"
DNS_RESOLVE="${6:-}"

# Example function call
# setup_port_redirect "80->8080,443->8080" wlan0 lo
setup_port_redirect() {
  local port_mappings="$1"
  local INTERFACE_IN="$2"
  local INTERFACE_OUT="$3"

  if [ -z "$port_mappings" ]; then
    # No parameter, do nothing
    return 0
  fi

  local LOG_PREFIX_FORWARD="AP: ${INTERFACE_IN}->${INTERFACE_OUT}"

  IFS=',' read -ra pairs <<< "$port_mappings"

  for pair in "${pairs[@]}"; do
    if [[ "$pair" == *"->"* ]]; then
      local port_dest=$(echo "$pair" | awk -F'->' '{print $1}')
      local port_redirect=$(echo "$pair" | awk -F'->' '{print $2}')

      local log_prefix="AP: redirect port dest:${port_dest}->lo:${port_redirect}"

      local rule_log_nat="-i $INTERFACE_IN -p tcp --dport $port_dest -j LOG --log-prefix \"$log_prefix\""
      local rule_redirect_nat="-i $INTERFACE_IN -p tcp --dport $port_dest -j REDIRECT --to-port $port_redirect"

      if ! sudo iptables-save -t nat | grep -F -- "$rule_log_nat" >/dev/null 2>&1; then
        echo "Adding LOG rule to nat PREROUTING for port $port_dest redirecting to $port_redirect"
        sudo iptables -t nat -A PREROUTING -i "$INTERFACE_IN" -p tcp --dport "$port_dest" -j LOG --log-prefix "$log_prefix"
      else
        echo "LOG rule for port $port_dest already exists, skipping"
      fi

      if ! sudo iptables-save -t nat | grep -F -- "$rule_redirect_nat" >/dev/null 2>&1; then
        echo "Adding REDIRECT rule to nat PREROUTING from port $port_dest to $port_redirect"
        sudo iptables -t nat -A PREROUTING -i "$INTERFACE_IN" -p tcp --dport "$port_dest" -j REDIRECT --to-port "$port_redirect"
      else
        echo "REDIRECT rule for port $port_dest already exists, skipping"
      fi

    else
      echo "Invalid pair format: '$pair' (expected port->port)"
    fi
  done
}


setup_dns_resolution() {
    local dns_entries="$1"
    local DNSMASQ_CONF="/etc/dnsmasq.conf"

    if [ -z "$dns_entries" ]; then
        echo "[i] No DNS resolution entries provided."
        return 0
    fi

    echo -e "\n[i] Processing DNS resolution entries..."

    IFS=',' read -ra pairs <<< "$dns_entries"

    for pair in "${pairs[@]}"; do
        if [[ "$pair" == *"->"* ]]; then
            local host=$(echo "$pair" | awk -F'->' '{print $1}')
            local ip=$(echo "$pair" | awk -F'->' '{print $2}')

            # Syntax check
            if [[ -z "$host" || -z "$ip" ]]; then
                echo "[!] Invalid DNS resolve entry: '$pair' — skipping"
                continue
            fi

            local entry="address=/$host/$ip"

            # Avoid duplicates
            if ! sudo grep -Fx "$entry" "$DNSMASQ_CONF" >/dev/null 2>&1; then
                echo "[i] Adding DNS override: $host -> $ip"
                echo "$entry" | sudo tee -a "$DNSMASQ_CONF" >/dev/null
            else
                echo "[i] DNS override for $host already exists, skipping"
            fi
        else
            echo "[!] Invalid pair format: '$pair' (expected host->ip)"
        fi
    done

    echo "[i] Restarting dnsmasq to apply DNS resolution rules..."
    sudo systemctl restart dnsmasq || echo "[!] Warning: dnsmasq restart failed"
}


# Function to show usage
function show_usage {
    echo "Usage: $0 <AP_NAME> <AP_PASSWORD> <INPUT_INTERFACE> <OUTPUT_INTERFACE> <REDIRECT> <DNS-RESOLVE>"
    echo "Example: $0 MyAP MyPass wlan0 eth0 80->8080,443->8080"
    echo "Parameters:"
    echo "  AP_NAME          - Name of the Access Point (SSID)"
    echo "  AP_PASSWORD      - Password of the Access Point"
    echo "  INPUT_INTERFACE  - Interface to use as AP (e.g., wlan0)"
    echo "  OUTPUT_INTERFACE - Interface for internet access (e.g., eth0)"
    echo "  REDIRECT         - Redirect a destination port to a local port on which a transparent proxy is listening."
    echo "                     The ports to be redirected must be in the following form: \"<destination port>-><local port to be redirected to>,<destination por>t-><local port to be redirected to>\""
    echo "                     If this parameter is not needed, it will still be necessary to enter at least one -"
    echo "  DNS_RESOLVE      - I can define the IP address that resolves to a given host or domain."
    echo "                     To do this, simply define the list of hosts/domains to resolve in the following format: \"<host/domain>-><IP>,<host/domain>-><IP>\"."
    echo "                     If this parameter is not needed, it will still be necessary to enter at least one -"
    echo ""
    echo "Example:"
    echo "$0 myAP mySuperSecretPassword wlan0 eth0 \"80->8080,443->8080\" \"www.example.org->192.168.1.11,example.org->192.168.1.11\""
    echo "$0 myAP mySuperSecretPassword wlan0 eth0 \"-\" \"www.example.org->192.168.1.11,example.org->192.168.1.11\""
    echo "$0 myAP mySuperSecretPassword wlan0 eth0 \"-\" \"-\""

}

# Check if all parameters are provided
if [ -z "$AP_NAME" ] || [ -z "$PWD" ] || [ -z "$iIN" ] || [ -z "$iOUT" ] || [ -z "$REDIRECT" ] || [ -z "$DNS_RESOLVE" ]; then
    echo -e "\n[i] Error: Missing required parameters."
    show_usage
    exit 1
fi
# If REDIRECT = - Then REDIRECT=""
if [[ "$REDIRECT" == "-" ]]; then
    REDIRECT=""
fi
# If DNS_RESOLVE = - Then DNS_RESOLVE=""
if [[ "$DNS_RESOLVE" == "-" ]]; then
    DNS_RESOLVE=""
fi



echo -e "\n[i] Starting AP setup with:"
echo "  AP name: $AP_NAME"
echo "  AP password: $PWD"
echo "  Input interface: $iIN"
echo "  Output interface: $iOUT"
echo "  Redirect port: $REDIRECT"
echo "  DNS resolution: $DNS_RESOLVE"

# Check if dnsmasq is running
echo -e "\n[i]Checking if dnsmasq is running..."
if pgrep dnsmasq > /dev/null; then
    echo "dnsmasq is running. Stopping dnsmasq..."
    sudo systemctl stop dnsmasq || true
    echo "dnsmasq stopped."
else
    echo "dnsmasq is not running."
fi

echo ""

# Check if hostapd is running
echo -e "\n[i] Checking if hostapd is running..."
if pgrep hostapd > /dev/null; then
    echo "hostapd is running. Stopping hostapd..."
    sudo systemctl stop hostapd || true
    echo "hostapd stopped."
else
    echo "hostapd is not running."
fi

# 1. Install necessary packages if not installed
echo -e "\n[i] Checking and installing required packages..."
if ! dpkg -s hostapd dnsmasq &> /dev/null; then
    sudo apt update
    sudo apt install -y hostapd dnsmasq
else
    echo -e "\n[i] hostapd and dnsmasq are already installed."
fi

# 2. SET INTERFACE !P/NETMASK
#    Set static IP for input interface
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

# 3. NETWORKMANAGER: 
#    Disable NetworkManager control of interfaces
#    set managed=false in NetworkManager.conf
echo -e "\n[i] Configuring NetworkManager..."
NM_CONF="/etc/NetworkManager/NetworkManager.conf"
if [ -f "$NM_CONF" ]; then
    sudo sed -i '/^\[ifupdown\]/,${s/managed=.*/managed=false/}' "$NM_CONF" || true
else
    echo "[ifupdown]" | sudo tee "$NM_CONF" > /dev/null
    echo "managed=false" | sudo tee -a "$NM_CONF" > /dev/null
fi

# 4. CONFIGURE AP: 
#    Create hostapd configuration file
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
wpa_passphrase=$PWD
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
# Don't use a MAC ACL
macaddr_acl=0
EOL

# 5. CONFIGURE DHCP and DNS: 
#    Create dnsmasq configuration file
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
EOL

# 6. Restart networking services
echo -e "\n[i] Restarting networking services..."
sudo systemctl restart NetworkManager || true
sudo systemctl restart networking || true

# 7. Enable IP forwarding
echo -e "\n[i] Enabling IP forwarding..."
sudo sysctl -w net.ipv4.ip_forward=1 || true
sudo sysctl -w net.ipv6.conf.all.forwarding=1 || true
sudo sysctl -w net.ipv4.conf.all.send_redirects=0 || true

# 8. Configure iptables for traffic forwarding and NAT
echo -e "\n[i] IPtables backup"
sudo iptables-save > ~/iptables-backup-$(date +%F-%T).rules || true
echo -e "\n[i] reset iptables rules"
sudo iptables -F || true
sudo iptables -t nat -F || true
sudo iptables -t mangle -F || true
sudo iptables -X || true
sudo iptables -t nat -X || true
sudo iptables -t mangle -X || true
echo -e "\n[i] Setting up iptables rules..."
sudo iptables -t nat -A POSTROUTING -o "$iOUT" -j LOG --log-prefix "AP: masquerade" || true
sudo iptables -t nat -A POSTROUTING -o "$iOUT" -j MASQUERADE || true
sudo iptables -A FORWARD -i "$iOUT" -o "$iIN" -m conntrack --ctstate RELATED,ESTABLISHED -j LOG --log-prefix "AP: $iOUT->$iIN" || true
sudo iptables -A FORWARD -i "$iOUT" -o "$iIN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || true
sudo iptables -A FORWARD -i "$iIN" -o "$iOUT" -j LOG --log-prefix "AP: $iIN->$iOUT" || true
sudo iptables -A FORWARD -i "$iIN" -o "$iOUT" -j ACCEPT || true

# 9. Activate Port Redirection
if [ -n "$REDIRECT" ]; then
  echo -e "\n[i] Port Redirection is defined: $REDIRECT"
  setup_port_redirect "$REDIRECT" "$iIN" lo
else
  echo -e "\n[i] Port Redirection is NOT defined, skipping redirect function"
fi

# 9a. DNS Resolution
if [ -n "$DNS_RESOLVE" ]; then
  echo -e "\n[i] DNS Resoltion is defined: $DNS_RESOLVE"
  setup_dns_resolution "$DNS_RESOLVE"
else
  echo -e "\n[i] DNS Resolution is NOT defined, skipping DNS function"
fi



# 10. Start hostapd and dnsmasq services (in background)
echo -e "\n[i] Starting hostapd and dnsmasq..."
sudo hostapd /etc/hostapd/hostapd.conf >/var/log/hostapd-ap.log 2>&1 &
HOSTAPD_PID=$!
echo "hostapd PID: $HOSTAPD_PID"

sudo dnsmasq -C /etc/dnsmasq.conf >/var/log/dnsmasq-ap.log 2>&1 &
DNSMASQ_PID=$!
echo "dnsmasq PID: $DNSMASQ_PID"

echo -e "\n[i] Access Point setup is complete."
echo -e "[i] AP running in background (hostapd PID=$HOSTAPD_PID dnsmasq PID=$DNSMASQ_PID)"
echo -e "[i] Press CTRL+C to stop and perform cleanup."

# Keep script in foreground so traps work. Wait on child processes (if any)
# We use a simple loop to remain responsive to signals.
while true; do
    # if both processes are gone, exit normally
    if ! kill -0 "$HOSTAPD_PID" >/dev/null 2>&1 && ! kill -0 "$DNSMASQ_PID" >/dev/null 2>&1; then
        echo "[i] Both AP services have exited."
        cleanup_all
        exit 0
    fi
    sleep 1
done
