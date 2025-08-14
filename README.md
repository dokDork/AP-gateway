# AP-gateway
[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)  


## Description
The tool activates an access point, on the Linux machine on which it is activated, that works like a gateway thus creating an AP that must be connected to the internet. All traffic passing through the access point can be analyzed or diverted to other proxies, by means of iptables, active on the Linux machine (such as burpSuite, mitmproxy, certmitm, or others).

Once all network traffic from connected clients passes through the gateway AP, it can be analyzed with tools like mitmproxy (in transparent mode) to see the packets in transit. To do this, you'll need to divert the traffic from its original path to the proxy port (e.g., port 8080 for mitmproxy) with the following commands:
 ```
# Port forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
# Disable ICMP redirects.
sysctl -w net.ipv4.conf.all.send_redirects=0
# Create an iptables ruleset that redirects the desired traffic to mitmproxy:
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
 ```


## Example Usage
You'll need two network cards on your Linux PC. One connected to the internet (e.g., eth0 or wlan0) and one Wi-Fi (e.g., wlan1) free to host new connections for the devices you want to connect. At this point, to create the gateway access point, simply use the following command:
 ```
./AP-gateway MyAPName MyAPpassword wlan1 wlan0
 ```
 
  
## Command-line parameters
```
./AP-gateway MyAPName MyAPpassword wlan1 wlan0
```

| Parameter | Description                          | Example       |
|-----------|--------------------------------------|---------------|
| `MyAPName`      | The name of the Access Point that should be activate | `SuperSecureAP`, `LetMeIn`, `HelloWorld`, ... |
| `MyAPpassword`      | The password of the Access Point that should be activate          | `password123`          |
| `wlan1`      | Interface to use as AP (e.g., wlan1)         | `wlan1`          |
| `wlan0`      | Interface for internet access       | `wlan0`, `eth0`          |
 
 
 
## How to install it on Kali Linux (or Debian distribution)
It's very simple  
```
cd /opt
sudo git clone https://github.com/dokDork/AP-geteway.git
cd AP-gateway 
chmod 755 AP-gateway.sh 
./AP-gateway.sh 
```
