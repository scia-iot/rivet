"""Shared OpenVPN and route samples used by API and utility tests."""

SERVER_CONFIG_LINES = """
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh2048.pem
data-ciphers-fallback AES-256-CBC
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist /var/log/openvpn/ipp.txt
client-config-dir ccd
ccd-exclusive
keepalive 10 120
persist-key
persist-tun
status /var/log/openvpn/openvpn-status.log
log         /var/log/openvpn/openvpn.log
verb 3
explicit-exit-notify 1
client-connect /opt/rivet/client-connect.sh
client-disconnect /opt/rivet/client-disconnect.sh
script-security 2
"""

SERVER_STATUS_ACTIVE = """
● openvpn@server.service - OpenVPN connection to server
    Loaded: loaded (/usr/lib/systemd/system/openvpn@.service; enabled; preset: enabled)
    Active: active (running) since Mon 2025-01-13 08:15:17 UTC; 15s ago
    """

MOCKED_ROUTES = """10.8.0.0/24 proto kernel scope link src 10.8.0.1
192.168.1.0/24 via 10.8.0.1
"""
