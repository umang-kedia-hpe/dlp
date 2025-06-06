#!/bin/sh
set -e
# Set up iptables rules (exclude mitmproxy user, UID 1000)
iptables -t nat -A OUTPUT -m owner --uid-owner 1000 -j RETURN
iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8082
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8082
# Drop to mitmproxy user (UID 1000) and run mitmdump
exec su -s /bin/sh -c "mitmdump -s /scripts/dlp.py --listen-port 8082 --ssl-insecure" mitmproxy