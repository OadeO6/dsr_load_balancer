#!/bin/bash
# lab/backend.sh
set -e
B="ip netns exec backend"

# VIP = the LB's IP, as a /32 on the tunnel interface
ip -n backend link set tunl0 up
ip -n backend addr add 10.0.1.10/32 dev tunl0

# Never answer or announce ARP for an address that isn't on the interface asking
for i in all eth0; do
  $B sysctl -qw net.ipv4.conf.$i.arp_ignore=1 net.ipv4.conf.$i.arp_announce=2
done

# Strict rp_filter would drop decapsulated packets (source = client)
for i in all default eth0 tunl0; do
  $B sysctl -qw net.ipv4.conf.$i.rp_filter=0
done

# The LB's IP is also local here, so packets from the LB (ARP and IPIP)
# look like martians. Accept local-source packets on eth0.
for i in all eth0; do
  $B sysctl -qw net.ipv4.conf.$i.accept_local=1
done

# Service listening on all addresses, so it accepts packets to the VIP
mkdir -p /tmp/www && echo "hello from backend" > /tmp/www/index.html
$B python3 -m http.server 8080 --bind 0.0.0.0 --directory /tmp/www >/dev/null 2>&1 &
