#!/bin/bash
# lab/up.sh
set -e
bash "$(dirname "$0")/down.sh"

for n in client router lb backend; do
  ip netns add $n
  ip -n $n link set lo up
done
ip netns exec router sysctl -qw net.ipv4.ip_forward=1

# client <-> router
ip link add c0 netns client type veth peer name rc netns router
ip -n client addr add 10.0.0.2/24 dev c0
ip -n router addr add 10.0.0.1/24 dev rc
ip -n client link set c0 up
ip -n router link set rc up
ip -n client route add default via 10.0.0.1

# bridge in the router, with lb and backend plugged in
ip -n router link add br0 type bridge
ip -n router addr add 10.0.1.1/24 dev br0
ip -n router link set br0 up

attach() {   # name, host-octet
  ip link add eth0 netns $1 type veth peer name rb-$1 netns router
  ip -n $1 addr add 10.0.1.$2/24 dev eth0
  ip -n $1 link set eth0 up
  ip -n router link set rb-$1 master br0 up
  ip -n $1 route add default via 10.0.1.1
}
attach lb 10
attach backend 20
