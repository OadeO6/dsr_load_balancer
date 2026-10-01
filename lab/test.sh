#!/bin/bash
# lab/test.sh - rebuild the lab, send one request through the LB, show what each hop saw.
# Run as root from anywhere: sudo bash lab/test.sh
cd "$(dirname "$0")/.."
OUT=/tmp/dsrlb-test
rm -rf $OUT && mkdir -p $OUT

pkill -f "http.server 8080" 2>/dev/null
bash lab/down.sh
bash lab/up.sh && bash lab/backend.sh || exit 1

ip netns exec lb ./dsrlb >$OUT/dsrlb.log 2>&1 &
sleep 1
ip netns exec lb      tcpdump -l -ni eth0 'tcp port 8080 or ip proto 4' >$OUT/lb.txt      2>&1 &
ip netns exec backend tcpdump -l -ni any  'tcp port 8080 or ip proto 4' >$OUT/backend.txt 2>&1 &
ip netns exec client  tcpdump -l -ni c0   'tcp port 8080'              >$OUT/client.txt  2>&1 &
sleep 1

ip netns exec client curl -sS -m 3 http://10.0.1.10:8080/ >$OUT/curl.txt 2>&1
echo "curl exit=$?" >>$OUT/curl.txt
sleep 3

pkill -INT tcpdump; pkill -INT dsrlb; sleep 1
pkill -f "http.server 8080"

for f in curl lb backend client; do echo "===== $f"; grep -v '^tcpdump: \(verbose\|listening\|data link\)' $OUT/$f.txt; done
echo "===== dsrlb (last counters)"; tail -n 2 $OUT/dsrlb.log
echo "===== backend tunl0 / eth0 stats"
ip netns exec backend ip -s link show tunl0 | sed -n 3,6p
ip netns exec backend ip -s link show eth0  | sed -n 3,6p
