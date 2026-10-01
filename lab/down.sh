#!/bin/bash
pkill -f "http.server 8080" || true
for n in client router lb backend; do ip netns del $n 2>/dev/null || true; done
