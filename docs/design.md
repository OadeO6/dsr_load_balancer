# Design

## Goal
Layer 4 DSR load balancer using IPIP tunneling. Single VIP:port (TCP/IPv4) to a
single backend for v1. Replies go directly from backend to client, bypassing the LB.

## Non-goals (v1)
IPv6, UDP, IP options, inbound fragments, multiple VIPs, LB high availability.
These packets pass through to the normal stack.

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Data plane hook | TC ingress (BPF) | Works on any NIC; consumes the packet before the IP stack, so no RST and no conntrack. Generic XDP has no real speed edge over TC. |
| Attach method | TCX, kernel >= 6.6 | Link fd ties the program's lifetime to our process (no orphaned programs after a crash) and avoids shared clsact qdisc state. Costs us support for kernels < 6.6; accepted because it removes netlink attach/cleanup code we'd have to maintain. Revisit if older kernels are needed. |
| Encapsulation | IPIP (IP proto 4) | Works across subnets; backend only needs `ipip`. |
| Data plane language | C (port to Rust/aya later) | Verifier and reference material (Katran, Cilium) are C-first; the program is small and isolated. |
| Control plane | Go + cilium/ebpf | Loads the program, manages maps. |

## Requirements
- LB: Linux >= 6.6 (5.10+ for `bpf_redirect_neigh`), BTF, root or CAP_BPF/NET_ADMIN/PERFMON.
- Backend: `ipip` module, VIP as /32 on the tunnel interface, rp_filter off/loose,
  IP proto 4 allowed from the LB, service bound to 0.0.0.0 or the VIP.

## Open
- Lab layout: direct return link (A) vs router namespace (B).
- `tunl0` vs dedicated IPIP interface on the backend (start with `tunl0`).
