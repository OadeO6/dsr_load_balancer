#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

enum {                       /* keep in sync with counterNames in main.go */
    CNT_TOTAL, CNT_NOT_IPV4, CNT_NOT_TCP, CNT_OPTS_OR_FRAG,
    CNT_NOT_VIP, CNT_PORT_MISS, CNT_MATCHED,
    CNT_FWD, CNT_ENCAP_ERR, CNT_REDIR_ERR, CNT_MAX
};

struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, CNT_MAX);
         __type(key, __u32); __type(value, __u64); } counters SEC(".maps");


struct config {
    __be32 vip;        /* match on this destination */
    __be32 backend;    /* outer dst */
    __be32 outer_src;  /* outer src */
};
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
         __type(key, __u32); __type(value, struct config); } cfg_map SEC(".maps");

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
         __type(key, __u16); __type(value, __u8); } ports SEC(".maps");       /* host-order port */

static __always_inline void count(__u32 idx)
{
    __u64 *v = bpf_map_lookup_elem(&counters, &idx);
    if (v) (*v)++;
}

static __always_inline __u16 ip_csum(struct iphdr *iph)
{
    __u16 *p = (__u16 *)iph;
    __u32 sum = 0;
#pragma unroll
    for (int i = 0; i < 10; i++)
        sum += p[i];
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

SEC("tc")
int lb_ingress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    count(CNT_TOTAL);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP)) {
        count(CNT_NOT_IPV4); return TC_ACT_UNSPEC;
    }
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP) {
        count(CNT_NOT_TCP); return TC_ACT_UNSPEC;
    }
    /* v1 non-goal: IP options and fragments go to the normal stack */
    if (ip->ihl != 5 || (bpf_ntohs(ip->frag_off) & 0x3fff)) {
        count(CNT_OPTS_OR_FRAG); return TC_ACT_UNSPEC;
    }
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end) {
        count(CNT_NOT_TCP); return TC_ACT_UNSPEC;
    }

    __u32 zero = 0;
    struct config *cfg = bpf_map_lookup_elem(&cfg_map, &zero);
    if (!cfg || ip->daddr != cfg->vip) { count(CNT_NOT_VIP); return TC_ACT_UNSPEC; }

    __u16 dport = bpf_ntohs(tcp->dest);
    if (!bpf_map_lookup_elem(&ports, &dport)) {
        count(CNT_PORT_MISS); return TC_ACT_UNSPEC;
    }
        count(CNT_MATCHED);

    /* Build the outer header first: adjust_room invalidates packet pointers. */
    struct iphdr outer = {
        .version = 4, .ihl = 5, .tos = ip->tos,
        .tot_len = bpf_htons(bpf_ntohs(ip->tot_len) + sizeof(outer)),
        .ttl = 64, .protocol = IPPROTO_IPIP,
        .saddr = cfg->outer_src, .daddr = cfg->backend,
    };
    outer.check = ip_csum(&outer);

    if (bpf_skb_adjust_room(skb, sizeof(outer), BPF_ADJ_ROOM_MAC,
                            BPF_F_ADJ_ROOM_ENCAP_L3_IPV4) ||
        bpf_skb_store_bytes(skb, ETH_HLEN, &outer, sizeof(outer),
                            BPF_F_INVALIDATE_HASH)) {
        count(CNT_ENCAP_ERR);
        return TC_ACT_SHOT;
    }

    /* Route + ARP for the outer dst, then transmit. The original packet never
     * reaches the IP stack, so no RST. */
    long rc = bpf_redirect_neigh(skb->ifindex, NULL, 0, 0);
    count(rc == TC_ACT_REDIRECT ? CNT_FWD : CNT_REDIR_ERR);
    return rc;
}

char LICENSE[] SEC("license") = "GPL";
