#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define TC_ACT_OK 0
#define TC_ACT_STOLEN 4
#define MAX_RULES 32

#define MATCH_SRC_IP   (1 << 0)
#define MATCH_DST_IP   (1 << 1)
#define MATCH_SRC_PORT (1 << 2)
#define MATCH_DST_PORT (1 << 3)
#define MATCH_PROTO    (1 << 4)

struct filter_rule {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    uint8_t  match_mask;
};

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} pcap_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, uint32_t);
    __type(value, struct filter_rule);
    __uint(max_entries, MAX_RULES);
} rules_map SEC(".maps");

static __always_inline bool match_packet(struct __sk_buff *skb, struct filter_rule *rule) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return false;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return false;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return false;

    uint32_t p_src_ip = ip->saddr;
    uint32_t p_dst_ip = ip->daddr;
    uint8_t  p_proto = ip->protocol;
    uint16_t p_src_port = 0, p_dst_port = 0;

    if (p_proto == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) <= data_end) {
            p_src_port = bpf_ntohs(tcp->source);
            p_dst_port = bpf_ntohs(tcp->dest);
        }
    } else if (p_proto == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) <= data_end) {
            p_src_port = bpf_ntohs(udp->source);
            p_dst_port = bpf_ntohs(udp->dest);
        }
    }

    if ((rule->match_mask & MATCH_SRC_IP) && rule->src_ip != p_src_ip) return false;
    if ((rule->match_mask & MATCH_DST_IP) && rule->dst_ip != p_dst_ip) return false;
    if ((rule->match_mask & MATCH_SRC_PORT) && rule->src_port != p_src_port) return false;
    if ((rule->match_mask & MATCH_DST_PORT) && rule->dst_port != p_dst_port) return false;
    if ((rule->match_mask & MATCH_PROTO) && rule->proto != p_proto) return false;

    return true;
}

SEC("classifier")
int tc_divert_ingress(struct __sk_buff *skb) {
    if (skb->mark == 0x1) return TC_ACT_OK;

    bool matched = false;
    bool has_rules = false;

    #pragma unroll
    for (uint32_t i = 0; i < MAX_RULES; i++) {
        uint32_t key = i;
        struct filter_rule *rule = bpf_map_lookup_elem(&rules_map, &key);
        if (!rule) break;
        if (rule->match_mask != 0) {
            has_rules = true;
            if (match_packet(skb, rule)) {
                matched = true;
                break;
            }
        }
    }

    if (matched || !has_rules) {
        __u32 len = skb->len;
        if (len > 508) len = 508;
        if (len < 14) len = 14;

        void *ringbuf_space = bpf_ringbuf_reserve(&pcap_ringbuf, 512, 0);
        if (ringbuf_space) {
            *(__u32 *)ringbuf_space = len;
            __u32 load_len = len & 511;
            if (load_len < 1) load_len = 1;
            if (load_len > 508) load_len = 508;
            
            bpf_skb_load_bytes(skb, 0, (char *)ringbuf_space + 4, load_len);
            bpf_ringbuf_submit(ringbuf_space, 0);
            return TC_ACT_STOLEN;
        }
    }

    return TC_ACT_OK;
}
