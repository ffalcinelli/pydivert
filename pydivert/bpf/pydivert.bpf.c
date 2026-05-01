#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_STOLEN 4

#define ETH_P_IP 0x0800

#define MATCH_SRC_IP (1 << 0)
#define MATCH_DST_IP (1 << 1)
#define MATCH_SRC_PORT (1 << 2)
#define MATCH_DST_PORT (1 << 3)
#define MATCH_PROTO (1 << 4)
#define MATCH_DIRECTION (1 << 5)
#define MATCH_LOOPBACK (1 << 6)
#define MATCH_FALSE (1 << 7)
#define MATCH_ENABLED (1 << 8)
#define MATCH_SNIFF (1 << 9)
#define MATCH_DROP (1 << 10)
#define MATCH_TTL (1 << 11)
#define MATCH_TCP_FLAGS (1 << 12)

char LICENSE[] SEC("license") = "Dual MIT/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} pcap_ringbuf SEC(".maps");

struct filter_rule {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 match_mask;
    __u8 proto;
    __u8 direction;
    __u8 loopback;
    __u8 ttl;
    __u8 tcp_flags;
    __u8 tcp_flags_mask;
    __u8 padding[2];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct filter_rule);
} filter_rules SEC(".maps");

static __always_inline __u16 match_packet(struct __sk_buff *skb, __u8 direction) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return 0;
    
    struct iphdr *ip = NULL;
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    
    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > data_end) ip = NULL;
        else {
            if (ip->protocol == 6 /* TCP */) {
                tcp = (struct tcphdr *)((void *)ip + (ip->ihl * 4));
                if ((void *)(tcp + 1) > data_end) tcp = NULL;
            } else if (ip->protocol == 17 /* UDP */) {
                udp = (struct udphdr *)((void *)ip + (ip->ihl * 4));
                if ((void *)(udp + 1) > data_end) udp = NULL;
            }
        }
    }

    __u16 matched_mask = 0;
    
    for (__u32 i = 0; i < 64; i++) {
        __u32 key = i;
        struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules, &key);
        if (!rule) continue;
        if (!(rule->match_mask & MATCH_ENABLED)) continue;
        if (rule->match_mask & MATCH_FALSE) continue;

        int rule_matches = 1;

        if (rule->match_mask & MATCH_DIRECTION) {
            if (rule->direction != direction) rule_matches = 0;
        }
        
        if (rule->match_mask & MATCH_LOOPBACK) {
            if (rule->loopback != 1) rule_matches = 0;
        }

        if (ip) {
            if (rule->match_mask & MATCH_PROTO) {
                if (rule->proto != ip->protocol) rule_matches = 0;
            }
            if (rule->match_mask & MATCH_TTL) {
                if (rule->ttl != ip->ttl) rule_matches = 0;
            }
            if (rule->match_mask & MATCH_SRC_IP) {
                if (rule->src_ip != ip->saddr) rule_matches = 0;
            }
            if (rule->match_mask & MATCH_DST_IP) {
                if (rule->dst_ip != ip->daddr) rule_matches = 0;
            }
            if (rule->match_mask & MATCH_SRC_PORT) {
                if (tcp) {
                    if (rule->src_port != bpf_ntohs(tcp->source)) rule_matches = 0;
                } else if (udp) {
                    if (rule->src_port != bpf_ntohs(udp->source)) rule_matches = 0;
                } else {
                    rule_matches = 0;
                }
            }
            if (rule->match_mask & MATCH_DST_PORT) {
                if (tcp) {
                    if (rule->dst_port != bpf_ntohs(tcp->dest)) rule_matches = 0;
                } else if (udp) {
                    if (rule->dst_port != bpf_ntohs(udp->dest)) rule_matches = 0;
                } else {
                    rule_matches = 0;
                }
            }
            if (rule->match_mask & MATCH_TCP_FLAGS) {
                if (tcp) {
                    __u8 flags = ((__u8 *)tcp)[13];
                    if ((flags & rule->tcp_flags_mask) != rule->tcp_flags) rule_matches = 0;
                } else {
                    rule_matches = 0;
                }
            }
        } else {
            if (rule->match_mask & (MATCH_PROTO | MATCH_SRC_IP | MATCH_DST_IP | MATCH_SRC_PORT | MATCH_DST_PORT | MATCH_TTL | MATCH_TCP_FLAGS)) {
                rule_matches = 0;
            }
        }

        if (rule_matches) {
            matched_mask = rule->match_mask;
            break;
        }
    }
    return matched_mask;
}

SEC("classifier/ingress")
int tc_divert_ingress(struct __sk_buff *skb) {
    if (skb->mark == 0x4D49544D) return TC_ACT_OK;
    
    __u16 mask = match_packet(skb, 1); // 1 = Inbound
    if (!mask) return TC_ACT_OK;

    if (mask & MATCH_DROP) return TC_ACT_SHOT;

    __u32 len = skb->len;
    if (len > 2048) len = 2048;
    if (len < 14) len = 14;
    
    void *ringbuf_space = bpf_ringbuf_reserve(&pcap_ringbuf, 2053, 0);
    if (!ringbuf_space) return TC_ACT_OK;

    *(u32 *)ringbuf_space = len;
    *((__u8 *)ringbuf_space + 4) = 1;
    
    if (len <= 2048) {
        bpf_skb_load_bytes(skb, 0, (char *)ringbuf_space + 5, len);
    }
    
    bpf_ringbuf_submit(ringbuf_space, 0);

    if (mask & MATCH_SNIFF) return TC_ACT_OK;

    return TC_ACT_STOLEN;
}

SEC("classifier/egress")
int tc_divert_egress(struct __sk_buff *skb) {
    if (skb->mark == 0x4D49544D) return TC_ACT_OK;
    
    __u16 mask = match_packet(skb, 2); // 2 = Outbound
    if (!mask) return TC_ACT_OK;

    if (mask & MATCH_DROP) return TC_ACT_SHOT;

    __u32 len = skb->len;
    if (len > 2048) len = 2048;
    if (len < 14) len = 14;
    
    void *ringbuf_space = bpf_ringbuf_reserve(&pcap_ringbuf, 2053, 0);
    if (!ringbuf_space) return TC_ACT_OK;

    *(u32 *)ringbuf_space = len;
    *((__u8 *)ringbuf_space + 4) = 2; // 2 = Outbound
    
    if (len <= 2048) {
        bpf_skb_load_bytes(skb, 0, (char *)ringbuf_space + 5, len);
    }
    
    bpf_ringbuf_submit(ringbuf_space, 0);

    if (mask & MATCH_SNIFF) return TC_ACT_OK;

    return TC_ACT_STOLEN;
}
