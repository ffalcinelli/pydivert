#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_OK      0
#define TC_ACT_SHOT    2
#define TC_ACT_STOLEN  4

#define STAT_DIVERTED 0

struct pkt_header {
    __u32 pkt_len;
    __u8  direction;
    __u8  l2_len;
};

struct filter_rule {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 match_mask;
    __u8  proto;
    __u8  direction;
    __u8  loopback;
    __u8  ttl;
    __u8  tcp_flags;
    __u8  tcp_flags_mask;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} pcap_ringbuf SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct filter_rule);
} filter_rules SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

static __always_inline void increment_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val) *val += 1;
}

static __always_inline int process_packet(struct __sk_buff *skb, __u8 direction) {
    __u32 key = 0;
    struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules, &key);
    if (!rule || rule->match_mask == 0) return TC_ACT_OK;

    __u32 len = skb->len;
    if (len == 0) return TC_ACT_OK;
    if (len > 2048) len = 2048;

    // Fixed size reservation
    struct pkt_header *hdr = bpf_ringbuf_reserve(&pcap_ringbuf, 2056, 0);
    if (!hdr) return TC_ACT_OK;

    hdr->pkt_len = len;
    hdr->direction = direction;
    hdr->l2_len = 0;

    // Use bounded len for load_bytes
    if (len > 0 && len <= 2048) {
        bpf_skb_load_bytes(skb, 0, (void *)((__u8 *)hdr + 8), len);
    }
    
    bpf_ringbuf_submit(hdr, 0);

    increment_stat(STAT_DIVERTED);
    return TC_ACT_STOLEN;
}

SEC("classifier/ingress")
int tc_divert_ingress(struct __sk_buff *skb) {
    if (skb->mark == 0x4D49544D) return TC_ACT_OK;
    return process_packet(skb, 1);
}

SEC("classifier/egress")
int tc_divert_egress(struct __sk_buff *skb) {
    if (skb->mark == 0x4D49544D) return TC_ACT_OK;
    return process_packet(skb, 2);
}

char _license[] SEC("license") = "Dual LGPL/GPL";
