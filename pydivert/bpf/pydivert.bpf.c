#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define TC_ACT_UNSPEC  (-1)
#define TC_ACT_OK      0
#define TC_ACT_SHOT    2
#define TC_ACT_STOLEN  4

#define STAT_DIVERTED 0
#define STAT_DROPPED  1
#define STAT_SNIFFED  2

struct pydivert_pkt_header {
    __u32 pkt_len;
    __u32 ifindex;
    __u16 direction;
    __u16 l2_len;
    __u32 pad;
};

struct pydivert_packet_buffer {
    struct pydivert_pkt_header header;
    __u8 data[2048];
};

struct filter_rule {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u16 match_mask;
    __u16 invert_mask;
    __u8  proto;
    __u8  direction;
    __u8  loopback;
    __u8  ttl;
    __u8  tcp_flags;
    __u8  tcp_flags_mask;
};

#define MATCH_SRC_IP         (1 << 0)
#define MATCH_DST_IP         (1 << 1)
#define MATCH_SRC_PORT       (1 << 2)
#define MATCH_DST_PORT       (1 << 3)
#define MATCH_PROTO          (1 << 4)
#define MATCH_DIRECTION      (1 << 5)
#define MATCH_LOOPBACK       (1 << 6)
#define MATCH_FALSE          (1 << 7)
#define MATCH_ENABLED        (1 << 8)
#define MATCH_SNIFF          (1 << 9)
#define MATCH_DROP           (1 << 10)
#define MATCH_TTL            (1 << 11)
#define MATCH_TCP_FLAGS      (1 << 12)

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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} config_map SEC(".maps");

static __always_inline void increment_stat(__u32 key) {
    __u64 *val = bpf_map_lookup_elem(&stats_map, &key);
    if (val) {
        *val += 1;
    }
}

static __always_inline int matches_rule(struct __sk_buff *skb, struct filter_rule *rule, __u16 *l2_len_out, __u8 direction) {
    if (!(rule->match_mask & MATCH_ENABLED)) return 0;
    if (rule->match_mask & MATCH_FALSE) return 0;

    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    __u32 src_ip = 0, dst_ip = 0;
    __u16 src_port = 0, dst_port = 0;
    __u8 proto = 0;
    __u8 ttl = 0;
    __u8 tcp_flags = 0;
    __u16 l2_len = 0;
    int found = 0;

    // Detect L3 offset: try 0, 4, 14
    if (data + 20 <= data_end) {
        __u8 b0 = *(__u8 *)data;
        if ((b0 & 0xF0) == 0x40 || (b0 & 0xF0) == 0x60) {
            l2_len = 0; found = 1;
        }
    }
    if (!found && (char *)data + 4 + 20 <= (char *)data_end) {
        __u8 b4 = *((__u8 *)data + 4);
        if ((b4 & 0xF0) == 0x40 || (b4 & 0xF0) == 0x60) {
            l2_len = 4; found = 1;
        }
    }
    if (!found && (char *)data + 14 + 20 <= (char *)data_end) {
        __u8 b14 = *((__u8 *)data + 14);
        if ((b14 & 0xF0) == 0x40 || (b14 & 0xF0) == 0x60) {
            l2_len = 14; found = 1;
        }
    }

    if (!found) {
        if (rule->match_mask == MATCH_ENABLED) return 1;
        return 0;
    }

    *l2_len_out = l2_len;
    void *l3_ptr = (char *)data + l2_len;
    __u8 ver = (*(__u8 *)l3_ptr) >> 4;

    if (ver == 4) {
        struct iphdr *ip = l3_ptr;
        if ((void *)(ip + 1) > data_end) return 0;
        src_ip = bpf_ntohl(ip->saddr);
        dst_ip = bpf_ntohl(ip->daddr);
        proto = ip->protocol;
        ttl = ip->ttl;

        __u8 ihl = (*(__u8 *)l3_ptr) & 0x0F;
        if (ihl < 5) return 0;

        void *transport_ptr = (char *)l3_ptr + (ihl * 4);

        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcp = transport_ptr;
            if ((void *)(tcp + 1) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
                tcp_flags = *((__u8 *)tcp + 13);
            }
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udp = transport_ptr;
            if ((void *)(udp + 1) <= data_end) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }
    } else if (ver == 6) {
        struct ipv6hdr *ip6 = l3_ptr;
        if ((void *)(ip6 + 1) > data_end) return 0;
        proto = ip6->nexthdr;
        ttl = ip6->hop_limit;
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcp = (void *)(ip6 + 1);
            if ((void *)(tcp + 1) <= data_end) {
                src_port = bpf_ntohs(tcp->source);
                dst_port = bpf_ntohs(tcp->dest);
                tcp_flags = *((__u8 *)tcp + 13);
            }
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udp = (void *)(ip6 + 1);
            if ((void *)(udp + 1) <= data_end) {
                src_port = bpf_ntohs(udp->source);
                dst_port = bpf_ntohs(udp->dest);
            }
        }
    }

    if ((rule->match_mask & MATCH_SRC_IP) && ((src_ip == rule->src_ip) == !!(rule->invert_mask & MATCH_SRC_IP))) return 0;
    if ((rule->match_mask & MATCH_DST_IP) && ((dst_ip == rule->dst_ip) == !!(rule->invert_mask & MATCH_DST_IP))) return 0;
    if ((rule->match_mask & MATCH_SRC_PORT) && ((src_port == rule->src_port) == !!(rule->invert_mask & MATCH_SRC_PORT))) return 0;
    if ((rule->match_mask & MATCH_DST_PORT) && ((dst_port == rule->dst_port) == !!(rule->invert_mask & MATCH_DST_PORT))) return 0;
    if ((rule->match_mask & MATCH_PROTO) && ((proto == rule->proto) == !!(rule->invert_mask & MATCH_PROTO))) return 0;
    if ((rule->match_mask & MATCH_DIRECTION) && ((direction == rule->direction) == !!(rule->invert_mask & MATCH_DIRECTION))) return 0;
    if ((rule->match_mask & MATCH_TTL) && ((ttl == rule->ttl) == !!(rule->invert_mask & MATCH_TTL))) return 0;
    if ((rule->match_mask & MATCH_TCP_FLAGS) && (tcp_flags & rule->tcp_flags_mask) != rule->tcp_flags) return 0;

    if (rule->match_mask & MATCH_LOOPBACK) {
        int is_lo = (skb->ifindex == 1);
        if (is_lo != rule->loopback) return 0;
    }

    return 1;
}

static __always_inline int process_packet(struct __sk_buff *skb, __u8 direction) {
    __u32 key = 0;
    __u32 *my_prio_ptr = bpf_map_lookup_elem(&config_map, &key);
    __u32 my_prio = my_prio_ptr ? *my_prio_ptr : 0;

    // LOOP_PREVENTION_MARK mask: 0x4D490000 | priority
    if ((skb->mark & 0xFFFF0000) == 0x4D490000) {
        __u16 inject_prio = skb->mark & 0xFFFF;
        // Ignore if we injected it, or if our priority is higher/equal (lower/equal integer)
        // than the injector's priority. This allows lower priority handles (higher integer)
        // to see reinjected packets.
        if (my_prio <= inject_prio) return TC_ACT_UNSPEC;
    }

    // Avoid double-processing loopback: only capture on Egress (Outbound)
    // if (skb->ifindex == 1 && direction == 1) return TC_ACT_UNSPEC;

    bpf_skb_pull_data(skb, 64);

    __u16 l2_len = 0;
    int matched = 0;
    struct filter_rule *matched_rule = NULL;

    #pragma unroll
    for (__u32 i = 0; i < 16; i++) {
        __u32 key = i;
        struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules, &key);
        if (!rule || rule->match_mask == 0) break;
        if (matches_rule(skb, rule, &l2_len, direction)) {
            matched = 1;
            matched_rule = rule;
            break;
        }
    }

    if (!matched) return TC_ACT_UNSPEC;

    if (matched_rule->match_mask & MATCH_DROP) {
        increment_stat(STAT_DROPPED);
        return TC_ACT_SHOT;
    }

    struct pydivert_packet_buffer *buf = bpf_ringbuf_reserve(&pcap_ringbuf, sizeof(struct pydivert_packet_buffer), 0);
    if (!buf) return TC_ACT_UNSPEC;

    buf->header.pkt_len = skb->len;
    buf->header.ifindex = skb->ifindex;
    buf->header.direction = (__u16)direction;
    buf->header.l2_len = l2_len;
    buf->header.pad = 0xDEADC0DE;

    __u32 to_load = skb->len;
    if (to_load > 2048) to_load = 2048;
    if (to_load > 0) {
        bpf_skb_load_bytes(skb, 0, buf->data, ((to_load - 1) & 0x7FF) + 1);
    }

    bpf_ringbuf_submit(buf, 0);

    if (matched_rule->match_mask & MATCH_SNIFF) {
        increment_stat(STAT_SNIFFED);
        return TC_ACT_UNSPEC;
    }

    increment_stat(STAT_DIVERTED);
    return TC_ACT_STOLEN;
}

SEC("classifier")
int tc_divert_ingress(struct __sk_buff *skb) {
    return process_packet(skb, 1);
}

SEC("classifier")
int tc_divert_egress(struct __sk_buff *skb) {
    return process_packet(skb, 2);
}

char _license[] SEC("license") = "Dual LGPL/GPL";
