#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/pkt_cls.h>

#define MATCH_DST_PORT       (1 << 3)
#define MATCH_ENABLED        (1 << 8)
#define MATCH_SNIFF          (1 << 9)
#define MATCH_DROP           (1 << 10)

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

void update_rule(int map_fd, __u32 key, __u16 dst_port, __u16 mask) {
    struct filter_rule rule = {0};
    rule.dst_port = dst_port;
    rule.match_mask = mask | MATCH_ENABLED;
    if (bpf_map_update_elem(map_fd, &key, &rule, BPF_ANY)) {
        fprintf(stderr, "ERROR: updating filter_rules map failed: %s\n", strerror(errno));
        exit(1);
    }
}

void test_packet(int prog_fd, const char *msg, int expected_retval, __u16 dport) {
    char packet[128];
    memset(packet, 0, sizeof(packet));

    struct iphdr *ip = (struct iphdr *)packet;
    ip->version = 4;
    ip->ihl = 5;
    ip->protocol = 6; // TCP
    ip->saddr = inet_addr("127.0.0.1");
    ip->daddr = inet_addr("127.0.0.1");
    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));

    struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
    tcp->source = htons(12345);
    tcp->dest = htons(dport);

    struct bpf_test_run_opts opts = {
        .sz = sizeof(struct bpf_test_run_opts),
        .data_in = packet,
        .data_size_in = sizeof(packet),
        .repeat = 1,
    };

    int err = bpf_prog_test_run_opts(prog_fd, &opts);
    if (err) {
        printf("  [FAIL] %s: bpf_prog_test_run_opts failed: %s\n", msg, strerror(errno));
        exit(1);
    }

    if (opts.retval == expected_retval) {
        printf("  [PASS] %s (retval=%d)\n", msg, opts.retval);
    } else {
        printf("  [FAIL] %s: expected retval=%d, got %d\n", msg, expected_retval, opts.retval);
        exit(1);
    }
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bpf_object_file>\n", argv[0]);
        return 1;
    }

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "filter_rules");
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "tc_divert_egress");
    if (map_fd < 0 || !prog) {
        fprintf(stderr, "ERROR: finding map or program failed\n");
        return 1;
    }
    int prog_fd = bpf_program__fd(prog);

    printf("Running eBPF C Tests...\n");

    // Case 1: Match and Divert
    update_rule(map_fd, 0, 80, MATCH_DST_PORT);
    test_packet(prog_fd, "Match and Divert", 4, 80);

    // Case 2: Match and Sniff
    update_rule(map_fd, 0, 80, MATCH_DST_PORT | MATCH_SNIFF);
    test_packet(prog_fd, "Match and Sniff", -1, 80);

    // Case 3: Match and Drop
    update_rule(map_fd, 0, 80, MATCH_DST_PORT | MATCH_DROP);
    test_packet(prog_fd, "Match and Drop", 2, 80);

    // Case 4: No Match
    update_rule(map_fd, 0, 80, MATCH_DST_PORT);
    test_packet(prog_fd, "No Match (different port)", -1, 8080);

    printf("All eBPF C Tests passed!\n");
    bpf_object__close(obj);
    return 0;
}
