//go:build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_BACKENDS 16

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32); // IPv4 destination address
    __uint(max_entries, MAX_BACKENDS);
} backends SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64); // packet counter
    __uint(max_entries, 2); // 0 = total_packets, 1 = forwarded_packets
} lb_stats SEC(".maps");

// Incremental checksum update helper for IPv4 header
static __always_inline void update_csum(__u16 *csum, __u32 old_addr, __u32 new_addr) {
    __u32 sum = *csum;
    sum += (~old_addr & 0xffff) + (~(old_addr >> 16) & 0xffff);
    sum += (new_addr & 0xffff) + (new_addr >> 16);
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    *csum = sum;
}

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u32 key_total = 0;
    __u64 *total = bpf_map_lookup_elem(&lb_stats, &key_total);
    if (total) {
        __sync_fetch_and_add(total, 1);
    }

    // 1. Verify Ethernet Header boundary
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // 2. Verify IPv4 Header boundary
    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        return XDP_PASS;
    }

    // 3. Simple 5-tuple hash for backend selection
    __u32 hash = iph->saddr ^ iph->daddr;
    __u32 backend_idx = hash % MAX_BACKENDS;

    __u32 *backend_ip = bpf_map_lookup_elem(&backends, &backend_idx);
    if (!backend_ip || *backend_ip == 0) {
        return XDP_PASS;
    }

    // 4. Update packet counters
    __u32 key_fwd = 1;
    __u64 *fwd = bpf_map_lookup_elem(&lb_stats, &key_fwd);
    if (fwd) {
        __sync_fetch_and_add(fwd, 1);
    }

    // 5. Rewrite destination IP and recalculate checksum
    __u32 old_ip = iph->daddr;
    iph->daddr = *backend_ip;
    update_csum(&iph->check, old_ip, *backend_ip);

    // Forward packet back out or pass through
    return XDP_PASS;
}
