#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_PACKET_RATE 1000
#define WINDOW_NS 1000000000ULL

struct flow_stats {
    __u64 packet_count;
    __u64 window_start;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct flow_stats);
} flow_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_counter SEC(".maps");

SEC("xdp")
int xdp_flood_absorber(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u64 now = bpf_ktime_get_ns();

    struct flow_stats *stats = bpf_map_lookup_elem(&flow_map, &src_ip);

    if (!stats) {
        struct flow_stats new_stats = {
            .packet_count = 1,
            .window_start = now,
        };
        bpf_map_update_elem(&flow_map, &src_ip, &new_stats, BPF_ANY);
        return XDP_PASS;
    }

    if (now - stats->window_start > WINDOW_NS) {
        stats->packet_count = 1;
        stats->window_start = now;
        return XDP_PASS;
    }

    stats->packet_count++;

    if (stats->packet_count > MAX_PACKET_RATE) {
        __u32 key = 0;
        __u64 *counter = bpf_map_lookup_elem(&drop_counter, &key);
        if (counter)
            __sync_fetch_and_add(counter, 1);
        return XDP_DROP;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
