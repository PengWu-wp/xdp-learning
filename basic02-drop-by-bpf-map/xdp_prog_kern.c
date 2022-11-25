/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

/* Use ELF Conventions to create BPF maps */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1000);
    __type(key, __u32);
    __type(value, __u32);
} blacklist_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    int off = 0;
    off = sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (data + off > data_end) { // To pass eBPF verifier
        return XDP_PASS;
    }

    __u32 key = ip->saddr;
    __u32 *value;

    value = bpf_map_lookup_elem(&blacklist_map, &key);
    if (value) {
        // bpf_printk("ip found in blacklist, dropped\n");
        return XDP_DROP;
    } else {
        // bpf_printk("Okay to pass\n");
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";
