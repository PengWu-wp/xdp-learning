/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/if_ether.h>

#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") blacklist_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(__u32),
        .value_size  = sizeof(__u32),
        .max_entries = 1000,
};

SEC("xdp")
int  xdp_prog(struct xdp_md *ctx)
{
    int ipsize = 0;
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    ipsize = sizeof(*eth);
    ip = data + ipsize;
    ipsize += sizeof(struct iphdr);
    if (data + ipsize > data_end) { // To pass eBPF verifier
        return XDP_DROP;
    }

    __u32 key = ip->saddr;
    __u32 *value;

    value = bpf_map_lookup_elem(&blacklist_map, &key);
    if (value) {
        bpf_printk("ip found in blacklist, dropped\n");
        return XDP_DROP;
    } else {
        bpf_printk("Good to pass\n");
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
