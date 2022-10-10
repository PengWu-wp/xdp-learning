/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") xsks_map = {
        .type = BPF_MAP_TYPE_XSKMAP,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = 64,  /* Assume netdev has no more than 64 queues */
};

SEC("xdp")
int xdp_sock_prog(struct xdp_md *ctx)
{
    int index = ctx->rx_queue_index;

    if (bpf_map_lookup_elem(&xsks_map, &index)){ // 只有绑定了对应的XSK_fd才会redirect
        return bpf_redirect_map(&xsks_map, index, 0);
    }
//    bpf_printk("No xsk bounded to queue %d\n", index);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
