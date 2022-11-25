/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* SEC is a helper macro to place programs, maps, license
 * in different sections in elf_bpf file. It is defined in
 * bpf_helpers.h
 */
SEC("xdp")
int  xdp_prog(struct xdp_md *ctx)
{
	/* This is a helper macro defined in bpf_helpers.h. It would
	 * print fmt to /sys/kernel/debug/tracing/trace_pipe
	 * Noticed that it is not supported in HW mode
         */
//	bpf_printk("Hello, XDP and eBPF!\n");					      
					    
	return XDP_DROP; /* Drop all packets */
	// return XDP_PASS; /* Pass all packets to kernel */
	// return XDP_TX;   /* TX bouncing the received packet-page back out the same NIC it arrived on */
}
/* Linux kernel will refuse XDP progs using other licenses */
char _license[] SEC("license") = "GPL";
