/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int  xdp_prog(struct xdp_md *ctx)
{
	char fmt[] = "Hello, XDP and eBPF!\n";
	/* This helper function would print fmt to 
         * /sys/kernel/debug/tracing/trace_pipe
         */
	bpf_trace_printk(fmt, sizeof(fmt));					      
					    
	return XDP_DROP; /* Drop all packets */
}
/* Linux adopt GPL so it will refuse progs using other licenses */
char _license[] SEC("license") = "GPL";
