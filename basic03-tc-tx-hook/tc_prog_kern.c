#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>


#ifndef be16
#define be16 __be16
#endif
#ifndef be32
#define be32 __be32
#endif
#ifndef u32
#define u32 __u32
#endif
#ifndef u16
#define u16 __u16
#endif
#ifndef htonl
#define htonl __constant_htonl
#endif
#ifndef ntohl
#define ntohl __constant_ntohl
#endif
#ifndef htons
#define htons __constant_htons
#endif
#ifndef ntohs
#define ntohs __constant_ntohs
#endif

SEC("tx_prog")
int tx_prog_main(struct __sk_buff *skb) // 相比xdp_md来说__sk_buff结构体具有的信息多的多
{
    int ipsize = 0;
    void *data_end = (void *)(long)skb->data_end;
    void *data     = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    struct tcphdr *tcp = data + sizeof(*eth) + sizeof(*ip);

    ipsize = sizeof(*eth);
    ipsize += sizeof(struct iphdr);
    if (data + ipsize > data_end) { // To pass eBPF verifier
        return TC_ACT_OK;
    }

    if (ip->protocol != IPPROTO_TCP){
        bpf_printk("Not TCP, PASS.\n");
        return TC_ACT_OK;
    }
    ipsize += sizeof(struct tcphdr);

    if (data + ipsize > data_end)
        return TC_ACT_OK;

    __be16 sport = tcp->source;

    if (sport == htons(6379)) { // if this is a redis reply
        bpf_printk("That's a tcp reply to redis client.\n");
    }
    bpf_printk("Not from port 6379, pass.\n");
    return TC_ACT_OK;
}
char _license[] SEC("license") = "GPL";
