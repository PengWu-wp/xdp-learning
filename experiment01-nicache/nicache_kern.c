#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include "bpf_helpers.h"

#include "common.h"

// sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(struct memcached_udp_header) + ("get ")
#define ADJUST_HEAD_BYTES 54
// To leave head for conducting value
#define ADJUST_HEAD_LEN 128

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

struct memcached_udp_header {
    __be16 request_id;
    __be16 seq_num;
    __be16 num_dgram;
    __be16 unused;
    char data[];
} __attribute__((__packed__));


/*
 * eBPF maps
*/

struct bpf_map_def SEC("maps") cache_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(struct key_entry),
        .value_size  = sizeof(struct cache_entry),
        .max_entries = 1000,
};


static inline u16 compute_ip_checksum(struct iphdr *ip) {
    u32 csum = 0;
    u16 *next_ip_u16 = (u16 *) ip;

    ip->check = 0;

#pragma clang loop unroll(full)
    for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
        csum += *next_ip_u16++;
    }

    return ~((csum & 0xffff) + (csum >> 16));
}

SEC("xdp")
int bmc_rx_filter_main(struct xdp_md *ctx) {
    void *data_end = (void *) (long) ctx->data_end;
    void *data = (void *) (long) ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);
    void *transp = data + sizeof(*eth) + sizeof(*ip);
    struct udphdr *udp;
    char *payload;
    __be16 dport;
    unsigned int off = 0;

    if (ip + 1 > data_end)
        return XDP_PASS;

    //////////////////////////////////////////////////////////////////////////////////////
    /// stage 1: filter get requests
    switch (ip->protocol) {
        case IPPROTO_UDP:
            udp = (struct udphdr *) transp;
            if (udp + 1 > data_end)
                return XDP_PASS;
            dport = udp->dest;
            payload = transp + sizeof(*udp) + sizeof(struct memcached_udp_header);
            break;
        default:
            return XDP_PASS;
    }

    if (dport == htons(11211) && payload + 4 <= data_end) {
        if (ip->protocol == IPPROTO_UDP &&
            payload[0] == 'g' &&
            payload[1] == 'e' &&
            payload[2] == 't' &&
            payload[3] == ' ') { // is this a GET request
#pragma clang loop unroll(disable)
            for (off = 4; off < MAX_PACKET_LENGTH &&
                          payload + off + 1 <= data_end &&
                          payload[off] == ' '; off++) {} // move offset to the start of the first key
            if (off < MAX_PACKET_LENGTH) {
                if (bpf_xdp_adjust_head(ctx, ADJUST_HEAD_BYTES)) { // push headers + 'get ' keyword
                    return XDP_PASS;
                }
            }

            //////////////////////////////////////////////////////////////////////////////////////
            /// stage 2: parse key

            data_end = (void *) (long) ctx->data_end;
            data = (void *) (long) ctx->data;
            payload = data;

            struct key_entry key;
            unsigned short key_len = 0;
#pragma clang loop unroll(full)
            for (off = 0; off < MAX_KEY_LENGTH; off++) {
                key.data[off] = 0x00;
            }
            // parse the key
#pragma clang loop unroll(disable)
            for (off = 0; off < MAX_KEY_LENGTH && payload + off + 1 <= data_end; off++) {
                if (payload[off] == '\r') {
                    break;
                } else {
                    key.data[off] = payload[off];
                    key_len++;
                }
            }
            struct cache_entry *value = bpf_map_lookup_elem(&cache_map, &key);
            if (!value) {
                bpf_xdp_adjust_head(ctx, -ADJUST_HEAD_BYTES);
                return XDP_PASS;
            } else {

                //////////////////////////////////////////////////////////////////////////////////////
                /// stage 3: cache hit, prepare the packet

                // pop empty packet buffer memory to increase the available packet size
                if (bpf_xdp_adjust_head(ctx, -ADJUST_HEAD_LEN)) {
                    return XDP_PASS;
                }

                data_end = (void *) (long) ctx->data_end;
                data = (void *) (long) ctx->data;
                eth = data;
                ip = data + sizeof(*eth);
                udp = data + sizeof(*eth) + sizeof(*ip);
                struct memcached_udp_header *memcached_udp_hdr = data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp);
                payload = (char *) (memcached_udp_hdr + 1);

                void *old_data = data + ADJUST_HEAD_LEN - ADJUST_HEAD_BYTES;
                if (payload >= data_end ||
                    old_data + sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*memcached_udp_hdr) >= data_end)
                    return XDP_PASS;

                memmove(eth, old_data, sizeof(*eth) + sizeof(*ip) + sizeof(*udp) + sizeof(*memcached_udp_hdr));

                unsigned char tmp_mac[ETH_ALEN];
                __be32 tmp_ip;
                __be16 tmp_port;

                memcpy(tmp_mac, eth->h_source, ETH_ALEN);
                memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
                memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

                tmp_ip = ip->saddr;
                ip->saddr = ip->daddr;
                ip->daddr = tmp_ip;

                tmp_port = udp->source;
                udp->source = udp->dest;
                udp->dest = tmp_port;


                //////////////////////////////////////////////////////////////////////////////////////
                /// stage 4: header prepared, write packet
                unsigned short vlen_byte = (value->len > 9 ? 2 : 1);
                unsigned short tmp = 6 + key_len + 3 + vlen_byte + 2 + value->len + 2 + 3 + 2;
                // "VALUE " + key_len + " 0 " + vlen_byte + "0x0d 0x0a" + value_len + "0x0d 0x0a" + "END" + "0x0d 0x0a"

                if (payload + tmp <= data_end) {
                    off = 0;
                    payload[off++] = 'V';
                    payload[off++] = 'A';
                    payload[off++] = 'L';
                    payload[off++] = 'U';
                    payload[off++] = 'E';
                    payload[off++] = ' ';
#pragma clang loop unroll(disable)
                    for (int i = 0; i < key_len; i++) { // key
                        payload[off++] = key.data[i];
                    }
                    payload[off++] = ' ';
                    payload[off++] = '0';
                    payload[off++] = ' ';

                    if (vlen_byte == 1) { // value len' len
                        payload[off++] = value->len + '0';
                    } else {
                        payload[off++] = value->len / 10 + '0';
                        payload[off++] = value->len % 10 + '0';
                    }

                    payload[off++] = 0x0d;
                    payload[off++] = 0x0a;

#pragma clang loop unroll(disable)
                    for (int i = 0; i < value->len && i < MAX_VAL_LENGTH; i++) { // value
                        payload[off++] = value->data[i];
                    }

                    payload[off++] = 0x0d;
                    payload[off++] = 0x0a;

                    payload[off++] = 'E';
                    payload[off++] = 'N';
                    payload[off++] = 'D';

                    payload[off++] = 0x0d;
                    payload[off++] = 0x0a;


                }
                udp->len = htons(tmp + 16);
                ip->tot_len = htons(tmp + 36);
                udp->check = 0;
                ip->check = compute_ip_checksum(ip);

                //////////////////////////////////////////////////////////////////////////////////////
                /// stage 5: Trim and reply packet
                bpf_xdp_adjust_tail(ctx, 0 - (80 - tmp + key_len));
                return XDP_TX;
            }
        }
    }

    return XDP_PASS;
}

char _license[]
SEC("license") = "GPL";
