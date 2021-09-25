/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include <net/if.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>


struct config { /* xdp prog loading related config options */
    uint32_t xdp_flags;
    int ifindex;
    char *ifname;
    char filename[512];
    char progsec[32];
    bool do_unload;
};

static void usage(char *name) {
    printf("usage %s [options] \n\n"
           "Requried options:\n"
           "-d, --dev <ifname>\t\tSpecify the device <ifname>\n\n"

           "Other options:\n"
           "-h, --help\t\tthis text you see right here\n"
           "-S, --skb-mode\t\tInstall XDP program in SKB (AKA generic) mode\n"
           "-N, --native-mode\tInstall XDP program in native mode\n"
           "-U, --unload\t\tUnload XDP program instead of loading\n", name);
} // End of usage

int main(int argc, char **argv) {
    int err;

    struct config cfg = { /* xdp prog loading related config options */
            .ifindex   = -1,
            .do_unload = false,
            .filename = "xdp-drop-kern.o",
            .progsec = "xdp"
    };

    struct option long_options[] = {{"dev",         1, 0, 'd'},
                                    {"skb-mode",    0, 0, 'S'},
                                    {"native-mode", 1, 0, 'N'},
                                    {"help",        0, 0, 'h'},
                                    {"unload",      0, 0, 'U'}
    };
    int c, option_index;
    while ((c = getopt_long(argc, argv, "d:USNh", long_options, &option_index)) != EOF) {
        switch (c) {
            case 'd':
                if (strlen(optarg) >= IF_NAMESIZE) {
                    fprintf(stderr, "ERR: dev name is too long\n");
                    goto error;
                }
                cfg.ifname = optarg;
                cfg.ifindex = if_nametoindex(cfg.ifname);
                if (cfg.ifindex == 0) {
                    fprintf(stderr, "ERR: dev name unknown err\n");
                    goto error;
                }
                break;
            case 'U':
                cfg.do_unload = true;
                break;
            case 'S':
                cfg.xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
                cfg.xdp_flags |= XDP_FLAGS_SKB_MODE;  /* Set   flag */
                break;
            case 'N':
                cfg.xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
                cfg.xdp_flags |= XDP_FLAGS_DRV_MODE;  /* Set   flag */
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            error:
            default:
                usage(argv[0]);
        }
    } // end of while

    /* Unload XDP prog */
    if (cfg.do_unload) {
        err = bpf_set_link_xdp_fd(cfg.ifindex, -1, cfg.xdp_flags); // set fd -1 to unload
        if (err) {
            fprintf(stderr, "ERR: %s() link set xdp failed (err=%d): %s\n",
                    __func__, err, strerror(-err));
        } else {
            printf("Success: XDP prog detached from device:%s(ifindex:%d)\n",
                   cfg.ifname, cfg.ifindex);
            return 0;
        }
    }

    /* Load XDP prog */
    struct bpf_object *obj;
    int prog_fd;
    /* This function will return the first prog's fd */
    err = bpf_prog_load(cfg.filename, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
    if (err) {
        fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
                cfg.filename, err, strerror(-err));
        return -1;
    }

    /* Attach XDP prg to the specified interface */
    err = bpf_set_link_xdp_fd(cfg.ifindex, prog_fd, cfg.xdp_flags);
    if (err < 0) {
        fprintf(stderr, "ERR: ifindex(%d) link set xdp fd failed (%d): %s\n",
                cfg.ifindex, -err, strerror(-err));
        switch (-err) {
            case EBUSY:
            case EEXIST:
                fprintf(stderr, "Hint: XDP already loaded on device\n");
                return -1;
                break;
            case EOPNOTSUPP:
                fprintf(stderr, "Hint: Native-XDP not supported"
                                " use --skb-mode or -S\n");
                return -1;
                break;
            default:
                break;
        }
    }

    printf("Success: XDP prog loaded on device:%s(ifindex:%d)\n",
           cfg.ifname, cfg.ifindex);
    return 0;
}