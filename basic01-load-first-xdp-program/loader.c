/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // uint32_t uint16_t define
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */




struct config {
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
           "-F, --force\t\tForce install, replacing existing program on interface\n"
           "-U, --unload\t\tUnload XDP program instead of loading\n"
           "-o, --obj <objname>\tSpecify the obj filename <objname>, default xdp-drop-kern.o\n"
           "-s, --sec <secname>\tSpecify the section name <secname>, default xdp\n", name);
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
    while ((c = getopt_long(argc, argv, "d:USNFho:s:", long_options, &option_index)) != EOF) {
        switch (c) {
            case 'd':
                if (strlen(optarg) >= IF_NAMESIZE) {
                    fprintf(stderr, "Error: dev name is too long\n");
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
            case 'F':
                cfg.xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
                break;
            case 'o':
                strncpy((char *)&cfg.filename, optarg, sizeof(cfg.filename));
                break;
            case 's':
                strncpy((char *)&cfg.progsec, optarg, sizeof(cfg.progsec));
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            error:
            default:
                usage(argv[0]);
                return 1;
        }
    } // end of while

    if (cfg.ifindex == -1) {
        fprintf(stderr, "Error: required option -d/--dev missing\n");
        usage(argv[0]);
        return 1;
    }
    /* Unload XDP prog */
    if (cfg.do_unload) {
        err = bpf_set_link_xdp_fd(cfg.ifindex, -1, cfg.xdp_flags); // set fd -1 to unload
        if (err) {
            fprintf(stderr, "Error: %s() link set xdp failed (err=%d): %s\n",
                    __func__, err, strerror(-err));
        } else {
            printf("Success: XDP prog detached from device:%s(ifindex:%d)\n",
                   cfg.ifname, cfg.ifindex);
            return 0;
        }
    }

    /* open obj */
    struct bpf_object *obj;
    obj = bpf_object__open(cfg.filename);
    if (!obj) {
        fprintf(stderr, "Error: bpf_object__open failed\n");
        return 1;
    }

    /* find program by section name and set prog type to XDP */
    struct bpf_program *bpf_prog;
    bpf_prog = bpf_object__find_program_by_title(obj, cfg.progsec);
    if (!bpf_prog) {
        fprintf(stderr, "Error: bpf_object__find_program_by_title failed\n");
        return 1;
    }
    bpf_program__set_type(bpf_prog, BPF_PROG_TYPE_XDP);

    /* Load obj into kernel */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error: bpf_object__load failed\n");
        return 1;
    }

    /* Get file descriptor for program */
    int prog_fd;
    prog_fd = bpf_program__fd(bpf_prog);
    if (prog_fd < 0) {
        fprintf(stderr, "Error: Couldn't get file descriptor for program\n");
        return 1;
    }

    /* load xdp prog in the specified interface */
    err = bpf_set_link_xdp_fd(cfg.ifindex, prog_fd, cfg.xdp_flags);
    if (err == -EEXIST && !(cfg.xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
        /* Force mode didn't work, probably because a program of the
         * opposite type is loaded. Let's unload that and try loading
         * again.
         */
        uint32_t old_flags = cfg.xdp_flags;

        cfg.xdp_flags &= ~XDP_FLAGS_MODES;
        cfg.xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
        err = bpf_set_link_xdp_fd(cfg.ifindex, -1, cfg.xdp_flags);
        if (!err)
            err = bpf_set_link_xdp_fd(cfg.ifindex, prog_fd, old_flags);
    }
    if (err < 0) {
        fprintf(stderr, "Error: ifindex(%d) link set xdp fd failed (%d): %s\n",
                cfg.ifindex, -err, strerror(-err));
        switch (-err) {
            case EBUSY:
            case EEXIST:
                fprintf(stderr, "Hint: XDP already loaded on device"
                                " use --force or -F to swap/replace\n");
                break;
            case EOPNOTSUPP:
                fprintf(stderr, "Hint: Native-XDP not supported"
                                " use --skb-mode or -S\n");
                break;
            default:
                break;
        }
        return 1;
    }

    printf("Success: XDP prog loaded on device:%s(ifindex:%d)\n",
           cfg.ifname, cfg.ifindex);
    return 0;
}