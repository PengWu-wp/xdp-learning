/* SPDX-License-Identifier: GPL-2.0 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // uint32_t uint16_t define
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>


struct config {
    uint32_t xdp_flags;
    int ifindex;
    char *ifname;
    char ifname_buf[IF_NAMESIZE];
    int redirect_ifindex;
    char *redirect_ifname;
    char redirect_ifname_buf[IF_NAMESIZE];
    bool do_unload;
    bool reuse_maps;
    char pin_dir[512];
    char filename[512];
    char progsec[32];
    char src_mac[18];
    char dest_mac[18];
    uint16_t xsk_bind_flags;
    int xsk_if_queue;
    bool xsk_poll_mode;
};

static void usage(char *name) {
    printf("usage %s [options] \n\n"
           "Requried options:\n"
           "-d, --dev <ifname>\t\tSpecify the device <ifname>\n\n"

           "Other options:\n"
           "-h, --help\t\tthis text you see right here\n"
           "-S, --skb-mode\t\tInstall XDP program in SKB (AKA generic) mode\n"
           "-N, --native-mode\tInstall XDP program in native mode\n"
           "-U, --unload\t\tUnload XDP program instead of loading\n"
           "-o, --obj <objname>\tSpecify the obj filename <objname>, default xdp_drop_kern.o\n"
           "-s, --sec <secname>\tSpecify the section name <secname>, default xdp\n", name);
} // End of usage



int main(int argc, char **argv) {
    int err;


    struct config cfg = {
            .ifindex   = -1,
            .do_unload = false,
            .filename = "xdp-drop-kern.o",
            .progsec = "xdp"
    };

    struct option long_options[] = {{"dev",         1, 0, 'd'},
                                    {"skb-mode",    0, 0, 'S'},
                                    {"native-mode", 1, 0, 'N'},
                                    {"help",        0, 0, 'h'},
                                    {"obj",         0, 0, 'o'},
                                    {"sec",         0, 0, 's'},
                                    {"unload",      0, 0, 'U'}
    };
    int c, option_index;
    while ((c = getopt_long(argc, argv, "d:USNho:s:", long_options, &option_index)) != EOF) {
        switch (c) {
            case 'd':
                if (strlen(optarg) >= IF_NAMESIZE) {
                    fprintf(stderr, "ERR: dev name is too long\n");
                    goto error;
                }
//                strncpy(cfg.ifname, optarg, IF_NAMESIZE);
                cfg.ifname = optarg;
                cfg.ifindex = if_nametoindex(cfg.ifname);
                if (cfg.ifindex == 0) {
                    fprintf(stderr, "ERR: dev name unknown err\n");
                    goto error;
                } else {
                    printf("WP: ifindex is %d\n", cfg.ifindex);
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
            case 'o':
                strncpy((char *) &cfg.filename, optarg, sizeof(cfg.filename));
                break;
            case 's':
                strncpy((char *) &cfg.progsec, optarg, sizeof(cfg.progsec));
                break;
            error:
            default:
                usage(argv[0]);
        }
    } // end of while

    /* 卸载程序 */
    if (cfg.do_unload) {
        err = bpf_set_link_xdp_fd(cfg.ifindex, -1, cfg.xdp_flags); // fd设为-1，卸载程序
        if (err) {
            fprintf(stderr, "ERR: %s() link set xdp failed (err=%d): %s\n",
                    __func__, err, strerror(-err));
        } else {
            printf("WP: XDP prog detached from device:%s(ifindex:%d)\n",
                   cfg.ifname, cfg.ifindex);
            return 0;
        }
    }

    /* 加载obj文件，获取obj和prog_fd */
    struct bpf_object *obj; // 虽然simple用不上，但还是得承接着
    int prog_fd;
    err = bpf_prog_load(cfg.filename, BPF_PROG_TYPE_XDP, &obj, &prog_fd); // 取到第一个程序的id
    if (err) {
        fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
                cfg.filename, err, strerror(-err));
        return -1;
    }

    /* 挂载程序到指定接口 */

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
        fprintf(stderr, "ERR: "
                        "ifindex(%d) link set xdp fd failed (%d): %s\n",
                cfg.ifindex, -err, strerror(-err));

        switch (-err) {
            case EBUSY:
            case EEXIST:
                fprintf(stderr, "Hint: XDP already loaded on device"
                                " use --force to swap/replace\n");
                return -1;
                break;
            case EOPNOTSUPP:
                fprintf(stderr, "Hint: Native-XDP not supported"
                                " use --skb-mode or --auto-mode\n");
                return -1;
                break;
            default:
                break;
        }
    }

    printf("Success: Loading XDP prog on device:%s(ifindex:%d)\n",
           cfg.ifname, cfg.ifindex);
    return 0;

}