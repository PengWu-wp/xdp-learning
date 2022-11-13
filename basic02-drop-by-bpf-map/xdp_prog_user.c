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

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

/* xdp prog loading related config options */
struct config {
    uint32_t xdp_flags;
    int ifindex;
    char *ifname;
    char filename[512];
    char progname[32];
    bool do_unload;
};

static const char *file_path = "/sys/fs/bpf/black_list";

static void usage(char *name) {
    printf("usage %s [options] \n\n"
           "Requried options:\n"
           "-d, --dev <ifname>\t\tSpecify the device <ifname>\n\n"

           "Other options:\n"
           "-h, --help\t\tthis text you see right here\n"
           "-S, --skb-mode\t\tInstall XDP program in SKB (AKA generic) mode\n"
           "-N, --native-mode\t(default) Install XDP program in native mode\n"
           "-H, --offload-mode\tInstall XDP program in offload (AKA HW) mode(NIC support needed)\n"
           "-F, --force\t\tForce install, replacing existing program on interface\n"
           "-U, --unload\t\tUnload XDP program instead of loading\n"
           "-o, --obj <objname>\tSpecify the obj filename <objname>\n"
           "-n, --name <progname>\tSpecify the program name <progname>\n"

           "Map operations:\n"
           "    --map-add <addr>\tAdd an IP to blacklist_map\n"
           "    --map-delete <addr/all>\tDelete an IP to blacklist_map\n"
           "    --map-show\t\tShow blocked IPs in blacklist_map\n", name);
} // End of usage



int main(int argc, char **argv) {
    int err;
    int map_fd = 0;
    __u32 key;
    __u32 value;
    __u32 next_key, lookup_key = -1;

    struct config cfg = {
            /* set XDP_FLAGS_UPDATE_IF_NOEXIST to avoid accidentally unloading
             * an unrelated XDP program, a good practice */
            .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
            .ifindex   = -1,
            .do_unload = false,
            .filename = "xdp_prog_kern.o",
            .progname = "xdp_prog"
    };

    struct option long_options[] = {{"dev",          required_argument, 0, 'd'},
                                    {"skb-mode",     no_argument,       0, 'S'},
                                    {"native-mode",  required_argument, 0, 'N'},
                                    {"offload-mode", required_argument, 0, 'H'},
                                    {"help",         no_argument,       0, 'h'},
                                    {"unload",       no_argument,       0, 'U'},
                                    {"obj",          no_argument,       0, 'o'},
                                    {"name",         no_argument,       0, 'n'},
                                    {"map-add",      required_argument, 0, '1'},
                                    {"map-delete",   required_argument, 0, '2'},
                                    {"map-show",     no_argument,       0, '3'}
    };
    int c, option_index;
    while ((c = getopt_long(argc, argv, "d:USNHFho:n:1:2:3", long_options, &option_index)) != EOF) {
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
            case 'H':
                cfg.xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
                cfg.xdp_flags |= XDP_FLAGS_HW_MODE;  /* Set   flag */
                break;
            case 'F':
                cfg.xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
                break;
            case 'o':
                strncpy((char *) &cfg.filename, optarg, sizeof(cfg.filename));
                break;
            case 's':
                strncpy((char *) &cfg.progname, optarg, sizeof(cfg.progname));
                break;
            case '1':
                map_fd = bpf_obj_get(file_path);
                if (map_fd < 0) {
                    fprintf(stderr, "Error: Failed to fetch the map: %d (%s)\n",
                            map_fd, strerror(errno));
                    return 1;
                }
                key = inet_addr(optarg);
                err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
                if (err) {
                    fprintf(stderr, "Error: Failed to update map: %d (%s)\n",
                            map_fd, strerror(errno));
                    return -1;
                } else {
                    printf("Success: map updated!\n");
                }
                return 0;
            case '2':
                map_fd = bpf_obj_get(file_path);
                if (map_fd < 0) {
                    fprintf(stderr, "Error: Failed to fetch the map: %d (%s)\n",
                            map_fd, strerror(errno));
                    return 1;
                }

                if (!strcmp(optarg, "all")) {
                    while (bpf_map_get_next_key(map_fd, &lookup_key, &next_key)
                           == 0) {
                        err = bpf_map_delete_elem(map_fd, &next_key);
                        if (err) {
                            fprintf(stderr, "Error: Failed to delete map: %d (%s)\n",
                                    map_fd, strerror(errno));
                            return 1;
                        }
                        lookup_key = next_key;
                    }
                    printf("Success: All entries deleted in map!\n");
                } else {
                    key = inet_addr(optarg);
                    err = bpf_map_delete_elem(map_fd, &key);
                    if (err) {
                        fprintf(stderr, "Error: Failed to delete map: %d (%s)\n",
                                map_fd, strerror(errno));
                        return 1;
                    } else {
                        printf("Success: %s deleted in map!\n", optarg);
                    }
                }
                return 0;
            case '3':
                map_fd = bpf_obj_get(file_path);
                if (map_fd < 0) {
                    fprintf(stderr, "Error: Failed to fetch the map: %d (%s)\n",
                            map_fd, strerror(errno));
                    return 1;
                }
                printf("black_list_ipaddr:\n");
                while (bpf_map_get_next_key(map_fd, &lookup_key, &next_key) == 0) {
                    struct in_addr ia = {next_key};
                    printf("%s\n", inet_ntoa(ia));
                    lookup_key = next_key;
                }
                return 0;
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            error:
            default:
                usage(argv[0]);
                return -1;
        }
    } // end of while

    if (cfg.ifindex == -1) {
        fprintf(stderr, "Error: required option -d/--dev missing\n");
        usage(argv[0]);
        return -1;
    }
    /* Unload XDP prog */
    if (cfg.do_unload) {
        err = remove(file_path);
        if (err) {
            fprintf(stderr, "Error: pinned map remove failed: %s\n",
                    strerror(-err));
        } else {
            printf("Pinned map removed\n");
        }

        /* bpf_set_link_xdp_fd() has been deprecated since libbpf v1.0+
         * Use bpf_xdp_detach and bpf_xdp_attach instead.
         */
        err = bpf_xdp_detach(cfg.ifindex, cfg.xdp_flags, NULL);
        if (err) {
            fprintf(stderr, "Error: bpf_xdp_detach failed (err=%d): %s\n",
                    err, strerror(errno));
            return -1;
        } else {
            printf("Success: XDP prog detached from device:%s(ifindex:%d)\n",
                   cfg.ifname, cfg.ifindex);
            return 0;
        }
    }

    /* open obj */
    struct bpf_object *obj;
    obj = bpf_object__open_file(cfg.filename, NULL);
    err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "Error: bpf_object__open_file failed (err=%d): %s\n",
                err, strerror(errno));
        if (err == -ENOENT)
            fprintf(stderr, "No such file, or maybe the program was compiled with "
                            "a too old version of LLVM (need v9.0+)?\n");
        return -1;
    }

    /* Find program by program name
     * Note that bpf_object__find_program_by_title (section name) API was deprecated
     * since libbpf v0.7. All callers should move to
     * bpf_object__find_program_by_name (program name) if possible, otherwise use
     * bpf_object__for_each_program and bpf_program__section_name
     * to find a program out from a given section name.
     */
    struct bpf_program *bpf_prog;
    bpf_prog = bpf_object__find_program_by_name(obj, cfg.progname);
    if (!bpf_prog) {
        fprintf(stderr, "Error: bpf_object__find_program_by_name failed\n");
        return -1;
    }

    if (cfg.xdp_flags & XDP_FLAGS_HW_MODE) {
        bpf_program__set_ifindex(bpf_prog, cfg.ifindex);
        struct bpf_map *map;
        bpf_object__for_each_map (map, obj) {
            bpf_map__set_ifindex(map, cfg.ifindex);
        }
    }

    err = bpf_program__set_type(bpf_prog, BPF_PROG_TYPE_XDP);
    if (err) {
        fprintf(stderr, "Error: bpf_program__set_type failed\n");
        return -1;
    }

    /* Load obj into kernel */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Error: bpf_object__load failed\n");
        return 1;
    }

    /* Find map fd and pin it to bpf file system */
    map_fd = bpf_object__find_map_fd_by_name(obj, "blacklist_map");
    if (map_fd < 0) {
        fprintf(stderr, "Error: bpf_object__find_map_fd_by_name failed\n");
        return 1;
    }

    err = bpf_obj_pin(map_fd, file_path);
    if (err < 0) {
        fprintf(stderr, "Error: Failed to pin map to the file system: %d (%s)\n",
                err, strerror(errno));
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
    err = bpf_xdp_attach(cfg.ifindex, prog_fd, cfg.xdp_flags, NULL);
    if (err < 0) {
        fprintf(stderr, "Error: ifindex(%d) bpf_xdp_attach failed (%d): %s\n",
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
        return -1;
    }

    printf("Success: XDP prog loaded on device:%s(ifindex:%d)\n",
           cfg.ifname, cfg.ifindex);
    return 0;


}