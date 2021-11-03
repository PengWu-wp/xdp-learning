/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // uint32_t uint16_t define
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/resource.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

/* Global macros */
#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

/* Global variables */
static bool verbose = true;
static bool global_exit = false;


struct config {
    uint32_t xdp_flags;
    int ifindex;
    char *ifname;
    char filename[512];
    char progsec[32];
    bool do_unload;
    __u16 xsk_bind_flags;
    int xsk_if_queue;
    bool xsk_poll_mode;
};

struct xsk_umem_info { // 该结构体是linux源码samples示例中用的
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct stats_record { // 报文统计信息记录
    uint64_t timestamp;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
};

struct xsk_socket_info { // 该结构体是linux源码samples示例中用的，有过修改
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;

    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;

    uint32_t outstanding_tx; // 这个是干啥的？

    struct stats_record stats;
    struct stats_record prev_stats;
};

/***********************************************************************************************
 * Functions
 */
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
           "-o, --obj <objname>\tSpecify the obj filename <objname>, default af-xdp-kern.o\n"
           "-s, --sec <secname>\tSpecify the section name <secname>, default xdp\n"
           "-c, --copy\t\tForce copy mode\n"
           "-z, --zero-copy\t\tForce zero-copy mode\n"
           "-Q, --queue <queue_id>\tConfigure interface receive queue for AF_XDP, default is 0\n"
           "-p, --poll-mode\t\tUse the poll() API waiting for packets to arrive\n"
           "-q, --quiet\t\tQuiet mode (no output)\n", name);
} /* End of usage */

static void IntHandler(int signal) {
    global_exit = true;
} /* End of IntHandler */

static inline __u16

compute_ip_checksum(struct iphdr *ip) {
    __u32 csum = 0;
    __u16 * next_ip_u16 = (__u16 * )
    ip;
    ip->check = 0;

    for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
        csum += *next_ip_u16++;
    }

    return ~((csum & 0xffff) + (csum >> 16));
}

static inline __u16

compute_icmp_checksum(struct icmphdr *icmp) {
    __u32 csum = 0;
    __u16 * next_icmp_u16 = (__u16 * )
    icmp;
    icmp->checksum = 0;

    for (int i = 0; i < (sizeof(*icmp) >> 1); i++) {
        csum += *next_icmp_u16++;
    }

    return ~((csum & 0xffff) + (csum >> 16));
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk) {
    uint64_t frame;
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free]; // 所以frame就是某个帧chunk的字节偏移量，每分配一个就将umem_frame_free
    // 即空闲的umem_frame数量减一，（问题：用完了就没了？后面会释放的）
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME; // 用了以后再把下一个帧chunk置为INVALID_UMEM_FRAME（why?）
    return frame;
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */

static uint64_t gettime(void) {
    struct timespec t;
    int res;

    res = clock_gettime(CLOCK_MONOTONIC, &t);
    if (res < 0) {
        fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
        exit(1);
    }
    return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record *r, struct stats_record *p) {
    double period_ = 0;
    __u64 period = 0;

    period = r->timestamp - p->timestamp;
    if (period > 0)
        period_ = ((double) period / NANOSEC_PER_SEC);

    return period_;
}

static void stats_print(struct stats_record *stats_rec,
                        struct stats_record *stats_prev) {
    uint64_t packets, bytes;
    double period;
    double pps; /* packets per sec */
    double bps; /* bits per sec */

    char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
                " %'11lld Kbytes (%'6.0f Mbits/s)"
                " period:%f\n";

    period = calc_period(stats_rec, stats_prev);
    if (period == 0)
        period = 1;

    packets = stats_rec->rx_packets - stats_prev->rx_packets;
    pps = packets / period;

    bytes = stats_rec->rx_bytes - stats_prev->rx_bytes;
    bps = (bytes * 8) / period / 1000000;

    printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
           stats_rec->rx_bytes / 1000, bps,
           period);

    packets = stats_rec->tx_packets - stats_prev->tx_packets;
    pps = packets / period;

    bytes = stats_rec->tx_bytes - stats_prev->tx_bytes;
    bps = (bytes * 8) / period / 1000000;

    printf(fmt, "       TX:", stats_rec->tx_packets, pps,
           stats_rec->tx_bytes / 1000, bps,
           period);

    printf("\n");
}

static void *stats_poll(void *arg) {
    unsigned int interval = 2;
    struct xsk_socket_info *xsk = arg;
    static struct stats_record previous_stats = {0};

    previous_stats.timestamp = gettime();

    /* Trick to pretty printf with thousands separators use %' */
    setlocale(LC_NUMERIC, "en_US");

    while (!global_exit) {
        sleep(interval);
        xsk->stats.timestamp = gettime();
        stats_print(&xsk->stats, &previous_stats);
        previous_stats = xsk->stats;
    }
    return NULL;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame) {
    assert(xsk->umem_frame_free < NUM_FRAMES); // 所以assert是个啥：assert(expression):
    // 如果expression为错误，则终止程序运行（是终止这个function吧），一般用于不会发生的非法情况

    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static void complete_tx(struct xsk_socket_info *xsk) {
    unsigned int completed;
    uint32_t idx_cq;

    if (!xsk->outstanding_tx)
        return;

    sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);


    /* Collect/free completed TX buffers */
    completed = xsk_ring_cons__peek(&xsk->umem->cq,
                                    XSK_RING_CONS__DEFAULT_NUM_DESCS,
                                    &idx_cq);

    if (completed > 0) {
        for (int i = 0; i < completed; i++)
            xsk_free_umem_frame(xsk,
                                *xsk_ring_cons__comp_addr(&xsk->umem->cq,
                                                          idx_cq++));

        xsk_ring_cons__release(&xsk->umem->cq, completed);
        xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
                               completed : xsk->outstanding_tx;
    }
}


int main(int argc, char **argv) {
    int err;
    uint64_t packet_buffer_size;
    void *packet_buffer;


    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY}; // Resource LIMIT，一会儿用于setrlimit()的
    struct xsk_umem_info *umem_info = NULL;
    struct xsk_socket_info *xsk_info = NULL;

    struct config cfg = { /* xdp prog loading related config options */
            .ifindex   = -1,
            .do_unload = false,
            .filename = "af-xdp-kern.o",
            .progsec = "xdp"
    };

    struct option long_options[] = {{"dev",         required_argument, 0, 'd'},
                                    {"help",        no_argument,       0, 'h'},
                                    {"skb-mode",    no_argument,       0, 'S'},
                                    {"native-mode", no_argument,       0, 'N'},
                                    {"force",       no_argument,       0, 'F'},
                                    {"unload",      no_argument,       0, 'U'},
                                    {"obj",         no_argument,       0, 'o'},
                                    {"sec",         no_argument,       0, 's'},

                                    {"copy",        no_argument,       0, 'c'},
                                    {"zero-copy",   no_argument,       0, 'z'},
                                    {"queue",       required_argument, 0, 'Q'},
                                    {"poll-mode",   no_argument,       0, 'p'},
                                    {"quiet",       no_argument,       0, 'q'}
    };
    int c, option_index;
    while ((c = getopt_long(argc, argv, "d:hSNFUo:s:czQ:pq", long_options, &option_index)) != EOF) {
        switch (c) {
            case 'd':
                if (strlen(optarg) >= IF_NAMESIZE) {
                    fprintf(stderr, "Error: dev name is too long\n");
                    return 1; // 暂时就把所有的错误都返回1吧
                }
                cfg.ifname = optarg;
                cfg.ifindex = if_nametoindex(cfg.ifname);
                if (cfg.ifindex == 0) {
                    fprintf(stderr, "ERR: dev name unknown err\n");
                    return 1;
                }
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            case 'S':
                cfg.xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
                cfg.xdp_flags |= XDP_FLAGS_SKB_MODE;  /* Set   flag */
                cfg.xsk_bind_flags &= XDP_ZEROCOPY;
                cfg.xsk_bind_flags |= XDP_COPY;
                break;
            case 'N':
                cfg.xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
                cfg.xdp_flags |= XDP_FLAGS_DRV_MODE;  /* Set   flag */
                break;
            case 'F':
                cfg.xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
                break;
            case 'U':
                cfg.do_unload = true;
                break;
            case 'o':
                strncpy((char *) &cfg.filename, optarg, sizeof(cfg.filename));
                break;
            case 's':
                strncpy((char *) &cfg.progsec, optarg, sizeof(cfg.progsec));
                break;
            case 'c':
                cfg.xsk_bind_flags &= XDP_ZEROCOPY;
                cfg.xsk_bind_flags |= XDP_COPY;
                break;
            case 'z':
                cfg.xsk_bind_flags &= XDP_COPY;
                cfg.xsk_bind_flags |= XDP_ZEROCOPY;
                break;
            case 'Q':
                cfg.xsk_if_queue = atoi(optarg);
                break;
            case 'p':
                cfg.xsk_poll_mode = true;
                break;
            case 'q':
                verbose = false;
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    } // end of while

    /* Check requried options */
    if (cfg.ifindex == -1) {
        fprintf(stderr, "Error: required option -d/--dev missing\n");
        usage(argv[0]);
        return 1;
    }

    /* Unload XDP program */
    if (cfg.do_unload) {
        err = bpf_set_link_xdp_fd(cfg.ifindex, -1, cfg.xdp_flags);
        if (err) {
            fprintf(stderr, "Error: %s() link set xdp failed (err=%d): %s\n",
                    __func__, err, strerror(-err));
            return 1;
        } else {
            printf("Success: XDP prog detached from device:%s(ifindex:%d)\n",
                   cfg.ifname, cfg.ifindex);
            return 0;
        }
    }

//    /* open obj */
//    struct bpf_object *obj = NULL;
//    obj = bpf_object__open(cfg.filename);
//    if (!obj) {
//        fprintf(stderr, "Error: bpf_object__open failed\n");
//        return 1;
//    }
//
//    /* find program by section name and set prog type to XDP */
//    struct bpf_program *bpf_prog;
//    bpf_prog = bpf_object__find_program_by_title(obj, cfg.progsec);
//    if (!bpf_prog) {
//        fprintf(stderr, "Error: bpf_object__find_program_by_title failed\n");
//        return 1;
//    }
//    bpf_program__set_type(bpf_prog, BPF_PROG_TYPE_XDP);
//
//    /* Load obj into kernel */
//    err = bpf_object__load(obj);
//    if (err) {
//        fprintf(stderr, "Error: bpf_object__load failed\n");
//        return 1;
//    }
//
//    /* Find map fd */
//    int xsks_map_fd;
//    struct bpf_map *map;
//    map = bpf_object__find_map_by_name(obj, "xsks_map");
//    xsks_map_fd = bpf_map__fd(map);
//    if (xsks_map_fd < 0) {
//        fprintf(stderr, "Error: no xsks map found: %s\n",
//                strerror(xsks_map_fd));
//        return 1;
//    }
//
//    /* Get file descriptor for program */
//    int prog_fd;
//    prog_fd = bpf_program__fd(bpf_prog);
//    if (prog_fd < 0) {
//        fprintf(stderr, "Error: Couldn't get file descriptor for program\n");
//        return 1;
//    }
//
//    /* load xdp prog in the specified interface */
//    err = bpf_set_link_xdp_fd(cfg.ifindex, prog_fd, cfg.xdp_flags);
//    if (err == -EEXIST && !(cfg.xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
//        /* Force mode didn't work, probably because a program of the
//         * opposite type is loaded. Let's unload that and try loading
//         * again.
//         */
//        uint32_t old_flags = cfg.xdp_flags;
//
//        cfg.xdp_flags &= ~XDP_FLAGS_MODES;
//        cfg.xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
//        err = bpf_set_link_xdp_fd(cfg.ifindex, -1, cfg.xdp_flags);
//        if (!err)
//            err = bpf_set_link_xdp_fd(cfg.ifindex, prog_fd, old_flags);
//    }
//    if (err < 0) {
//        fprintf(stderr, "Error: ifindex(%d) link set xdp fd failed (%d): %s\n",
//                cfg.ifindex, -err, strerror(-err));
//        switch (-err) {
//            case EBUSY:
//            case EEXIST:
//                fprintf(stderr, "Hint: XDP already loaded on device"
//                                " use --force or -F to swap/replace\n");
//                break;
//            case EOPNOTSUPP:
//                fprintf(stderr, "Hint: Native-XDP not supported"
//                                " use --skb-mode or -S\n");
//                break;
//            default:
//                break;
//        }
//        return 1;
//    }
//
//    printf("Success: XDP prog loaded on device:%s(ifindex:%d)\n",
//           cfg.ifname, cfg.ifindex);

    /* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked.
	 */
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Error: setrlimit(RLIMIT_MEMLOCK) failed \"%s\"\n",
                strerror(errno));
        return 1;
    }

    /* Signal handling */
    struct sigaction act;
    act.sa_handler = IntHandler;
    sigemptyset(&act.sa_mask);
    sigaction(SIGINT, &act, 0); // 注册SIGINT信号的处理函数

    /* Allocate memory for NUM_FRAMES of the default XDP frame size */
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE; /* FRAME_SIZE应该UMEM规定的数据帧的默认大小，
												   * NUM_FRAMES就是我们设置的UMEM中默认数据帧数量了 */
    err = posix_memalign(&packet_buffer, /* 分配packet_buffer_size的内存，并按pagesize对齐 */
                         getpagesize(),
                         packet_buffer_size);
    if (err) {
        fprintf(stderr, "Error: Can't allocate buffer memory \"%s\"\n",
                strerror(errno));
        return 1;
    } else {
        printf("WPDEBUG: Buffer memory allocated! packet_buffer is %p, buffer size is %ld\n", packet_buffer,
               packet_buffer_size);
    }

    /* Initialize shared packet_buffer for umem usage
     * 这里的umem结构体定义是linux源码samples中的用法，值得参考
	 */
    umem_info = calloc(1, sizeof(*umem_info)); // 不分配会报错Bad address
    err = xsk_umem__create(&umem_info->umem, packet_buffer, packet_buffer_size, &umem_info->fq, &umem_info->cq, NULL);
    if (err) {
        fprintf(stderr, "Error: Can't create umem: \"%s\"\n", strerror(errno));
        return 1;
    }else {
        umem_info->buffer = packet_buffer;
        printf("WPDEBUG: umem created! \n");/////////////////////////////////////////////////////////////////////////////////////DEBUG
    }

    /* Open and configure the AF_XDP socket (xsk) */
    struct xsk_socket_config xsk_cfg;

    xsk_info = calloc(1, sizeof(*xsk_info));
    printf("WPDEBUG: xsk_info memory is %p\n", xsk_info);
    if (!xsk_info) {
        fprintf(stderr, "Error: Cannot alloc memory for xsk_info: \"%s\"\n", strerror(errno));
        return 1;
    }
    xsk_info->umem = umem_info;

    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS; // 默认各一半
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.libbpf_flags = 0;
    xsk_cfg.xdp_flags = cfg.xdp_flags;
    xsk_cfg.bind_flags = cfg.xsk_bind_flags;

    err = xsk_socket__create(&xsk_info->xsk, cfg.ifname,
                             cfg.xsk_if_queue, umem_info->umem, &xsk_info->rx,
                             &xsk_info->tx, &xsk_cfg);
    if (err) {
        fprintf(stderr, "Error: Can't create xsk socket: \"%s\"\n", strerror(-err));
        return 1;
    }else {
        printf("WPDEBUG: xsk socket created! \n");/////////////////////////////////////////////////////////////////////////////////DEBUG
    }

    uint32_t prog_id = 0; // 貌似没什么用，但是先全盘复制；
    err = bpf_get_link_xdp_id(cfg.ifindex, &prog_id, cfg.xdp_flags); // 指定接口index和flag获取xdp程序id；
    if (err) {
        fprintf(stderr, "Error: bpf_get_link_xdp_id failed: \"%s\"\n", strerror(-err));
        return 1;
    }

    /* Initialize umem frame allocation */
    for (int i = 0; i < NUM_FRAMES; i++) { // 把UMEM中每个数据帧的地址都指定好？但这个地址是以FRAME_SIZE也就是4096为单位的，emm
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;
    }
    xsk_info->umem_frame_free = NUM_FRAMES; // 剩余能操作的数据帧数量

    /* 填充FILL ring */
    /* Stuff the receive path with buffers, we assume we have enough */

    uint32_t idx; // 下标
    err = xsk_ring_prod__reserve(&xsk_info->umem->fq,/* 这里理解成填充Fill ring */
                                 XSK_RING_PROD__DEFAULT_NUM_DESCS,/* 2048 */
                                 &idx);
    if (err != XSK_RING_PROD__DEFAULT_NUM_DESCS) {
        fprintf(stderr, "Error: xsk_ring_prod__reserve failed: \"%s\"\n", strerror(-err));
        return 1;
    }

    //uint64_t frame;
    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++) {/* 2048 */
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
                xsk_alloc_umem_frame(xsk_info);
    }

    xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS); // 数据更新完毕，更新生产者下标
    /* 注：生产者下标永远指向下一个可填充数据位置 */

    /* Start thread to do statistics display */
    pthread_t stats_poll_thread; // 指定开线程用的

    if (verbose) { // 全局变量
        err = pthread_create(&stats_poll_thread, NULL, stats_poll,
                             xsk_info); // 总之就是另开一个线程跑stats_poll
        if (err) {
            fprintf(stderr, "ERROR: Failed creating statistics thread "
                            "\"%s\"\n", strerror(errno));
            exit(1);
        }
    }

    /* Receive and count packets */
    struct pollfd fds[2];////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    int nfds = 1;////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(xsk_info->xsk);
    fds[0].events = POLLIN;

    /***********************************************************************************************
    * Main loop
    */
    printf("进入主循环\n");

    while (!global_exit) {
        if (cfg.xsk_poll_mode) {
            err = poll(fds, nfds, -1);
            if (err <= 0 || err > 1)
                continue;
        }
        ///////////////handle_receive_packets(xsk_socket);//////////////////
        unsigned int rcvd, stock_frames, i;
        uint32_t idx_rx = 0, idx_fq = 0;

        rcvd = xsk_ring_cons__peek(&xsk_info->rx, RX_BATCH_SIZE, &idx_rx); // 以RX_BATCH_SIZE为批处理单位（现64）
        if (!rcvd) {
            continue;
        }
        printf("收到%d个包，开始处理\n", rcvd);
//        printf("	当前各RING的状态：\n"
//               "\t\tproducer\tconsumer\tcached_prod\tcached_cons\n"
//               "    FILL_RING   %d		%d		%d		%d\n"
//               "    COMP_RING	%d		%d		%d		%d\n"
//               "    RX_RING	%d		%d		%d		%d\n"
//               "    TX_RING	%d		%d		%d		%d\n\n", *xsk_info->umem->fq.producer,
//               *xsk_info->umem->fq.consumer,
//               xsk_info->umem->fq.cached_prod, xsk_info->umem->fq.cached_cons, *xsk_info->umem->cq.producer,
//               *xsk_info->umem->cq.consumer,
//               xsk_info->umem->cq.cached_prod, xsk_info->umem->cq.cached_cons, *xsk_info->rx.producer,
//               *xsk_info->rx.consumer,
//               xsk_info->rx.cached_prod, xsk_info->rx.cached_cons, *xsk_info->tx.producer, *xsk_info->tx.consumer,
//               xsk_info->tx.cached_prod,
//               xsk_info->tx.cached_cons);

        /* Stuff the ring with as much frames as possible
         * 发现空闲desc了马上生产；
         */

        stock_frames = xsk_prod_nb_free(&xsk_info->umem->fq, xsk_info->umem_frame_free);
        if (stock_frames > 0) {
            printf("stock_frames大于0\n");
            err = xsk_ring_prod__reserve(&xsk_info->umem->fq, stock_frames, &idx_fq);

            /* This should not happen, but just in case */
            while (err != stock_frames)
                err = xsk_ring_prod__reserve(&xsk_info->umem->fq, rcvd, &idx_fq);

            /* 改动过 */
            for (i = 0; i < stock_frames; i++) {
                *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx_fq++) =
                        xsk_alloc_umem_frame(xsk_info);
            }

            xsk_ring_prod__submit(&xsk_info->umem->fq, stock_frames);
            printf("又生产了%d个desc\n", stock_frames);
        }

        /* Process received packets */
        for (i = 0; i < rcvd; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx++)->len;

            uint8_t *pkt = xsk_umem__get_data(xsk_info->umem->buffer, addr); // addr只是对应的偏移量；取具体地址就是用这个函数

            uint32_t tx_idx = 0;
            uint8_t tmp_mac[ETH_ALEN];
            __be32 tmp_ip;
            struct ethhdr *eth = (struct ethhdr *) pkt;
            struct iphdr *ip = (struct iphdr *) (eth + 1);
            struct icmphdr *icmp = (struct icmphdr *) (ip + 1);

            memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
            memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
            memcpy(eth->h_source, tmp_mac, ETH_ALEN);

            memcpy(&tmp_ip, &ip->saddr, sizeof(tmp_ip));
            memcpy(&ip->saddr, &ip->daddr, sizeof(tmp_ip));
            memcpy(&ip->daddr, &tmp_ip, sizeof(tmp_ip));

            icmp->type = ICMP_ECHOREPLY;

            ip->check = compute_ip_checksum(ip);
            icmp->checksum = compute_icmp_checksum(icmp);
            printf("处理完毕\n");

            /* Here we sent the packet out of the receive port. Note that
             * we allocate one entry and schedule it. Your design would be
             * faster if you do batch processing/transmission */

            err = xsk_ring_prod__reserve(&xsk_info->tx, 1, &tx_idx);
            if (err != 1) {
                /* No more transmit slots, drop the packet */
                xsk_free_umem_frame(xsk_info, addr);
            }

            xsk_ring_prod__tx_desc(&xsk_info->tx, tx_idx)->addr = addr;
            xsk_ring_prod__tx_desc(&xsk_info->tx, tx_idx)->len = len;
            xsk_ring_prod__submit(&xsk_info->tx, 1);
            xsk_info->outstanding_tx++;

            xsk_info->stats.tx_bytes += len;
            xsk_info->stats.tx_packets++;

            xsk_info->stats.rx_bytes += len;
        }

        xsk_ring_cons__release(&xsk_info->rx, rcvd); // 也就是当前consumer指针加上rcvd即刚才消费的个数
        xsk_info->stats.rx_packets += rcvd;

        /* Do we need to wake up the kernel for transmission */

        complete_tx(xsk_info);

//        printf("	处理结束！当前各RING的状态：\n"
//               "\t\tproducer\tconsumer\tcached_prod\tcached_cons\n"
//               "    FILL_RING   %d		%d		%d		%d\n"
//               "    COMP_RING	%d		%d		%d		%d\n"
//               "    RX_RING	%d		%d		%d		%d\n"
//               "    TX_RING	%d		%d		%d		%d\n\n", *xsk_info->umem->fq.producer,
//               *xsk_info->umem->fq.consumer,
//               xsk_info->umem->fq.cached_prod, xsk_info->umem->fq.cached_cons, *xsk_info->umem->cq.producer,
//               *xsk_info->umem->cq.consumer,
//               xsk_info->umem->cq.cached_prod, xsk_info->umem->cq.cached_cons, *xsk_info->rx.producer,
//               *xsk_info->rx.consumer,
//               xsk_info->rx.cached_prod, xsk_info->rx.cached_cons, *xsk_info->tx.producer, *xsk_info->tx.consumer,
//               xsk_info->tx.cached_prod,
//               xsk_info->tx.cached_cons);
    } // End of while

    /* Cleanup */
    xsk_socket__delete(xsk_info->xsk);
    xsk_umem__delete(umem_info->umem);
    err = bpf_set_link_xdp_fd(cfg.ifindex, -1, cfg.xdp_flags);
    if (err) {
        fprintf(stderr, "Error: %s() link set xdp failed (err=%d): %s\n",
                __func__, err, strerror(-err));
        return 1;
    } else {
        printf("Success: XDP prog detached from device:%s(ifindex:%d)\n",
               cfg.ifname, cfg.ifindex);
        return 0;
    }

    return 0;
}
