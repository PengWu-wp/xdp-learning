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

static inline __u16 compute_ip_checksum(struct iphdr *ip) {
    __u32 csum = 0;
    __u16 *next_ip_u16 = (__u16 *) ip;
    ip->check = 0;

    for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
        csum += *next_ip_u16++;
    }

    return ~((csum & 0xffff) + (csum >> 16));
}

static inline __u16 compute_icmp_checksum(struct icmphdr *icmp) {
    __u32 csum = 0;
    __u16 *next_icmp_u16 = (__u16 *) icmp;
    icmp->checksum = 0;

    for (int i = 0; i < (sizeof(*icmp) >> 1); i++) {
        csum += *next_icmp_u16++;
    }

    return ~((csum & 0xffff) + (csum >> 16));
}






int main(int argc, char **argv) {
    int err;
    uint64_t packet_buffer_size;
    void *packet_buffer;

    struct bpf_object *obj = NULL;
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

    /* open obj */
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

    /* Find map fd */
    int xsks_map_fd;
    struct bpf_map *map;
    map = bpf_object__find_map_by_name(obj, "xsks_map");
    xsks_map_fd = bpf_map__fd(map);
    if (xsks_map_fd < 0) {
        fprintf(stderr, "Error: no xsks map found: %s\n",
                strerror(xsks_map_fd));
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

    /* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked. 所以默认的设置是多少？-默认设置是根据你bash的默认
	 * 继承下来的。可以用ulimit命令查看,虚机上root显示65536 kBytes。| 什么是内存锁定？
	 * 如果进程可以锁定在内存中数据量很小会发生什么？这个程序在哪锁定内存了？
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
                         getpagesize(), /* PAGE_SIZE aligned 等一下，DPDK所谓巨页的页就是这里的page吗？-是了*/
                         packet_buffer_size);
    if (err) {
        fprintf(stderr, "Error: Can't allocate buffer memory \"%s\"\n",
                strerror(errno));
        return 1;
    } else {
        printf("WPDEBUG: Buffer memory allocated! packet_buffer is %p, buffer size is %ld\n", packet_buffer,
               packet_buffer_size);
        //printf("WPDEBUG: packet_buffer+1 is %p\n", packet_buffer+1);
    }
    // 所以现在我分了4096个4096字节大小的数据帧缓存区，以4096（linux默认pagesize）对齐
    // 那这部分内存是给谁用的？umem吗

    /* Initialize shared packet_buffer for umem usage
     * 这里的umem结构体定义是linux源码samples中的用法，值得参考
	 */
    umem_info = calloc(1, sizeof(*umem_info)); // 不分配会报错Bad address
    err = xsk_umem__create(&umem_info->umem, packet_buffer, packet_buffer_size, &umem_info->fq, &umem_info->cq, NULL);
    if (err) {
        fprintf(stderr, "Error: Can't create umem: \"%s\"\n", strerror(-err));
        return 1;
    } else {
        umem_info->buffer = packet_buffer;
        printf("WPDEBUG: umem created! \n");/////////////////////////////////////////////////////////////////////////////////////DEBUG
    }
    printf("    刚创建UMEM后，相关信息：\n"
           "FILL ring的缓存生产/消费者下标为%d和%d\n"
           "FILL ring的实时生产/消费者下标为%d和%d\n"
           "COMP ring的缓存生产/消费者下标为%d和%d\n"
           "COMP ring的实时生产/消费者下标为%d和%d\n"
           , umem_info->fq.cached_prod, umem_info->fq.cached_cons,
           *umem_info->fq.producer, *umem_info->fq.consumer,
           umem_info->cq.cached_prod, umem_info->cq.cached_cons,
           *umem_info->cq.producer, *umem_info->cq.consumer
    );
    printf("WP!!: umem_info->fq.ring 指向的地址是%p\n",umem_info->fq.ring);
    printf("WP!!: umem_info->fq.mask 为%x\n",umem_info->fq.mask);
    /* Open and configure the AF_XDP socket (xsk) */
    struct xsk_socket_config xsk_cfg; ////////////////////////////////////////////////////////////////////////////////////////////////////
    //uint32_t prog_id = 0; ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    xsk_info = calloc(1, sizeof(*xsk_info));
    printf("WPDEBUG: xsk_info memory is %p\n", xsk_info);
    if (!xsk_info) {
        printf("Error: Cannot alloc memory for xsk_info.\n");
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
    } else {
        printf("WPDEBUG: xsk socket created! \n");/////////////////////////////////////////////////////////////////////////////////DEBUG
    }
    printf("    刚创建XSK后，相关信息：\n"
           "RX ring的缓存生产/消费者下标为%d和%d\n"
           "RX ring的实时生产/消费者下标为%d和%d\n"
           "TX ring的缓存生产/消费者下标为%d和%d\n"
           "TX ring的实时生产/消费者下标为%d和%d\n"
            , xsk_info->rx.cached_prod, xsk_info->rx.cached_cons,
           *xsk_info->rx.producer, *xsk_info->rx.consumer,
           xsk_info->tx.cached_prod, xsk_info->tx.cached_cons,
           *xsk_info->tx.producer, *xsk_info->tx.consumer
    );

    //xsk_info->xsk->xsks_map_fd = xsks_map_fd;
//    err = bpf_map_update_elem(xsks_map_fd,&xsk_info->xsk->queue_id,&xsk_socket__fd(xsk_info->xsk),0);
//    if(err){
//        fprintf(stderr, "Error: Failed to update map: %d (%s)\n",
//                xsks_map_fd, strerror(errno));
//        return 1;
//    }




    /* 这里已经挂载了XDP程序…… */
//    err = bpf_get_link_xdp_id(cfg.ifindex, &prog_id, cfg.xdp_flags);
//    if (err) {
//        fprintf(stderr, "Error: bpf_get_link_xdp_id failed: \"%s\"\n", strerror(-err));
//        return 1;
//    } else {
//        printf("WPDEBUG: bpf_get_link_xdp_id success! xdp_id is %d.\n", prog_id);////////////////////////////////////////////////DEBUG
//    }

    /* Initialize umem frame allocation */
    for (int i = 0; i < NUM_FRAMES; i++) { // 把UMEM中每个数据帧的地址都指定好？但这个地址是以FRAME_SIZE也就是4096为单位的，emm
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;
        if (i < 5)printf("WPDEBUG: xsk_info->umem_frame_addr[%d] is %ld\n", i, xsk_info->umem_frame_addr[i]);///////////////////////////////DEBUG
    }
    xsk_info->umem_frame_free = NUM_FRAMES; // 剩余能操作的数据帧数量?不至于吧……这里改多少就收多少个包,或者是这里必须是总数，
                                            // 不然后面没法空出来
                                /* 4096 */

    /* 填充FILL ring */
    uint32_t idx; // 下标
    /* Stuff the receive path with buffers, we assume we have enough */

    /**************************************************************
     * static inline size_t xsk_ring_prod__reserve(struct xsk_ring_prod *prod,
	 *				    size_t nb, __u32 *idx)
     *   {
     *       if (xsk_prod_nb_free(prod, nb) < nb)
     *           return 0;
     *
     *       *idx = prod->cached_prod;
     *       prod->cached_prod += nb;
     *
     *       return nb;
     *   }
     *
     * 你给我在prod这个ring里面保留nb(NumBer)个数据，我马上要填充了！
     *
     * 我要生产2048个数据(也就是用以承载报文的UMEM frames)，ring里面有没有足够的空间？没有的话直接返回0，有的话把
     * FILL Ring生产者当前下标xsk_info->umem->fq->cached_prod赋值给idx，退出函数后要根据该idx指向的位置开始生产desc，
     * 最后FILL Ring生产者当前下标xsk_info->umem->fq->cached_prod要加上2048，返回2048（概述函数内容）
     *
     * 注： fill_ring 的生产者是用户态程序，消费者是内核态中的XDP程序；
     *     用户态程序通过 fill_ring 将可以用来承载报文的 UMEM frames 传到内核，然后内核消耗 fill_ring 中的元素
     *     （后文统一称为 desc），并将报文拷贝到desc中指定地址（该地址即UMEM frame的地址）；
     */

    printf("    xsk_ring_prod__reserve之前，相关信息：\n"
           "  FILL ring的缓存生产/消费者下标为%d和%d\n"
           "  FILL ring的实时生产/消费者下标为%d和%d\n"
           "  COMP ring的缓存生产/消费者下标为%d和%d\n"
           "  COMP ring的实时生产/消费者下标为%d和%d\n"
            , umem_info->fq.cached_prod, umem_info->fq.cached_cons,
           *umem_info->fq.producer, *umem_info->fq.consumer,
           umem_info->cq.cached_prod, umem_info->cq.cached_cons,
           *umem_info->cq.producer, *umem_info->cq.consumer
    );
    err = xsk_ring_prod__reserve(&xsk_info->umem->fq,/* 这里理解成填充Fill ring */
                           XSK_RING_PROD__DEFAULT_NUM_DESCS,/* 2048 */
                           &idx);
    printf("WPDEBUG: current idx is %d.\n",idx);
    printf("    xsk_ring_prod__reserve之后，相关信息：\n"
           "  FILL ring的缓存生产/消费者下标为%d和%d\n"
           "  FILL ring的实时生产/消费者下标为%d和%d\n"
           "  COMP ring的缓存生产/消费者下标为%d和%d\n"
           "  COMP ring的实时生产/消费者下标为%d和%d\n"
            , umem_info->fq.cached_prod, umem_info->fq.cached_cons,
           *umem_info->fq.producer, *umem_info->fq.consumer,
           umem_info->cq.cached_prod, umem_info->cq.cached_cons,
           *umem_info->cq.producer, *umem_info->cq.consumer
    );
    printf("WPDEBUG: xsk_info->umem->fq.size is %d.\n",xsk_info->umem->fq.size);
    if(err != XSK_RING_PROD__DEFAULT_NUM_DESCS){
        fprintf(stderr, "Error: xsk_ring_prod__reserve failed: \"%s\"\n", strerror(-err));
        return 1;
    }

    /* 我改过的 */
    /*************************************************
     * 解析:
     * 下面是FILL RING的填充过程
     * struct xdp_desc {
     *   __u64 addr;
     *   __u32 len;
     *   __u32 options;
     *  };
     *  以上为ring中元素xdp_desc的成员结构；
     *  addr：指向UMEM中某个帧的具体位置，并且不是真正的虚拟内存地址，而是相对UMEM内存起始地址的偏移（4096、8192……）
     *  len：指报文的具体的长度，当XDP程序向desc填充报文的时候需要设置len，但是用户态程序向FILL RING中填充desc则不用关心len，
     *      下面的操作就是要往FILL ring中填充desc；
     *  options：暂时用不到
     *
     *  这里向FILL RING填充了2048个desc，xsk_info->umem_frame_free也对应减少了2048
     */

    uint64_t frame;
    for (int i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++){/* 2048 */
        if (xsk_info->umem_frame_free == 0){
            *(xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++)) = INVALID_UMEM_FRAME;/* UINT64_MAX */
        } else {
            frame = xsk_info->umem_frame_addr[--xsk_info->umem_frame_free];
            xsk_info->umem_frame_addr[xsk_info->umem_frame_free] = INVALID_UMEM_FRAME; // 将改地址无效化？
            *(xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++)) = frame;
            //printf("WPDEBUG: 向FILL ring中下标idx为 %d 的desc地址%p，填充了frame %ld 这个字节偏移量\n",idx-1,
            //       xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx-1),frame);
        }
    }

    /*******************************************************
     * xsk_ring_prod__submit
     *
     * 数据更新完毕后，先是一个memory barrier相关的东西，更新生产者下标xsk_info->umem->fq.producer，
     * 将其加上上述更新的数量：XSK_RING_PROD__DEFAULT_NUM_DESCS
     *
     * 可是这个FILL ring的size：xsk_info->umem->fq.size，也才2048啊，下标还能超出的？
     */
    xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__DEFAULT_NUM_DESCS); // 数据更新完毕，更新生产者下标
    printf("WPDEBUG: 数据更新完毕，更新生产者下标为：%d\n",*xsk_info->umem->fq.producer);
    /* 注：下标永远指向下一个可填充数据位置 */


    printf("WPDEBUG: Open and configure the AF_XDP (xsk) socket done!\n");/////////////////////////////////////////////////////////////DEBUG


    /* Receive and count packets */
    struct pollfd fds[2];////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    int nfds = 1;////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(xsk_info->xsk);
    fds[0].events = POLLIN;


    /***********************************************************************************************
    * Main loop
    */
    printf("WPDEBUG: Enter main loop\n\n");//////////////////////////////////////////////////////////DEBUG

//    printf("WPDEBUG: xsk_info->rx.cached_prod is %d\n"
//           "         xsk_info->rx.cached_cons is %d\n"
//           "         *xsk_info->rx.producer is %d\n"
//            ,xsk_info->rx.cached_prod,xsk_info->rx.cached_cons,*xsk_info->rx.producer);


    while(!global_exit) {
        if (cfg.xsk_poll_mode) {
            err = poll(fds, nfds, -1);
            if (err <= 0 || err > 1)
                continue;
        }
        ///////////////handle_receive_packets(xsk_socket);//////////////////
        unsigned int rcvd, stock_frames, i;///////////////////////////////////////////////////////////////////////////////////////////////
        uint32_t idx_rx = 0, idx_fq = 0;/////////////////////////////////////////////////////////////////////////////////////////////////
        /*********************************************
         * xsk_ring_cons__peek
         *
         * 对RX RING进行消费，返回消费的消费者下标idx_rx和消费个数，并累加消费的个数到cached_cons；
         * 注：内核此时是生产者，收到包会往*(xsk_info->rx.producer)这里一个个放，收几个包就相当生产几个desc
         *    消费个数不会超过RX_BATCH_SIZE，相当于批处理RX_BATCH_SIZE个了吧
         */

        rcvd = xsk_ring_cons__peek(&xsk_info->rx, RX_BATCH_SIZE, &idx_rx); // 收到包以后，会有数
        if (!rcvd){
            continue;
        }
        printf("收到包了，FILL/COMP Ring相关信息：\n"
               "  FILL ring的缓存生产/消费者下标为%d和%d\n"
               "  FILL ring的实时生产/消费者下标为%d和%d\n"
               "  COMP ring的缓存生产/消费者下标为%d和%d\n"
               "  COMP ring的实时生产/消费者下标为%d和%d\n"
                , umem_info->fq.cached_prod, umem_info->fq.cached_cons,
               *umem_info->fq.producer, *umem_info->fq.consumer,
               umem_info->cq.cached_prod, umem_info->cq.cached_cons,
               *umem_info->cq.producer, *umem_info->cq.consumer
        );
        printf("收到包了，RX/TX Ring相关信息：\n"
               "RX ring的缓存生产/消费者下标为%d和%d\n"
               "RX ring的实时生产/消费者下标为%d和%d\n"
               "TX ring的缓存生产/消费者下标为%d和%d\n"
               "TX ring的实时生产/消费者下标为%d和%d\n"
                , xsk_info->rx.cached_prod, xsk_info->rx.cached_cons,
               *xsk_info->rx.producer, *xsk_info->rx.consumer,
               xsk_info->tx.cached_prod, xsk_info->tx.cached_cons,
               *xsk_info->tx.producer, *xsk_info->tx.consumer
        );
        printf("WPDEBUG: xsk_info->rx.cached_prod is %d\n"
               "         xsk_info->rx.cached_cons is %d\n"
               "         *xsk_info->rx.producer is %d\n"
                ,xsk_info->rx.cached_prod,xsk_info->rx.cached_cons,*xsk_info->rx.producer);

        printf("WPDEBUG: rcvd is %d\n",rcvd);//////////////////////////////////////////////////////////DEBUG
        printf("WPDEBUG: umem_frame_free is %d\n",xsk_info->umem_frame_free);

//        printf("WPDEBUG: umem_info->fq.cached_prod is %d\n",umem_info->fq.cached_prod);
//        printf("WPDEBUG: umem_info->fq.cached_cons is %d\n",umem_info->fq.cached_cons);
//        printf("WPDEBUG: umem_info->fq.producer is %p\n",umem_info->fq.producer);
//        printf("WPDEBUG: umem_info->fq.consumer is %p\n",umem_info->fq.consumer);
//        printf("WPDEBUG: umem_info->fq.ring is %p\n",umem_info->fq.ring);
//
//        printf("WPDEBUG: xsk_info->rx.cached_prod is %d\n",xsk_info->rx.cached_prod);
//        printf("WPDEBUG: xsk_info->rx.cached_cons is %d\n",xsk_info->rx.cached_cons);
//        printf("WPDEBUG: xsk_info->rx.producer is %p\n",xsk_info->rx.producer);
//        printf("WPDEBUG: xsk_info->rx.consumer is %p\n",xsk_info->rx.consumer);
//        printf("WPDEBUG: xsk_info->rx.ring is %p\n",xsk_info->rx.ring);
//
//        printf("WPDEBUG: xsk_info->tx.cached_prod is %d\n",xsk_info->tx.cached_prod);
//        printf("WPDEBUG: xsk_info->tx.cached_cons is %d\n",xsk_info->tx.cached_cons);
//        printf("WPDEBUG: xsk_info->tx.producer is %p\n",xsk_info->tx.producer);
//        printf("WPDEBUG: xsk_info->tx.consumer is %p\n",xsk_info->tx.consumer);
//        printf("WPDEBUG: xsk_info->tx.ring is %p\n",xsk_info->tx.ring);


        /* Stuff the ring with as much frames as possible */
        /***************************************************
         * static inline __u32 xsk_prod_nb_free(struct xsk_ring_prod *r, __u32 nb)
         *   {
         *       __u32 free_entries = r->cached_cons - r->cached_prod;
         *
         *       if (free_entries >= nb)
         *           return free_entries;
         *
         *        //  Refresh the local tail pointer.
         *        * cached_cons is r->size bigger than the real consumer pointer so
         *        * that this addition can be avoided in the more frequently
         *        * executed code that computs free_entries in the beginning of
         *        * this function. Without this optimization it whould have been
         *        * free_entries = r->cached_prod - r->cached_cons + r->size.
         *        //
         *           r->cached_cons = *r->consumer + r->size;
         *
         *           return r->cached_cons - r->cached_prod;
         *     }
         *
         *
         */
        printf("WPDEBUG: xsk_info->umem->fq.cached_prod is %d\n"
               "         xsk_info->umem->fq.cached_cons is %d\n"
               "         *(xsk_info->umem->fq.consumer) is %d\n"
                ,xsk_info->umem->fq.cached_prod,xsk_info->umem->fq.cached_cons,*(xsk_info->umem->fq.consumer));
        printf("WPDEBUG: umem_frame_free is %d\n",xsk_info->umem_frame_free);
        stock_frames = xsk_prod_nb_free(&xsk_info->umem->fq, xsk_info->umem_frame_free);
        printf("WPDEBUG: stock_frames is %d\n",stock_frames);//////////////////////////////////////////////////////////DEBUG
        if (stock_frames > 0) {

            err = xsk_ring_prod__reserve(&xsk_info->umem->fq, stock_frames, &idx_fq);

            /* This should not happen, but just in case */
            while (err != stock_frames)
                err = xsk_ring_prod__reserve(&xsk_info->umem->fq, rcvd, &idx_fq);

            /* 改动过 */
            for (i = 0; i < stock_frames; i ++){
                if (xsk_info->umem_frame_free == 0){
                    *(xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++)) = INVALID_UMEM_FRAME;
                } else {
                    frame = xsk_info->umem_frame_addr[--xsk_info->umem_frame_free];
                    xsk_info->umem_frame_addr[xsk_info->umem_frame_free] = INVALID_UMEM_FRAME;
                    *(xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++)) = frame;
                }
            }

            xsk_ring_prod__submit(&xsk_info->umem->fq, stock_frames);
            printf("WPDEBUG: 当前生产者下标为：%d\n",*xsk_info->umem->fq.producer);
        }

        /* Process received packets */
        for (i = 0; i < rcvd; i++) {
            uint64_t addr = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx)->addr;
            uint32_t len = xsk_ring_cons__rx_desc(&xsk_info->rx, idx_rx++)->len;

            printf("WPDEBUG: idx_rx is %d\n"
                   "         xsk_ring_cons__rx_desc addr is %ld\n"
                   "         xsk_ring_cons__rx_desc len is %d\n",idx_rx-1,addr,len);//////////////////////////////////////////////////////////DEBUG

            //if (!process_packet(xsk, addr, len))
            //    xsk_free_umem_frame(xsk, addr);
            uint8_t *pkt = xsk_umem__get_data(xsk_info->umem->buffer, addr); // addr只是对应的偏移量；取具体地址就是用这个函数
                                                                   // 返回&((char *)xsk_info->umem->buffer)[addr];
            printf("WPDEBUG: pkt's addr is %p\n",pkt);//////////////////////////////////////////////////////////DEBUG

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

            err = xsk_ring_prod__reserve(&xsk_info->tx, 1, &tx_idx);
            if (err != 1) {
                /* No more transmit slots, drop the packet */
                //////xsk_free_umem_frame(xsk_info, addr);
                assert(xsk_info->umem_frame_free < NUM_FRAMES);
                xsk_info->umem_frame_addr[xsk_info->umem_frame_free++] = addr;
            }

            xsk_ring_prod__tx_desc(&xsk_info->tx, tx_idx)->addr = addr;
            xsk_ring_prod__tx_desc(&xsk_info->tx, tx_idx)->len = len;
            printf("WPDEBUG: xsk_ring_prod__tx_desc addr is %ld\n"
                   "         xsk_ring_prod__tx_desc len is %d\n",addr,len);//////////////////////////////////////////////////////////DEBUG
            xsk_ring_prod__submit(&xsk_info->tx, 1);
            xsk_info->outstanding_tx++;
            printf("WPDEBUG: outstanding_tx is %d\n",xsk_info->outstanding_tx);//////////////////////////////////////////////////////////DEBUG

            xsk_info->stats.tx_bytes += len;
            xsk_info->stats.tx_packets++;
            printf("WPDEBUG: tx_bytes is %ld\n"
                   "         tx_packets is %ld\n",xsk_info->stats.tx_bytes,xsk_info->stats.tx_packets);///////////////////////DEBUG

            xsk_info->stats.rx_bytes += len;
        }

        xsk_ring_cons__release(&xsk_info->rx, rcvd); // 也就是当前consumer指针加上rcvd即刚才消费的个数
        xsk_info->stats.rx_packets += rcvd;
        printf("WPDEBUG: rx_bytes is %ld\n"
               "         rx_packets is %ld\n",xsk_info->stats.rx_bytes,xsk_info->stats.rx_packets);///////////////////////DEBUG

        /* Do we need to wake up the kernel for transmission */
        ////////////complete_tx(xsk_info);/////////////

        unsigned int completed;
        uint32_t idx_cq;

        if (!xsk_info->outstanding_tx)
            continue;

        sendto(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

        /* Collect/free completed TX buffers */
        completed = xsk_ring_cons__peek(&xsk_info->umem->cq,
                                        XSK_RING_CONS__DEFAULT_NUM_DESCS,
                                        &idx_cq);

        if (completed > 0) {
            for (int i = 0; i < completed; i++){
                assert(xsk_info->umem_frame_free < NUM_FRAMES);
                xsk_info->umem_frame_addr[xsk_info->umem_frame_free++] =
                        *(xsk_ring_cons__comp_addr(&xsk_info->umem->cq, idx_cq++));
            }

            xsk_ring_cons__release(&xsk_info->umem->cq, completed);
            xsk_info->outstanding_tx -= completed < xsk_info->outstanding_tx ?
                                   completed : xsk_info->outstanding_tx;
        }
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
