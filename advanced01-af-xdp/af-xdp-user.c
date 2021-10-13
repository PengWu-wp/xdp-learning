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
#include <linux/ipv6.h>
#include <linux/icmpv6.h>

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_umem_info { // 该结构体是linux源码samples示例中用的，xsk_umem信息
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct stats_record { // 用于包统计计数的结构体
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

    uint32_t outstanding_tx;

    struct stats_record stats;
    struct stats_record prev_stats;
};

//static inline __u32 xsk_ring_prod__free(struct xsk_ring_prod *r) // 这居然也是你定义的？
//{
//    r->cached_cons = *r->consumer + r->size;
//    return r->cached_cons - r->cached_prod;
//}

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
           "-q, --quiet\t\tQuiet mode (no output)\n"
           , name);
} // End of usage

static bool global_exit;
static bool verbose = true;

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size)
{
    struct xsk_umem_info *umem;
    int ret;

    umem = calloc(1, sizeof(*umem));
    if (!umem)
        return NULL;

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                           NULL); // 具体做了什么？-判断buffer是否对齐、socket()创建、umem config
    // 的默认配置、向AF_XDP注册UMEM、设置UMEM的FILL/COMLETION ring大小
    // 将整个FILL/COMLETION ring 映射到用户态空间（这样用户态才能操作）；
    if (ret) {
        errno = -ret;
        return NULL;
    }

    umem->buffer = buffer;
    return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk)
{
    uint64_t frame;
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame)
{
    assert(xsk->umem_frame_free < NUM_FRAMES);

    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk)
{
    return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct config *cfg,
                                                    struct xsk_umem_info *umem)
{
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    uint32_t idx;
    uint32_t prog_id = 0;
    int i;
    int ret;

    xsk_info = calloc(1, sizeof(*xsk_info)); // 为什么不会自动分配内存？
    if (!xsk_info)
        return NULL;

    xsk_info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS; // 默认各一半
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.libbpf_flags = 0;
    xsk_cfg.xdp_flags = cfg->xdp_flags;
    xsk_cfg.bind_flags = cfg->xsk_bind_flags;
    ret = xsk_socket__create(&xsk_info->xsk, cfg->ifname,
                             cfg->xsk_if_queue, umem->umem, &xsk_info->rx,
                             &xsk_info->tx, &xsk_cfg); // 和xsk_umem__create很像：
    // - xsk_cfg的默认配置、获取xsk_socket的fd（前面给umem创建的）、
    // 设置XSK RX/TX ring大小、得到RX/TX ring偏移量，进行用户空间映射、
    // …………

    if (ret)
        goto error_exit;

    ret = bpf_get_link_xdp_id(cfg->ifindex, &prog_id, cfg->xdp_flags); // 指定接口index和flag获取xdp程序id；
    if (ret)
        goto error_exit;

    /* Initialize umem frame allocation */

    for (i = 0; i < NUM_FRAMES; i++) // 把UMEM中每个数据帧的地址都指定好？
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

    xsk_info->umem_frame_free = NUM_FRAMES; // 剩余能操作的数据帧数量?

    /* Stuff the receive path with buffers, we assume we have enough */
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                                 XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                 &idx); //

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
        goto error_exit;

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i ++)
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
                xsk_alloc_umem_frame(xsk_info);

    xsk_ring_prod__submit(&xsk_info->umem->fq,
                          XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;

    error_exit:
    errno = -ret;
    return NULL;
}

static void complete_tx(struct xsk_socket_info *xsk)
{
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

static bool process_packet(struct xsk_socket_info *xsk,
                           uint64_t addr, uint32_t len)
{
    //uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

    /* Reply a ping...
     *
     */

    if (true) {
        /* To be continued... */
        //struct ethhdr *eth = (struct ethhdr *) pkt;
        return true;
    }

    return false;
}

static void handle_receive_packets(struct xsk_socket_info *xsk)
{
    unsigned int rcvd, stock_frames, i;
    uint32_t idx_rx = 0, idx_fq = 0;
    int ret;

    rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd)
        return;

    /* Stuff the ring with as much frames as possible */
    stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
                                    xsk_umem_free_frames(xsk));

    if (stock_frames > 0) {

        ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
                                     &idx_fq);

        /* This should not happen, but just in case */
        while (ret != stock_frames)
            ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
                                         &idx_fq);

        for (i = 0; i < stock_frames; i++)
            *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
                    xsk_alloc_umem_frame(xsk);

        xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
    }

    /* Process received packets */
    for (i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

        if (!process_packet(xsk, addr, len))
            xsk_free_umem_frame(xsk, addr);

        xsk->stats.rx_bytes += len;
    }

    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk->stats.rx_packets += rcvd;

    /* Do we need to wake up the kernel for transmission */
    complete_tx(xsk);
}

static void rx_and_process(struct config *cfg,
                           struct xsk_socket_info *xsk_socket)
{
    struct pollfd fds[2];
    int ret, nfds = 1;

    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
    fds[0].events = POLLIN;

    while(!global_exit) {
        if (cfg->xsk_poll_mode) {
            ret = poll(fds, nfds, -1);
            if (ret <= 0 || ret > 1)
                continue;
        }
        handle_receive_packets(xsk_socket);
    }
}


#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static uint64_t gettime(void)
{
    struct timespec t;
    int res;

    res = clock_gettime(CLOCK_MONOTONIC, &t);
    if (res < 0) {
        fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
        exit(1);
    }
    return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record *r, struct stats_record *p)
{
    double period_ = 0;
    __u64 period = 0;

    period = r->timestamp - p->timestamp;
    if (period > 0)
        period_ = ((double) period / NANOSEC_PER_SEC);

    return period_;
}

static void stats_print(struct stats_record *stats_rec,
                        struct stats_record *stats_prev)
{
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
    pps     = packets / period;

    bytes   = stats_rec->rx_bytes   - stats_prev->rx_bytes;
    bps     = (bytes * 8) / period / 1000000;

    printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
           stats_rec->rx_bytes / 1000 , bps,
           period);

    packets = stats_rec->tx_packets - stats_prev->tx_packets;
    pps     = packets / period;

    bytes   = stats_rec->tx_bytes   - stats_prev->tx_bytes;
    bps     = (bytes * 8) / period / 1000000;

    printf(fmt, "       TX:", stats_rec->tx_packets, pps,
           stats_rec->tx_bytes / 1000 , bps,
           period);

    printf("\n");
}

static void *stats_poll(void *arg)
{
    unsigned int interval = 2;
    struct xsk_socket_info *xsk = arg;
    static struct stats_record previous_stats = { 0 };

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

static void exit_application(int signal)
{
    // signal = signal; // 是传统吗？不要应该也行吧？至少删掉以后我没发现什么问题。
    global_exit = true; // 定义一个全局exit变量，配合signal中断处理用于死循环的条件退出；
}

int xdp_link_detach(int ifindex, __u32 xdp_flags){
    return bpf_set_link_xdp_fd(ifindex, -1, xdp_flags); // set fd -1 to unload
}




int main(int argc, char **argv) {
    int err;
    //int xsks_map_fd;
    void *packet_buffer;
    uint64_t packet_buffer_size;
    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY}; // Resource LIMIT，一会儿用于setrlimit()的

    struct config cfg = { /* xdp prog loading related config options */
            .ifindex   = -1,
            .do_unload = false,
            .filename = "af-xdp-kern.o",
            .progsec = "xdp"
    };

    struct xsk_umem_info *umem;
    struct xsk_socket_info *xsk_socket;
    //struct bpf_object *bpf_obj = NULL;
    pthread_t stats_poll_thread; // 干啥的？

    /* Global shutdown handler */
    signal(SIGINT, exit_application); // 设置一个函数来处理前面的信号，SIGINT
    //(Signal Interrupt) 为中断信号，如 ctrl-C，通常由用户生成

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

    if (cfg.ifindex == -1) {
        fprintf(stderr, "Error: required option -d/--dev missing\n");
        usage(argv[0]);
        return 1;
    }
    /* Unload XDP prog */
    if (cfg.do_unload) {
        err = xdp_link_detach(cfg.ifindex, cfg.xdp_flags);
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

    /* Allow unlimited locking of memory, so all memory needed for packet
	 * buffers can be locked. 所以默认的设置是多少？-默认设置是根据你bash的默认
	 * 继承下来的。可以用ulimit命令查看。| 什么是内存锁定？如果进程可以锁定在内
	 * 存中数据量很小会发生什么？这个程序在哪锁定内存了？
	 */
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Allocate memory for NUM_FRAMES of the default XDP frame size
	 * 还不是很懂
	 */
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE; /* FRAME_SIZE应该UMEM规定的数据帧的默认大小，
												   * NUM_FRAMES就是我们设置的UMEM中默认数据帧数量了 */
    if (posix_memalign(&packet_buffer, /* 分配packet_buffer_size的内存，并按pagesize对齐 */
                       getpagesize(), /* PAGE_SIZE aligned 等一下，DPDK所谓巨页的页就是这里的page吗？-是了*/
                       packet_buffer_size)) {
        fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    } // 所以现在我分了4096个4096字节大小的数据帧缓存区，以4096（linux默认pagesize）对齐
    // 那这部分内存是给谁用的？umem吗

    /* Initialize shared packet_buffer for umem usage
	 * packet_buffer是上一步分配到的内存地址，这里的umem结构体定义
	 * 是linux源码samples中的用法，值得参考
	 */
    umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
    if (umem == NULL) {
        fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    } // umem、FILL/COMPLETION ring现在配置好了；

    /* Open and configure the AF_XDP (xsk) socket
	 * 不出意外就是rx、tx ring的设置
	 */
    xsk_socket = xsk_configure_socket(&cfg, umem);
    if (xsk_socket == NULL) {
        fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    /* Start thread to do statistics display */
    if (verbose) { // 全局变量，
        err = pthread_create(&stats_poll_thread, NULL, stats_poll,
                             xsk_socket); // 总之就是另开一个线程跑stats_poll
        if (err) {
            fprintf(stderr, "ERROR: Failed creating statistics thread "
                            "\"%s\"\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    /* Receive and count packets than drop them */
    rx_and_process(&cfg, xsk_socket);

    /* Cleanup */
    xsk_socket__delete(xsk_socket->xsk);
    xsk_umem__delete(umem->umem);
    xdp_link_detach(cfg.ifindex, cfg.xdp_flags);

    return 0;
}
