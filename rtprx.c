#define __STDC_FORMAT_MACROS
#define _GNU_SOURCE
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/select.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <net/ethernet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

#include "ns.h"
#include "addr_list.h"
#include "rtp_window.h"

static void exit_with_usage() {
    fprintf(stderr, "Usage: rtprx [--netmap <devs> [--rxonly] | --xdp <dev>] [-d] [-i <us>] [-v] <locips> <dstips> <srcips> <dstport0> <#TSs>\n");
    exit(0);
}

struct global_data {
    struct addr_list locaddr;
    struct addr_list dstaddr;
    struct addr_list srcaddr;
    uint16_t dstport0; 
    bool daemonize;
    int signum;
    int killed;
    int N;
    ns_t t0;
    ns_t interval;
    bool verbose;
    bool rxonly;
    struct str_list netdev;
};
struct global_data* globptr = NULL;

struct ts_data {
    int index;
    struct rtp_window rtp_window;
    uint32_t prev_valid;
    uint32_t max_burst;
    bool running;
} *tsptr0 = NULL;

struct vlan_header {
    uint16_t tag;
    uint16_t ether_type;
};

static void sighandle(int signum)
{
  globptr->signum = signum;
}

static void handle_udp_packet(struct ts_data* tsptr, const uint8_t* pkt) {
    uint16_t seqnr = pkt[2] << 8 | pkt[3];
    int16_t diff = seqnr - tsptr->rtp_window.seqnr;
    if (globptr->verbose && !tsptr->rtp_window.firstpkt && diff != 0) {
        time_t now = time(0);
        char nowstr[26];
        printf("Port %d expected seqnr %d but got %d at %s",
            globptr->dstport0 + (int)(tsptr - tsptr0), tsptr->rtp_window.seqnr, seqnr, ctime_r(&now, nowstr));
        fflush(stdout);
    }
    rtp_window_push(&tsptr->rtp_window, seqnr);
}

static bool handle_eth_packet(const uint8_t* pkt, size_t len) {
    const uint8_t* pktend = pkt + len;
    const struct ether_header* eth = (const struct ether_header*)pkt;
    pkt += sizeof(struct ether_header);
    if (pkt > pktend) return false;
    uint16_t ether_type = ntohs(eth->ether_type);

    if (ether_type == ETH_P_8021Q) {
        const struct vlan_header* vlan = (const struct vlan_header*)pkt;
        pkt += sizeof(struct vlan_header);
        if (pkt > pktend) return false;
        ether_type = ntohs(vlan->ether_type);
    }

    if (ether_type != ETH_P_IP) return false;

    const struct iphdr* ip = (const struct iphdr*)pkt;
    if (pkt + sizeof(struct iphdr) > pktend) return false;
    pkt += ip->ihl * 4;
    if (pkt > pktend) return false;

    //printf("PKT %08x -> %08x\n", ntohl(ip->saddr), ntohl(ip->daddr));

    if (ip->protocol != IPPROTO_UDP) return false;
    if (ntohs(ip->frag_off) & 0x1fff) return false;

    const struct udphdr* udp = (const struct udphdr*)pkt;
    pkt += sizeof(struct udphdr);
    if (pkt > pktend) return false;

    uint16_t dstport = ntohs(udp->dest);
    int tsindex = dstport - globptr->dstport0;
    if (tsindex < 0 || tsindex >= globptr->N) return false;
    struct ts_data* tsptr = &tsptr0[tsindex];

    handle_udp_packet(tsptr, pkt);

    return true;
}

static int join_mcast(int fd, struct sockaddr_in* dstaddr, struct sockaddr_in* locaddr, struct sockaddr_in* srcaddr)
{
    if (srcaddr->sin_addr.s_addr == INADDR_ANY)
    { // -> EXCLUDE(), a.k.a. non-source specific multicast
        struct ip_mreq mreq;
        mreq.imr_multiaddr = dstaddr->sin_addr;
        mreq.imr_interface = locaddr->sin_addr;

        if (setsockopt(fd, SOL_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
            char dstaddrbuf[20];
            char locaddrbuf[20];

            fprintf(stderr, "setsockopt(IP_ADD_MEMBERSHIP, %s@%s:EX()) failed: %m\n",
                    inet_ntop(dstaddr->sin_family, &dstaddr->sin_addr, dstaddrbuf, sizeof(dstaddrbuf)),
                    inet_ntop(locaddr->sin_family, &locaddr->sin_addr, locaddrbuf, sizeof(locaddrbuf)));
            return -1;
        }
    }
    else
    { // -> INCLUDE(srcaddr), a.k.a. source specific multicast
        struct ip_mreq_source mreq;
        mreq.imr_multiaddr = dstaddr->sin_addr;
        mreq.imr_interface = locaddr->sin_addr;
        mreq.imr_sourceaddr = srcaddr->sin_addr;

        if (setsockopt(fd, SOL_IP, IP_ADD_SOURCE_MEMBERSHIP, &mreq, sizeof(mreq))) {
            char dstaddrbuf[20];
            char locaddrbuf[20];
            char srcaddrbuf[20];

            fprintf(stderr, "setsockopt(IP_ADD_SOURCE_MEMBERSHIP, %s@%s:IN(%s)) failed: %m\n",
                    inet_ntop(dstaddr->sin_family, &dstaddr->sin_addr, dstaddrbuf, sizeof(dstaddrbuf)),
                    inet_ntop(locaddr->sin_family, &locaddr->sin_addr, locaddrbuf, sizeof(locaddrbuf)),
                    inet_ntop(srcaddr->sin_family, &srcaddr->sin_addr, srcaddrbuf, sizeof(srcaddrbuf)));
            return -1;
        }
    }
    return 0;
}

static void *run(void *arg) {
    struct ts_data *tsptr = arg;
    int index = tsptr - tsptr0;
    uint16_t dstport = globptr->dstport0 + index;

    char threadname[16];
    sprintf(threadname, "%s:%u", "rtprx", dstport);
    prctl(PR_SET_NAME, threadname, 0, 0, 0);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        fprintf(stderr, "socket() failed: %m\n");
        goto leave;
    }
    
    int bufsize = 2097152; // copied from /proc/sys/net/core/rmem_max
    if (setsockopt(s, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize))) {
        fprintf(stderr, "setsockopt(SO_RCVBUF, %d) failed for port %u: %m\n", 
                bufsize, dstport);
    }
    
    struct sockaddr_in dstaddr = *addr_list_get(&globptr->dstaddr, index);
    dstaddr.sin_port = htons(dstport);

    if (bind(s, (struct sockaddr *)&dstaddr, sizeof(dstaddr)))
    {
        char ipaddrbuf[20];
        fprintf(stderr, "bind(%s:%u) failed: %m\n", 
                inet_ntop(dstaddr.sin_family, &dstaddr.sin_addr, ipaddrbuf, sizeof(ipaddrbuf)), dstport);
        goto leave; // this is a failure
    }
    
    uint8_t *dstip = (uint8_t *)&dstaddr.sin_addr;
    if ((dstip[0] & 0xf0) == 0xe0) {
        if (join_mcast(s, &dstaddr, addr_list_get(&globptr->locaddr, index),
                                    addr_list_get(&globptr->srcaddr, index)) < 0)
            goto leave;
    }

    int flags = fcntl(s, F_GETFL, 0);
    if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0)
    {
      fprintf(stderr, "fcntl(flags | O_NONBLOCK) failed: %m\n");
      goto leave;
    }

    uint8_t buf[1500];
    struct iovec iov;
    struct msghdr msg;
    iov.iov_base = buf;
    iov.iov_len = 1500;
    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    ns_t t = ns_now();

    for (;!globptr->killed;) {
        uint32_t burst = 0;
        for (;;) {
          int n = recvmsg(s, &msg, 0);
          if (n <= 0) {
              if (errno == EWOULDBLOCK) {
                  break;
              } else {
                  fprintf(stderr, "recvmsg() failed for port %u: %m\n", dstport);
                  goto leave;
              }
          }
          handle_udp_packet(tsptr, buf);
          burst++;
        }
        ns_t t1 = ns_now();

        t += globptr->interval;
        if (burst > tsptr->max_burst) tsptr->max_burst = burst;

        if (t >= t1 + 1000) {
            struct timeval tv;
            ns_totimeval(t - t1, &tv);
            select(0, NULL, NULL, NULL, &tv);
        }
    }
leave:
    if (s > 0)
        close(s);
    tsptr->running = false;
    return NULL;
}

#ifdef NETMAP

#include <net/netmap.h>
#include <net/netmap_user.h>

static void* run_netmap(void* arg)
{
    struct ts_data* threadptr = (struct ts_data*)arg;
    int index = threadptr - tsptr0;
    int step = globptr->netdev.size;

    const char* dev = str_list_get(&globptr->netdev, index);

    char threadname[16];
    sprintf(threadname, "%s:%s", "rtprx", dev);
    prctl(PR_SET_NAME, threadname, 0, 0, 0);

    struct nmreq_register reg = {
        .nr_mode = NR_REG_NIC_SW,
    };
    struct nmreq_header hdr = {
        .nr_version = NETMAP_API,
        .nr_reqtype = NETMAP_REQ_REGISTER,
        .nr_body    = (uint64_t)&reg,
    };
    void *mem = MAP_FAILED;
    int fd = -1;
    int igmpfd = - 1;

    fd = open("/dev/netmap", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "open(/dev/netmap) failed: %m\n");
        goto leave;
    }

    snprintf(hdr.nr_name, NETMAP_REQ_IFNAMSIZ, "%s", dev);
    if (ioctl(fd, NIOCCTRL, &hdr) < 0) {
        fprintf(stderr, "ioctl(/dev/netmap, NIOCCTRL, {type=NETMAP_REQ_REGISTER, port=%s}) failed: %m\n", dev);
        goto leave;
    }

    mem = mmap(NULL, reg.nr_memsize, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "mmap(/dev/netmap) failed: %m\n");
        goto leave;
    }
    struct netmap_if *ifp = NETMAP_IF(mem, reg.nr_offset);

    igmpfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (igmpfd < 0) {
        fprintf(stderr, "socket() failed: %m\n");
        goto leave;
    }
    int memberships = globptr->dstaddr.size;
    if (memberships < globptr->srcaddr.size)
        memberships = globptr->srcaddr.size;
    for (int i = index; i < memberships; i += step)
    {
        struct sockaddr_in dstaddr = *addr_list_get(&globptr->dstaddr, i);
        uint8_t *dstip = (uint8_t *)&dstaddr.sin_addr;
        if ((dstip[0] & 0xf0) == 0xe0) {
            if (join_mcast(igmpfd, &dstaddr, addr_list_get(&globptr->locaddr, i),
                                             addr_list_get(&globptr->srcaddr, i)) < 0)
                goto leave;
        }
    }

    ns_t t = ns_now();
    bool first = true;

    for (;!globptr->killed;) {

        if (ioctl(fd, NIOCRXSYNC, NULL) < 0) {
            fprintf(stderr, "ioctl(/dev/netmap, NIOCRXSYNC) failed: %m\n");
            goto leave;
        }

        // from nic rx ring to rtp window or to host rx ring
        uint32_t burst = 0;
        for (uint32_t rxringi = 0; rxringi < ifp->ni_rx_rings; rxringi++) {
            struct netmap_ring* rxringp = NETMAP_RXRING(ifp, rxringi);
            struct netmap_ring* txringp = NETMAP_TXRING(ifp, ifp->ni_tx_rings + rxringi % ifp->ni_host_tx_rings);
            uint32_t rxhead = rxringp->head, rxtail = rxringp->tail;
            uint32_t txhead = txringp->head, txtail = txringp->tail;

            for (; rxhead != rxtail; rxhead = nm_ring_next(rxringp, rxhead)) {
                burst++;
                struct netmap_slot* rxslotp = &rxringp->slot[rxhead];
                const uint8_t* pkt = (const uint8_t*)NETMAP_BUF(rxringp, rxslotp->buf_idx);
                if (rxslotp->flags & NS_MOREFRAG) continue; // don't support this.

                if (handle_eth_packet(pkt, rxslotp->len)) continue;

                if (txhead == txtail) continue; // this is packet drop

                struct netmap_slot* txslotp = &txringp->slot[txhead];
                struct netmap_slot tmp = *txslotp;
                *txslotp = *rxslotp;
                *rxslotp = tmp;
                txslotp->flags |= NS_BUF_CHANGED;
                rxslotp->flags |= NS_BUF_CHANGED;
                txhead = nm_ring_next(txringp, txhead);
            }
            rxringp->head = rxringp->cur = rxhead;
            txringp->head = txringp->cur = txhead;
        }
        if (burst > threadptr->max_burst) threadptr->max_burst = burst;

        if (!globptr->rxonly) {
            // From host rx ring to nic tx ring
            for (uint32_t rxringi = 0; rxringi < ifp->ni_host_rx_rings; rxringi++) {
                struct netmap_ring* rxringp = NETMAP_RXRING(ifp, ifp->ni_rx_rings + rxringi);
                struct netmap_ring* txringp = NETMAP_TXRING(ifp, rxringi % ifp->ni_tx_rings);
                uint32_t rxhead = rxringp->head, rxtail = rxringp->tail;
                uint32_t txhead = txringp->head, txtail = txringp->tail;

                for (; rxhead != rxtail; rxhead = nm_ring_next(rxringp, rxhead)) {
                    struct netmap_slot* rxslotp = &rxringp->slot[rxhead];

                    if (txhead == txtail) continue; // this is packet drop

                    struct netmap_slot* txslotp = &txringp->slot[txhead];
                    struct netmap_slot tmp = *txslotp;
                    *txslotp = *rxslotp;
                    *rxslotp = tmp;
                    txslotp->flags |= NS_BUF_CHANGED;
                    rxslotp->flags |= NS_BUF_CHANGED;
                    txhead = nm_ring_next(txringp, txhead);
                }
                rxringp->head = rxringp->cur = rxhead;
                txringp->head = txringp->cur = txhead;
            }
        }

        if (ioctl(fd, NIOCTXSYNC, NULL) < 0) {
            fprintf(stderr, "ioctl(/dev/netmap, NIOCTXSYNC) failed: %m\n");
            goto leave;
        }

        ns_t t1 = ns_now();

        t += globptr->interval;

        if (t >= t1 + 1000) {
            struct timeval tv;
            ns_totimeval(t - t1, &tv);
            select(0, NULL, NULL, NULL, &tv);
        }

        first = false;
    }

leave:
    if (mem != MAP_FAILED)
        munmap(mem, reg.nr_memsize);
    if (igmpfd > 0)
        close(igmpfd);
    if (fd > 0)
        close(fd);
    threadptr->running = false;
    return NULL;
}

#else

static void* run_netmap(void* arg)
{
    struct ts_data *threadptr = arg;
    fprintf(stderr, "Netmap support was disabled at compile time. Exiting...\n");
    threadptr->running = false;
    return NULL;
}

#endif

#ifdef XDP

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include "bpfprog.h"

static void* run_xdp(void* arg)
{
    struct ts_data *threadptr = arg;
    const char* dev = str_list_get(&globptr->netdev, 0);
    int igmpfd = - 1;
    int progfd = -1;
    int globalparamsfd = -1;
    int xskmapfd = -1;
    int nrqueues = get_nrqueues(dev);
    struct bpf_object *obj = NULL;
    int err = 0;

    char threadname[16];
    sprintf(threadname, "%s:%s", "rtprx", dev);
    prctl(PR_SET_NAME, threadname, 0, 0, 0);

    struct xsk_info
    {
      struct xsk_umem* umem;
      struct xsk_socket* xsk;
      struct xsk_ring_prod fillq;
      struct xsk_ring_cons compq;
      struct xsk_ring_cons rxq;
      void *mem;
    };
    struct xsk_info xsk_info[nrqueues];
    memset(xsk_info, 0, sizeof(xsk_info));

    int ifindex = if_nametoindex(dev);
    if (!ifindex)
    {
        fprintf(stderr, "if_nametoindex(%s) failed: %m\n", dev);
        goto leave;
    }

    /* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
     * loading this into the kernel via bpf-syscall */
    err = bpf_prog_load("bpfprog.o", BPF_PROG_TYPE_XDP, &obj, &progfd);
    if (err) {
        fprintf(stderr, "bpf_prog_load(\"bpfprog.o\", BPF_PROG_TYPE_XDP) failed: %s\n", strerror(-err));
        goto leave;
    }

    struct bpf_map *map = bpf_object__find_map_by_name(obj, "global_params_map");
    if (!map) {
        fprintf(stderr, "bpf_object__find_map_by_name(global_params_map) failed: %m\n");
        goto leave;
    }
    globalparamsfd = bpf_map__fd(map);
    map = bpf_object__find_map_by_name(obj, "xsk_map");
    if (!map) {
        fprintf(stderr, "bpf_object__find_map_by_name(xsk_map) failed: %m\n");
        goto leave;
    }
    xskmapfd = bpf_map__fd(map);

    uint32_t mapkey = 0;
    struct global_params mapval = {
            .udp_lo  = globptr->dstport0,
            .udp_hi = globptr->dstport0 + globptr->N - 1
    };
    err = bpf_map_update_elem(globalparamsfd, &mapkey, &mapval, 0);
    if (err)
    {
        fprintf(stderr, "bpf_map_update_elem() failed: %s\n", strerror(-err));
        goto leave;
    }

    err = bpf_set_link_xdp_fd(ifindex, progfd, 0);
    if (err)
    {
        fprintf(stderr, "bpf_set_link_xdp_fd(%s) failed: %s\n", dev, strerror(-err));
        goto leave;
    }

    struct xsk_umem_config umem_config = {
         .fill_size = 8192,
         .comp_size = 8192,
         .frame_size = 2048,
         .frame_headroom = 0,
         .flags = 0
    };
    struct xsk_socket_config xsk_config = {
         .rx_size = 8192,
         .tx_size = 0,
         .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
         .xdp_flags = 0,
         .bind_flags = 0
    };

    for (int queueid = 0; queueid < nrqueues; queueid++)
    {
        struct xsk_info* xsk = &xsk_info[queueid];
        size_t umem_size = umem_config.fill_size * umem_config.frame_size;
        posix_memalign(&xsk->mem, getpagesize(), umem_size);
        err = xsk_umem__create(&xsk->umem, xsk->mem, umem_size, &xsk->fillq, &xsk->compq, &umem_config);
        if (err)
        {
            fprintf(stderr, "xsk_umem__create() failed: %s\n", strerror(-err));
            goto leave;
        }

        err = xsk_socket__create(&xsk->xsk, dev, queueid, xsk->umem, &xsk->rxq, NULL, &xsk_config);
        if (err)
        {
            fprintf(stderr, "xsk_socket__create() failed: %s\n", strerror(-err));
            goto leave;
        }

        int xskfd = xsk_socket__fd(xsk->xsk);
        err = bpf_map_update_elem(xskmapfd, &queueid, &xskfd, 0);
        if (err)
        {
            fprintf(stderr, "bpf_map_update_elem(xsk_map, queue_id=%d, fd=%d) failed: %s\n", queueid, xskfd, strerror(-err));
            goto leave;
        }

        /* Stuff the receive path with buffers, we assume we have enough */
        __u32 idx = 0;
        xsk_ring_prod__reserve(&xsk->fillq, umem_config.fill_size, &idx);
        for (__u32 i = 0; i < umem_config.fill_size; i++)
        {
            *xsk_ring_prod__fill_addr(&xsk->fillq, idx++) = umem_config.frame_size * i;
        }
        xsk_ring_prod__submit(&xsk->fillq, umem_config.fill_size);
    }

    igmpfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (igmpfd < 0) {
        fprintf(stderr, "socket() failed: %m\n");
        goto leave;
    }
    int memberships = globptr->dstaddr.size;
    if (memberships < globptr->srcaddr.size)
        memberships = globptr->srcaddr.size;
    for (int i = 0; i < memberships; i++)
    {
        struct sockaddr_in dstaddr = *addr_list_get(&globptr->dstaddr, i);
        uint8_t *dstip = (uint8_t *)&dstaddr.sin_addr;
        if ((dstip[0] & 0xf0) == 0xe0) {
            if (join_mcast(igmpfd, &dstaddr, addr_list_get(&globptr->locaddr, i),
                                             addr_list_get(&globptr->srcaddr, i)) < 0)
                goto leave;
        }
    }

    ns_t t = ns_now();

    for (;!globptr->killed;) {

        for (int queueid = 0; queueid < nrqueues; queueid++)
        {
            struct xsk_info* xsk = &xsk_info[queueid];
            __u32 rxidx = 0, fillidx = 0;
            size_t n = xsk_ring_cons__peek(&xsk->rxq, umem_config.fill_size, &rxidx);
            //if (n) fprintf(stderr, "queueid=%d xsk_ring_cons__peek=%zu\n", queueid, n);
            if (n) xsk_ring_prod__reserve(&xsk->fillq, n, &fillidx);
            for (__u32 i = 0; i < n; i++)
            {
                const struct xdp_desc* desc = xsk_ring_cons__rx_desc(&xsk->rxq, rxidx++);
                const uint8_t *pkt = xsk_umem__get_data(xsk->mem, desc->addr);
                handle_eth_packet(pkt, desc->len);
                *xsk_ring_prod__fill_addr(&xsk->fillq, fillidx++) = desc->addr;
            }
            if (n) xsk_ring_cons__release(&xsk->rxq, n);
            if (n) xsk_ring_prod__submit(&xsk->fillq, n);
        }

        ns_t t1 = ns_now();

        t += globptr->interval;

        if (t >= t1 + 1000) {
            struct timeval tv;
            ns_totimeval(t - t1, &tv);
            select(0, NULL, NULL, NULL, &tv);
        }

    }

leave:
    if (igmpfd > 0)
        close(igmpfd);
    for (int i = 0; i < nrqueues; i++)
    {
      struct xsk_info* xsk = &xsk_info[i];
      xsk_socket__delete(xsk->xsk);
      xsk_umem__delete(xsk->umem);
      free(xsk->mem);
    }
    if (ifindex) bpf_set_link_xdp_fd(ifindex, -1, 0); // detach XDP program from network device.
    bpf_object__close(obj);
    threadptr->running = false;
    return NULL;
}
#else

static void* run_xdp(void* arg)
{
  struct ts_data *threadptr = arg;
  fprintf(stderr, "XDP support was disabled at compile time. Exiting...\n");
  threadptr->running = false;
  return NULL;
}

#endif

static void report()
{
    static bool reported = false;

    if (!reported || globptr->daemonize) {
        reported = true;
    } else {
        printf("\r");
        for (int i = 0; i < globptr->N + 4; i++)
            printf("%s", "\033[A");
    }

    printf("      port |      valid |    missing |  reordered |  duplicate |      reset | rate(Mbps) |  max_burst\n");
    printf("=====================================================================================================\n");

    ns_t t1 = ns_now();
    ns_t elapsed = t1 - globptr->t0;

    struct rtp_window tot_window;
    rtp_window_init(&tot_window);
    uint32_t tot_rate = 0;
    uint32_t max_burst = 0;

    for (int i = 0; i < globptr->N; i++) {
        uint32_t valid = tsptr0[i].rtp_window.valid;
        uint32_t rate = (uint64_t)(valid - tsptr0[i].prev_valid) * 7 * 188 * 8 * 1000000 / elapsed;
        tsptr0[i].prev_valid = valid;
        printf("%10" PRIu32 " | %10" PRIu32 " | %10" PRIu32 " | %10" PRIu32 " | %10" PRIu32 " | %10" PRIu32 " | %6" PRIu32 ".%03" PRIu32 " | %10" PRIu32 "\n",
                globptr->dstport0 + i,
                tsptr0[i].rtp_window.valid,
                tsptr0[i].rtp_window.missing,
                tsptr0[i].rtp_window.reordered,
                tsptr0[i].rtp_window.duplicate,
                tsptr0[i].rtp_window.reset,
                rate / 1000, rate % 1000,
                tsptr0[i].max_burst);
        tot_window.valid += tsptr0[i].rtp_window.valid;
        tot_window.missing += tsptr0[i].rtp_window.missing;
        tot_window.reordered += tsptr0[i].rtp_window.reordered;
        tot_window.duplicate += tsptr0[i].rtp_window.duplicate;
        tot_window.reset += tsptr0[i].rtp_window.reset;
        if (tsptr0[i].max_burst > max_burst) max_burst = tsptr0[i].max_burst;
        tot_rate += rate;
    }
    printf("=====================================================================================================\n");
    printf("     total | %10" PRIu32 " | %10" PRIu32 " | %10" PRIu32 " | %10" PRIu32 " | %10" PRIu32 " | %6" PRIu32 ".%03" PRIu32 " | %10" PRIu32 "\n",
            tot_window.valid,
            tot_window.missing,
            tot_window.reordered,
            tot_window.duplicate,
            tot_window.reset,
            tot_rate / 1000, tot_rate % 1000,
            max_burst);
    fflush(stdout);

    globptr->t0 = t1;
}

int main(int argc, char **argv) {
    struct global_data glob = { .interval = 10000000ULL };
    bool netmap = false, xdp = false;
    globptr = &glob;

    while (argc > 6) {
        if (!strcmp(argv[1], "-d")) {
            glob.daemonize = true;
        } else if (!strcmp(argv[1], "-v")) {
            glob.verbose = true;
        } else if (!strcmp(argv[1], "-i")) {
            glob.interval = 1000ULL * atoi(argv[2]);
            argv++; argc--;
        } else if (!strcmp(argv[1], "--netmap")) {
            str_list_parse(&glob.netdev, argv[2]);
            netmap = true;
            argv++; argc--;
        } else if (!strcmp(argv[1], "--xdp")) {
            str_list_parse(&glob.netdev, argv[2]);
            if (glob.netdev.size != 1) exit_with_usage();
            xdp = true;
            argv++; argc--;
        } else if (!strcmp(argv[1], "--rxonly")) {
            glob.rxonly = true;
        } else {
            exit_with_usage();
        }
        argv++;
        argc--;
    }

    if (argc != 6) 
        exit_with_usage();

    if (argc != 6)
        exit_with_usage();
    
    if (addr_list_parse(&glob.locaddr, argv[1]))
        exit_with_usage();

    if (addr_list_parse(&glob.dstaddr, argv[2]))
        exit_with_usage();

    if (addr_list_parse(&glob.srcaddr, argv[3]))
        exit_with_usage();
    
    glob.dstport0 = atoi(argv[4]);
    if (!glob.dstport0) {
        fprintf(stderr, "Not a valid UDP port number: %s\n", argv[4]);
        exit_with_usage();
    }
    
    glob.N = atoi(argv[5]);
    if (!glob.N) {
        fprintf(stderr, "Not a valid number of TSs: %s\n", argv[5]);
        exit_with_usage();
    }
    
    struct ts_data ts[glob.N];
    memset(ts, 0, sizeof(ts));
    for (int i = 0; i < glob.N; i++) {
        rtp_window_init(&ts[i].rtp_window);
    }
    tsptr0 = ts;
    glob.t0 = ns_now();
    time_t now = time(0);
    printf("Kicked off at %s", ctime(&now));
    fflush(stdout);

    if (glob.daemonize)
       daemon(1, 1);

    int threads = glob.N;
    if ((netmap || xdp) && threads > glob.netdev.size) threads = glob.netdev.size;
    pthread_t thread[threads];
    if (netmap) {
        for (int i = 0; i < glob.netdev.size; i++) {
            ts[i].running = true;
            int err = pthread_create(&thread[i], NULL, run_netmap, &ts[i]);
            if (err) {
                fprintf(stderr, "pthread_create() failed for the %dth thread: %s\n", i + 1, strerror(err));
                exit(1);
            }
        }
    } else if (xdp) {
        for (int i = 0; i < glob.netdev.size; i++) {
            ts[i].running = true;
            int err = pthread_create(&thread[i], NULL, run_xdp, &ts[i]);
            if (err) {
                fprintf(stderr, "pthread_create() failed for the %dth thread: %s\n", i + 1, strerror(err));
                exit(1);
            }
        }
    } else {
        for (int i = 0; i < glob.N; i++) {
            ts[i].running = true;
            int err = pthread_create(&thread[i], NULL, run, &ts[i]);
            if (err) {
                fprintf(stderr, "pthread_create() failed for the %dth thread: %s\n", i + 1, strerror(err));
                exit(1);
            }
        }
    }

    if (!glob.daemonize)
        report();

    signal(SIGUSR1, sighandle);
    signal(SIGTERM, sighandle);
    signal(SIGINT, sighandle);

    for(;;) {
        int running = 0;
        for (int i = 0; i < threads; i++)
            if (ts[i].running)
                running++;
        if (!running)
            break;

        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        select(0, NULL, NULL, NULL, &tv);
        
        if (glob.signum) {
            if (glob.daemonize) {
               time_t now = time(0);
               printf("Caught signal %d at %s", glob.signum, ctime(&now));
            }
            if (glob.signum == SIGUSR1) {
                report();
            } else {
                glob.killed = true;
                break;
            }
            glob.signum = 0;
        }

        if (!glob.daemonize)
            report();
    }

    for (int i = 0; i < threads; i++)
        pthread_join(thread[i], NULL);
    
    report();

    now = time(0);
    printf("Stopped at %s", ctime(&now));

    addr_list_cleanup(&glob.dstaddr);
    addr_list_cleanup(&glob.locaddr);
    addr_list_cleanup(&glob.srcaddr);
    str_list_cleanup(&glob.netdev);

    return 0;
}

