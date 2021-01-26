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
#include <net/if.h>
#include <sys/prctl.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include "ns.h"
#include "addr_list.h"

static void exit_with_usage() {
    fprintf(stderr, "Usage: rtptx [--netmap <devs> [--txonly] [--dmac <dmacs>]] [-d] [--sndbuf] [-i <ms>] [-v] <locips> <dstips> <dstport0> <#TSs> <TS bitrate (Mbps)>\n");
    exit(0);
}

struct global_data {
    struct addr_list locaddr;
    struct addr_list dstaddr;
    struct ether_addr_list dmac;
    uint32_t bpi; // bits per interval
    ns_t interval;
    uint16_t dstport0;
    bool sndbuf;
    bool daemonize;
    int signum;
    int killed;
    int N;
    ns_t t0;
    struct str_list netmap_dev;
    bool txonly;
    bool verbose;
} *globptr = NULL;

struct packet {
    uint8_t eth[14];
    uint8_t ip[20];
    uint8_t udp[8];
    uint8_t rtp[12];
    uint8_t mpeg[7 * 188];
};

struct ts_data {
    uint32_t sent;
    uint32_t prev_sent;
    uint32_t dropped;
    ns_t spent;
    uint32_t intervalcounter;
    uint32_t prev_spent;
    uint32_t prev_intervalcounter;
    bool running;
    ns_t max_drift;
    struct packet pkt;
    uint16_t seqnr;
    uint32_t bytebucket;
} *tsptr0 = NULL;

static void sighandle(int signum) {
  globptr->signum = signum;
}

static void *run(void *arg) {
    struct ts_data *tsptr = arg;
    int index = tsptr - tsptr0;
    uint16_t dstport = globptr->dstport0 + index;

    char threadname[16];
    sprintf(threadname, "%s:%u", "rtptx", dstport);
    prctl(PR_SET_NAME, threadname, 0, 0, 0);
    
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        fprintf(stderr, "socket() failed: %m\n");
        return NULL;
    }
    
    struct sockaddr_in *locaddr = addr_list_get(&globptr->locaddr, index);
    if (bind(s, (struct sockaddr *)locaddr, sizeof(*locaddr))) {
        char ipaddrbuf[20];
        fprintf(stderr, "bind(%s) failed for port %u: %m\n", 
                inet_ntop(locaddr->sin_family, &locaddr->sin_addr, ipaddrbuf, sizeof(ipaddrbuf)), dstport);
        goto leave; // this is a failure
    }

    uint32_t ttlval = 64;;
    struct sockaddr_in *dstaddr = addr_list_get(&globptr->dstaddr, index);
    uint8_t *dstip = (uint8_t *)&dstaddr->sin_addr;
    if ((dstip[0] & 0xf0) == 0xe0) {
        if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttlval, sizeof(ttlval))) {
            fprintf(stderr, "setsockopt(IP_MULTICAST_TTL, %d) failed for port %u: %m\n", 
                    ttlval, dstport);
            // go on
        }
    }
    
    if (globptr->sndbuf) {
        int bufsize = 5242880; // copied from /proc/sys/net/core/wmem_max
        if (setsockopt(s, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(int)) < 0) {
                fprintf(stderr, "setsockopt(SO_SNDBUF, %d) failed for port %u: %m\n", 
                        bufsize, dstport);
        }
    }
    
    uint8_t buf[12 + 7 * 188];
    struct iovec iov;
    struct msghdr msg;
    struct sockaddr_in addr = *dstaddr;
    addr.sin_port = htons(dstport);
    memset(buf, 0xff, 12 + 7 * 188);
    buf[0] = 0x80;
    buf[1] = 0x21;
    int i;
    for (i = 0; i < 7; i++) {
        buf[12 + i * 188 + 0] = 0x47;
        buf[12 + i * 188 + 1] = 0x1f;
        buf[12 + i * 188 + 2] = 0xff;
        buf[12 + i * 188 + 3] = 0x00;
    }
    iov.iov_base = buf;
    iov.iov_len = 12 + 7 * 188;
    msg.msg_name = &addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;
    
    ns_t t = ns_now();
    
    for (;!globptr->killed;) {
        
        ns_t t0 = ns_now();
        
        uint32_t sent = 0;
        for (tsptr->bytebucket += globptr->bpi;
                tsptr->bytebucket >= 7 * 188;
                tsptr->bytebucket -= 7 * 188) {
                
            buf[2] = tsptr->seqnr >> 8;
            buf[3] = tsptr->seqnr & 0xff;
            tsptr->seqnr++;
            
            if (sendmsg(s, &msg, 0) <= 0) {
                fprintf(stderr, "sendmsg() failed for port %u: %m\n", dstport);
                goto leave;
            }
            sent++;
        }
        
        ns_t t1 = ns_now();
        
        tsptr->intervalcounter++;
        tsptr->spent += t1 - t0;
        tsptr->sent += sent;
        
        t += globptr->interval;

        if (t >= t1 + 1000) {
            struct timeval tv;
            ns_totimeval(t - t1, &tv);
            select(0, NULL, NULL, NULL, &tv);
        }
        else if (t < t1 && t1 - t > tsptr->max_drift)
        {
            tsptr->max_drift = t1 - t;
        }
    }
leave:
    close(s);
    tsptr->running = false;
    return NULL;
}

#define NETMAP
#ifdef NETMAP

#include <net/netmap.h>
#include <net/netmap_user.h>

#include <netpacket/packet.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <ifaddrs.h>

struct vlan_header {
    uint16_t tag;
    uint16_t ether_type;
};

static void* run_netmap(void* arg) {
    struct ts_data* threadptr = (struct ts_data*)arg;
    int index = threadptr - tsptr0;
    int step = globptr->netmap_dev.size;

    const char* dev = str_list_get(&globptr->netmap_dev, index);

    char threadname[16];
    sprintf(threadname, "%s:%s", "rtptx", dev);
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

    for (int tsindex = index; tsindex < globptr->N; tsindex += step)
    {
        struct ts_data* tsptr = &tsptr0[tsindex];
        struct ether_header* eth = (struct ether_header*)tsptr->pkt.eth;
        struct iphdr* ip = (struct iphdr*)tsptr->pkt.ip;
        struct udphdr* udp = (struct udphdr*)tsptr->pkt.udp;
        struct ifaddrs *ifaphead, *ifap;
        if (getifaddrs(&ifaphead) != 0) {
            fprintf(stderr, "getifaddrs %s failed", dev);
            goto leave;
        }
        for (ifap = ifaphead; ifap; ifap = ifap->ifa_next) {
            if (ifap->ifa_addr == NULL)
                continue;
            if (strncmp(ifap->ifa_name, dev, IFNAMSIZ) != 0)
                continue;
            if (ifap->ifa_addr->sa_family == AF_PACKET) {
                struct sockaddr_ll *sll = (struct sockaddr_ll *)ifap->ifa_addr;
                memcpy(eth->ether_shost, sll->sll_addr, 6);
            } else if (ifap->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sin = (struct sockaddr_in *)ifap->ifa_addr;
                ip->saddr = sin->sin_addr.s_addr;
            }
        }
        freeifaddrs(ifaphead);

        if (globptr->dmac.size) {
            memcpy(eth->ether_dhost, ether_addr_list_get(&globptr->dmac, tsindex), 6);
        } else {
            struct sockaddr_in dstaddr = *addr_list_get(&globptr->dstaddr, tsindex);
            const uint8_t *dstip = (const uint8_t *)&dstaddr.sin_addr;
            eth->ether_dhost[0] = 0x01;
            eth->ether_dhost[1] = 0x00;
            eth->ether_dhost[2] = 0x5E;
            eth->ether_dhost[3] = dstip[1] & ~0x80;
            eth->ether_dhost[4] = dstip[2];
            eth->ether_dhost[5] = dstip[3];
        }

        eth->ether_type = htons(ETH_P_IP);

        ip->version = 4;
        ip->ihl = 5;
        ip->check = 0;
        ip->frag_off = htons(0x4000); // do not fragment
        ip->id = htons(0);
        ip->protocol = IPPROTO_UDP;
        ip->tos = 0;
        ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 12 + 7 * 188);
        ip->ttl = 64;
        if (globptr->locaddr.size && globptr->locaddr.data[0].sin_addr.s_addr != INADDR_ANY)
          ip->saddr = addr_list_get(&globptr->locaddr, tsindex)->sin_addr.s_addr;
        // else it is hopefully automatically assigned by the getifaddrs loop.
        ip->daddr = addr_list_get(&globptr->dstaddr, tsindex)->sin_addr.s_addr;
        // and finally the checksum
        uint32_t ipcsum = 0;
        for (const uint16_t* p = (const uint16_t*)tsptr->pkt.ip; p < (const uint16_t*)tsptr->pkt.udp; p++) {
            ipcsum += ntohs(*p);
        }
        ip->check = htons(~(ipcsum + (ipcsum >> 16)));

        udp->check = htons(0);
        udp->len = htons(sizeof(struct udphdr) + 12 + 7 * 188);
        udp->source = htons(49152);
        udp->dest = htons(globptr->dstport0 + tsindex);
        memset(tsptr->pkt.rtp, 0xff, 12);
        memset(tsptr->pkt.mpeg, 0xff, 7 * 188);
        tsptr->pkt.rtp[0] = 0x80;
        tsptr->pkt.rtp[1] = 0x21;
        int i;
        for (i = 0; i < 7; i++) {
            tsptr->pkt.mpeg[i * 188 + 0] = 0x47;
            tsptr->pkt.mpeg[i * 188 + 1] = 0x1f;
            tsptr->pkt.mpeg[i * 188 + 2] = 0xff;
            tsptr->pkt.mpeg[i * 188 + 3] = 0x00;
        }
    }

    ns_t t = ns_now();

    for (;!globptr->killed;) {

        ns_t t0 = ns_now();

        if (ioctl(fd, NIOCRXSYNC, NULL) < 0) {
            fprintf(stderr, "ioctl(/dev/netmap, NIOCRXSYNC) failed: %m\n");
            goto leave;
        }

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

        for (int tsindex = index; tsindex < globptr->N; tsindex += step)
        {
            struct netmap_ring* txringp = NETMAP_TXRING(ifp, tsindex/step % ifp->ni_tx_rings);
            struct ts_data* tsptr = &tsptr0[tsindex];
            uint32_t txhead = txringp->head, txtail = txringp->tail;

            uint32_t sent = 0, dropped = 0;
            for (tsptr->bytebucket += globptr->bpi;
                    tsptr->bytebucket >= 7 * 188;
                    tsptr->bytebucket -= 7 * 188) {

                tsptr->pkt.rtp[2] = tsptr->seqnr >> 8;
                tsptr->pkt.rtp[3] = tsptr->seqnr & 0xff;
                tsptr->seqnr++;

                if (txhead == txtail)
                {
                    dropped++;
                    continue; // this is packet drop
                }

                struct netmap_slot* txslotp = &txringp->slot[txhead];
                uint8_t* pkt = (uint8_t*)NETMAP_BUF(txringp, txslotp->buf_idx);
                memcpy(pkt, &tsptr->pkt, sizeof(struct packet));
                txslotp->len = sizeof(struct packet);
                txhead = nm_ring_next(txringp, txhead);
                sent++;
            }

            txringp->head = txringp->cur = txhead;
            tsptr->sent += sent;
            tsptr->dropped += dropped;

            if (globptr->verbose && dropped > 0) {
                time_t now = time(0);
                char nowstr[26];
                printf("Dropped %u packets on port %d at %s",
                    dropped, globptr->dstport0 + tsindex, ctime_r(&now, nowstr));
                fflush(stdout);
            }
        }

        // from nic rx ring to rtp window or to host rx ring
        if (!globptr->txonly)
        {
          for (uint32_t rxringi = 0; rxringi < ifp->ni_rx_rings; rxringi++) {
              struct netmap_ring* rxringp = NETMAP_RXRING(ifp, rxringi);
              struct netmap_ring* txringp = NETMAP_TXRING(ifp, ifp->ni_tx_rings + rxringi % ifp->ni_host_tx_rings);
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

        threadptr->intervalcounter++;
        threadptr->spent += t1 - t0;

        t += globptr->interval;

        if (t >= t1 + 1000) {
            struct timeval tv;
            ns_totimeval(t - t1, &tv);
            select(0, NULL, NULL, NULL, &tv);
        }
        else if (t < t1 && t1 - t > threadptr->max_drift)
        {
            threadptr->max_drift = t1 - t;
        }
    }

leave:
    if (mem != MAP_FAILED)
        munmap(mem, reg.nr_memsize);
    if (fd > 0)
        close(fd);
    threadptr->running = false;
    return NULL;
}

#else

static void* run_netmap(void* arg)
{
  struct thread_data *threadptr = arg;
  fprintf(stderr, "Netmap support was disabled at compile time. Exiting...\n");
  threadptr->running = false;
  return NULL;
}

#endif


static void report() {
    static bool reported = false;

    if (!reported || globptr->daemonize) {
        reported = true;
    } else {
        printf("\r");
        for (int i = 0; i < globptr->N + 4; i++)
            printf("%s", "\033[A");
    }

    printf("      port |       sent | rate(Mbps) |    load(%%) | max_drift(ms)\n");
    printf("=================================================================\n");

    ns_t t1 = ns_now();
    ns_t elapsed = t1 - globptr->t0;

    uint32_t tot_sent = 0;
    uint32_t tot_rate = 0;
    uint32_t tot_load = 0;
    ns_t tot_max_drift = 0;
    for (int i = 0; i < globptr->N; i++) {
        uint32_t sent = tsptr0[i].sent;
        tot_sent += sent;
        uint32_t rate = (uint64_t)(sent - tsptr0[i].prev_sent) * 7 * 188 * 8 * 1000000 / (elapsed?:1);
        tsptr0[i].prev_sent = sent;
        tot_rate += rate;
        uint32_t spent = tsptr0[i].spent;
        uint32_t intervalcounter  = tsptr0[i].intervalcounter;
        uint32_t load = 0;
        if (intervalcounter - tsptr0[i].prev_intervalcounter > 0) {
            load = (spent - tsptr0[i].prev_spent) * 100ULL /
                    (intervalcounter - tsptr0[i].prev_intervalcounter) / globptr->interval;
        }
        ns_t max_drift = tsptr0[i].max_drift;
        if (max_drift > tot_max_drift)
            tot_max_drift = max_drift;
        tsptr0[i].prev_spent = spent;
        tsptr0[i].prev_intervalcounter = intervalcounter;
        tot_load += load;
        printf("%10u | %10" PRIu32 " | %6" PRIu32 ".%03" PRIu32 " | %10" PRIu32 " | %6" PRIu64 ".%06" PRIu64 "\n",
                globptr->dstport0 + i, sent, rate/1000, rate%1000, load, max_drift/1000000UL, max_drift%1000000UL);
    }
    printf("=================================================================\n");
    printf("     total | %10" PRIu32 " | %6" PRIu32 ".%03" PRIu32 " | %10" PRIu32 " | %6" PRIu64 ".%06" PRIu64 "\n",
        tot_sent, tot_rate/1000, tot_rate%1000, tot_load, tot_max_drift/1000000UL, tot_max_drift%1000000UL);
    fflush(stdout);

    globptr->t0 = t1;
}

int main(int argc, char **argv) {
    struct global_data glob = { .interval = 1000000ULL };
    globptr = &glob;
    bool netmap = false;
    
    while (argc > 6) {
        if (!strcmp(argv[1], "--sndbuf")) {
            glob.sndbuf = true;
        } else if (!strcmp(argv[1], "-d")) {
            glob.daemonize = true;
        } else if (!strcmp(argv[1], "-v")) {
            glob.verbose = true;
        } else if (!strcmp(argv[1], "-i")) {
            glob.interval = 1000000ULL * atoi(argv[2]);
            argv++; argc--;
        } else if (!strcmp(argv[1], "--netmap")) {
            str_list_parse(&glob.netmap_dev, argv[2]);
            netmap = true;
            argv++; argc--;
        } else if (!strcmp(argv[1], "--dmac")) {
            ether_addr_list_parse(&glob.dmac, argv[2]);
            argv++; argc--;
        } else if (!strcmp(argv[1], "--txonly")) {
            glob.txonly = true;
        } else {
            exit_with_usage();  
        }
        argv++;
        argc--;
    }

    if (argc != 6) 
        exit_with_usage();
    
    if (addr_list_parse(&glob.locaddr, argv[1]))
        exit_with_usage();

    if (addr_list_parse(&glob.dstaddr, argv[2]))
        exit_with_usage();
    
    glob.dstport0 = atoi(argv[3]);
    if (!glob.dstport0) {
        fprintf(stderr, "Not a valid UDP port number: %s\n", argv[3]);
        exit_with_usage();
    }
    
    glob.N = atoi(argv[4]);
    if (!glob.N) {
        fprintf(stderr, "Not a valid number of TSs: %s\n", argv[4]);
        exit_with_usage();
    }
    
    uint32_t mbps = atoi(argv[5]);
    if (!mbps) {
        fprintf(stderr, "Not a valid bitrate (Mbps): %s\n", argv[5]);
        exit_with_usage();
    }
    glob.interval = 1000000ULL;
    glob.bpi = mbps * 125; // * 1M (Mbps -> bps) / 1k (bps -> bpms) / 8 (bpms -> Bpms=bpi)
    glob.t0 = ns_now();
    printf("Total TS bitrate: %" PRIu32 " Mbps.\n", mbps * glob.N);
    printf("UDP pkts per second per TS: %" PRIu64 "\n", (uint64_t)mbps * 1000000 / 8 / 188 / 7);
    printf("Total UDP pkts per second: %" PRIu64 "\n", (uint64_t)mbps * glob.N * 1000000 / 8 / 188 / 7);
    printf("Using UDP destination ports %u -> %u.\n", glob.dstport0, glob.dstport0 + glob.N - 1);
    time_t now = time(0);
    printf("Kicked off at %s", ctime(&now));
    fflush(stdout);
    
    struct ts_data ts[glob.N];
    memset(ts, 0, sizeof(ts));
    tsptr0 = ts;

    if (glob.daemonize)
        daemon(1, 1);
    else
       report();

    int threads = glob.N;
    if (netmap && threads > glob.netmap_dev.size) threads = glob.netmap_dev.size;
    pthread_t thread[threads];
    if (netmap) {
        for (int i = 0; i < threads; i++) {
            ts[i].running = true;
            int err = pthread_create(&thread[i], NULL, run_netmap, &ts[i]);
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

    for (int i = 0; i < threads; i++) {
        pthread_join(thread[i], NULL);
    }
    
    report();

    now = time(0);
    printf("Stopped at %s", ctime(&now));

    addr_list_cleanup(&glob.locaddr);
    addr_list_cleanup(&glob.dstaddr);
    str_list_cleanup(&glob.netmap_dev);
    ether_addr_list_cleanup(&glob.dmac);
    
    return 0;
}

