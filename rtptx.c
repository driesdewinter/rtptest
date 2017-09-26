#define __STDC_FORMAT_MACROS
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

#include "ns.h"
#include "addr_list.h"

static void exit_with_usage() {
    fprintf(stderr, "Usage: rtptx [--sndbuf] <locips> <dstips> <dstport0> <#TSs> <TS bitrate (Mbps)>\n"); 
    exit(0);
}

struct global_data {
    struct addr_list locaddr;
    struct addr_list dstaddr;
    uint32_t bpi; // bits per interval
    ns_t interval;
    uint16_t dstport0;
    bool sndbuf;
} *global_data_ptr = NULL;

struct thread_data {
    int index;
    uint32_t sent;
    uint32_t prev_sent;
    ns_t spent;
    uint32_t intervalcounter;
    uint32_t prev_spent;
    uint32_t prev_intervalcounter;
    bool stopped;
};

static void *run(void *arg) {
    struct thread_data *thread_data_ptr = arg;
    uint16_t dstport = global_data_ptr->dstport0 + thread_data_ptr->index;

    char threadname[16];
    sprintf(threadname, "%s:%u", "rtptx", dstport);
    prctl(PR_SET_NAME, threadname, 0, 0, 0);
    
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) {
        fprintf(stderr, "socket() failed: %m\n");
        return NULL;
    }
    
    struct sockaddr_in *locaddr = addr_list_get(&global_data_ptr->locaddr, thread_data_ptr->index);
    if (bind(s, (struct sockaddr *)locaddr, sizeof(*locaddr))) {
        char ipaddrbuf[20];
        fprintf(stderr, "bind(%s) failed for port %u: %m\n", 
                inet_ntop(locaddr->sin_family, &locaddr->sin_addr, ipaddrbuf, sizeof(ipaddrbuf)), dstport);
        goto leave; // this is a failure
    }

    uint32_t ttlval = 64;;
    struct sockaddr_in *dstaddr = addr_list_get(&global_data_ptr->dstaddr, thread_data_ptr->index);
    uint8_t *dstip = (uint8_t *)&dstaddr->sin_addr;
    if ((dstip[0] & 0xf0) == 0xe0) {
        if (setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL, &ttlval, sizeof(ttlval))) {
            fprintf(stderr, "setsockopt(IP_MULTICAST_TTL, %d) failed for port %u: %m\n", 
                    ttlval, dstport);
            // go on
        }
    }
    
    if (global_data_ptr->sndbuf) {
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
    uint16_t seqnr = 0;
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
    uint32_t bytebucket = 0;
    
    for (;;) {
        
        ns_t t0 = ns_now();
        
        uint32_t sent = 0;
        for (bytebucket += global_data_ptr->bpi; 
                bytebucket >= 7 * 188; 
                bytebucket -= 7 * 188) {
                
            buf[2] = seqnr >> 8;
            buf[3] = seqnr & 0xff;
            seqnr++;
            
            if (sendmsg(s, &msg, 0) <= 0) {
                fprintf(stderr, "sendmsg() failed for port %u: %m\n", dstport);
                goto leave;
            }
            sent++;
        }
        
        ns_t t1 = ns_now();
        
        thread_data_ptr->intervalcounter++;
        thread_data_ptr->spent += t1 - t0;
        thread_data_ptr->sent += sent;
        
        t += global_data_ptr->interval;
        if (t >= t1 + 1000) {
            struct timeval tv;
            ns_totimeval(t - t1, &tv);
            if (select(0, NULL, NULL, NULL, &tv) < 0)
            {
                fprintf(stderr, "select() failed for port %u: %m\n", dstport);
                goto leave;
            }
        }
    }
leave:
    close(s);
    thread_data_ptr->stopped = true;
    return NULL;
}

int main(int argc, char **argv) {
    struct global_data global_data = { .dstport0 = 0, .sndbuf = false };
    global_data_ptr = &global_data;
    
    while (argc > 6) {
        if (!strcmp(argv[1], "--sndbuf")) {
            global_data.sndbuf = true;
        } else {
            exit_with_usage();  
        }
        argv++;
        argc--;
    }

    if (argc != 6) 
        exit_with_usage();
    
    if (addr_list_parse(&global_data.locaddr, argv[1]))
        exit_with_usage();

    if (addr_list_parse(&global_data.dstaddr, argv[2]))
        exit_with_usage();
    
    global_data.dstport0 = atoi(argv[3]);
    if (!global_data.dstport0) {
        fprintf(stderr, "Not a valid UDP port number: %s\n", argv[3]);
        exit_with_usage();
    }
    
    int N = atoi(argv[4]);
    if (!N) {
        fprintf(stderr, "Not a valid number of TSs: %s\n", argv[4]);
        exit_with_usage();
    }
    
    uint32_t mbps = atoi(argv[5]);
    if (!mbps) {
        fprintf(stderr, "Not a valid bitrate (Mbps): %s\n", argv[5]);
        exit_with_usage();
    }
    global_data.interval = 1000000ULL;
    global_data.bpi = mbps * 125; // * 1M (Mbps -> bps) / 1k (bps -> bpms) / 8 (bpms -> Bpms=bpi)
    printf("Total TS bitrate: %" PRIu32 " Mbps.\n", mbps * N);
    printf("UDP pkts per second per TS: %" PRIu64 "\n", (uint64_t)mbps * 1000000 / 8 / 188 / 7);
    printf("Total UDP pkts per second: %" PRIu64 "\n", (uint64_t)mbps * N * 1000000 / 8 / 188 / 7);
    printf("Using UDP destination ports %u -> %u.\n", global_data.dstport0, global_data.dstport0 + N - 1);
    
    struct thread_data thread_data[N];
    memset(thread_data, 0, sizeof(thread_data));
    pthread_t thread[N];
    
    int i;
    for (i = 0; i < N; i++) {
        thread_data[i].index = i;
        int err = pthread_create(&thread[i], NULL, run, (void*)&thread_data[i]);
        if (err) {
            fprintf(stderr, "pthread_create() failed for the %dth thread: %s\n", i + 1, strerror(err));
            exit(1);
        }
    }
    ns_t t0 = ns_now();
    
    printf("      port |       sent | rate(Mbps) |    load(%%)\n");
    printf("==================================================\n");
    for (i = 0; i < N; i++)
        printf("%10u | %10u | %6" PRIu32 ".%03" PRIu32 " | %10u\n", global_data.dstport0 + i, 0, 0, 0, 0);
    printf("==================================================\n");
    printf("     total | %10u | %6" PRIu32 ".%03" PRIu32 " | %10u\n", 0, 0, 0, 0);
    
    for(;;) {
        int stopped = 0;
        for (i = 0; i < N; i++)
            if (thread_data[i].stopped)
                stopped++;
        if (stopped == N)
            break;

        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        select(0, NULL, NULL, NULL, &tv);
        
        printf("\r");
        for (i = 0; i < N + 2; i++)
            printf("%s", "\033[A");
            
        ns_t t1 = ns_now();
        ns_t elapsed = t1 - t0;

        uint32_t tot_sent = 0;
        uint32_t tot_rate = 0;
        uint32_t tot_load = 0;
        for (i = 0; i < N; i++) {
            uint32_t sent = thread_data[i].sent;
            tot_sent += sent;
            uint32_t rate = (uint64_t)(sent - thread_data[i].prev_sent) * 7 * 188 * 8 * 1000000 / elapsed;
            thread_data[i].prev_sent = sent;
            tot_rate += rate;
            uint32_t spent = thread_data[i].spent; 
            uint32_t intervalcounter  = thread_data[i].intervalcounter; 
            uint32_t load = 0;
            if (intervalcounter - thread_data[i].prev_intervalcounter > 0) {
                load = (spent - thread_data[i].prev_spent) * 100ULL / 
                        (intervalcounter - thread_data[i].prev_intervalcounter) / global_data.interval;
            }
            thread_data[i].prev_spent = spent;
            thread_data[i].prev_intervalcounter = intervalcounter;
            tot_load += load;
            printf("%10u | %10" PRIu32 " | %6" PRIu32 ".%03" PRIu32 " | %10" PRIu32 "\n", 
                    global_data.dstport0 + i, sent, rate/1000, rate%1000, load);
        }
        printf("==================================================\n");
        printf("     total | %10" PRIu32 " | %6" PRIu32 ".%03" PRIu32 " | %10" PRIu32 "\n", 
            tot_sent, tot_rate/1000, tot_rate%1000, tot_load);
           
        t0 = t1;
    }

    for (i = 0; i < N; i++) {
        pthread_join(thread[i], NULL);
    }
    
    addr_list_cleanup(&global_data.locaddr);
    addr_list_cleanup(&global_data.dstaddr);
    
    return 0;
}

