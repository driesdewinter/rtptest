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
#include <sys/ioctl.h>
#include <net/if.h>
#include <pthread.h>
#include <sys/prctl.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>

#include "ns.h"
#include "addr_list.h"
#include "rtp_window.h"

static void exit_with_usage() {
    fprintf(stderr, "Usage: rtprx [-d] [-i <ms>] [-v] <locips> <dstips> <srcips> <dstport0> <#TSs>\n");
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
};
struct global_data* global_data_ptr = NULL;

struct thread_data {
    int index;
    struct rtp_window rtp_window;
    uint32_t prev_valid;
    bool stopped;
    uint32_t max_burst;
} *thread_data_ptr = NULL;

static void sighandle(int signum)
{
  global_data_ptr->signum = signum;
}

static void *run(void *arg) {
    struct thread_data *thread_data_ptr = arg;
    uint16_t dstport = global_data_ptr->dstport0 + thread_data_ptr->index;

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
    
    struct sockaddr_in dstaddr = *addr_list_get(&global_data_ptr->dstaddr, thread_data_ptr->index);
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
        struct sockaddr_in* locaddr = addr_list_get(&global_data_ptr->locaddr, thread_data_ptr->index);
        struct sockaddr_in* srcaddr = addr_list_get(&global_data_ptr->srcaddr, thread_data_ptr->index);
        
        if (srcaddr->sin_addr.s_addr == INADDR_ANY)
        { // -> EXCLUDE(), a.k.a. non-source specific multicast
          struct ip_mreq mreq;
          mreq.imr_multiaddr = dstaddr.sin_addr;
          mreq.imr_interface = locaddr->sin_addr;

          if (setsockopt(s, SOL_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
              char dstaddrbuf[20];
              char locaddrbuf[20];

              fprintf(stderr, "setsockopt(IP_ADD_MEMBERSHIP, %s@%s:EX()) failed for port %u: %m\n",
                      inet_ntop(dstaddr.sin_family, &dstaddr.sin_addr, dstaddrbuf, sizeof(dstaddrbuf)),
                      inet_ntop(locaddr->sin_family, &locaddr->sin_addr, locaddrbuf, sizeof(locaddrbuf)),
                      dstport);
              goto leave;
          }
        }
        else
        { // -> INCLUDE(srcaddr), a.k.a. source specific multicast
          struct ip_mreq_source mreq;
          mreq.imr_multiaddr = dstaddr.sin_addr;
          mreq.imr_interface = locaddr->sin_addr;
          mreq.imr_sourceaddr = srcaddr->sin_addr;

          if (setsockopt(s, SOL_IP, IP_ADD_SOURCE_MEMBERSHIP, &mreq, sizeof(mreq))) {
              char dstaddrbuf[20];
              char locaddrbuf[20];
              char srcaddrbuf[20];

              fprintf(stderr, "setsockopt(IP_ADD_SOURCE_MEMBERSHIP, %s@%s:IN(%s)) failed for port %u: %m\n",
                      inet_ntop(dstaddr.sin_family, &dstaddr.sin_addr, dstaddrbuf, sizeof(dstaddrbuf)),
                      inet_ntop(locaddr->sin_family, &locaddr->sin_addr, locaddrbuf, sizeof(locaddrbuf)),
                      inet_ntop(srcaddr->sin_family, &srcaddr->sin_addr, srcaddrbuf, sizeof(srcaddrbuf)),
                      dstport);
              goto leave;

          }
        }
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

    for (;!global_data_ptr->killed;) {
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
          uint16_t seqnr = buf[2] << 8 | buf[3];
          int16_t diff = seqnr - thread_data_ptr->rtp_window.seqnr;
          if (global_data_ptr->verbose && !thread_data_ptr->rtp_window.firstpkt && diff != 0) {
            time_t now = time(0);
            char nowstr[26];
            printf("Port %d expected seqnr %d but got %d at %s",
                dstport, thread_data_ptr->rtp_window.seqnr, seqnr, ctime_r(&now, nowstr));
            fflush(stdout);
          }
          rtp_window_push(&thread_data_ptr->rtp_window, seqnr);
          burst++;
        }
        ns_t t1 = ns_now();

        t += global_data_ptr->interval;
        if (burst > thread_data_ptr->max_burst) thread_data_ptr->max_burst = burst;

        if (t >= t1 + 1000) {
            struct timeval tv;
            ns_totimeval(t - t1, &tv);
            select(0, NULL, NULL, NULL, &tv);
        }
    }
leave:
    if (s > 0)
        close(s);
    thread_data_ptr->stopped = true;
    return NULL;
}

static void report()
{
  static bool reported = false;

  if (!reported || global_data_ptr->daemonize) {
      reported = true;
  } else {
      printf("\r");
      for (int i = 0; i < global_data_ptr->N + 4; i++)
          printf("%s", "\033[A");
  }

  printf("      port |      valid |    missing |  reordered |  duplicate |      reset | rate(Mbps) |  max_burst\n");
  printf("=====================================================================================================\n");

  ns_t t1 = ns_now();
  ns_t elapsed = t1 - global_data_ptr->t0;

  struct rtp_window tot_window;
  rtp_window_init(&tot_window);
  uint32_t tot_rate = 0;
  uint32_t max_burst = 0;

  for (int i = 0; i < global_data_ptr->N; i++) {
      uint32_t valid = thread_data_ptr[i].rtp_window.valid;
      uint32_t rate = (uint64_t)(valid - thread_data_ptr[i].prev_valid) * 7 * 188 * 8 * 1000000 / elapsed;
      thread_data_ptr[i].prev_valid = valid;
      printf("%10" PRIu32 " | %10" PRIu32 " | %10" PRIu32 " | %10" PRIu32 " | %10" PRIu32 " | %10" PRIu32 " | %6" PRIu32 ".%03" PRIu32 " | %10" PRIu32 "\n",
              global_data_ptr->dstport0 + i,
              thread_data_ptr[i].rtp_window.valid,
              thread_data_ptr[i].rtp_window.missing,
              thread_data_ptr[i].rtp_window.reordered,
              thread_data_ptr[i].rtp_window.duplicate,
              thread_data_ptr[i].rtp_window.reset,
              rate / 1000, rate % 1000,
              thread_data_ptr[i].max_burst);
      tot_window.valid += thread_data_ptr[i].rtp_window.valid;
      tot_window.missing += thread_data_ptr[i].rtp_window.missing;
      tot_window.reordered += thread_data_ptr[i].rtp_window.reordered;
      tot_window.duplicate += thread_data_ptr[i].rtp_window.duplicate;
      tot_window.reset += thread_data_ptr[i].rtp_window.reset;
      if (thread_data_ptr[i].max_burst > max_burst) max_burst = thread_data_ptr[i].max_burst;
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

  global_data_ptr->t0 = t1;
}

int main(int argc, char **argv) {
    struct global_data global_data = { .interval = 10000000ULL };
    global_data_ptr = &global_data;

    while (argc > 6) {
        if (!strcmp(argv[1], "-d")) {
            global_data.daemonize = true;
        } else if (!strcmp(argv[1], "-v")) {
            global_data.verbose = true;
        } else if (!strcmp(argv[1], "-i")) {
            global_data.interval = 1000000ULL * atoi(argv[2]);
            argv++; argc--;
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
    
    if (addr_list_parse(&global_data.locaddr, argv[1]))
        exit_with_usage();

    if (addr_list_parse(&global_data.dstaddr, argv[2]))
        exit_with_usage();

    if (addr_list_parse(&global_data.srcaddr, argv[3]))
        exit_with_usage();
    
    global_data.dstport0 = atoi(argv[4]);
    if (!global_data.dstport0) {
        fprintf(stderr, "Not a valid UDP port number: %s\n", argv[4]);
        exit_with_usage();
    }
    
    global_data.N = atoi(argv[5]);
    if (!global_data.N) {
        fprintf(stderr, "Not a valid number of TSs: %s\n", argv[5]);
        exit_with_usage();
    }
    
    struct thread_data thread_data[global_data.N];
    memset(thread_data, 0, sizeof(thread_data));
    thread_data_ptr = thread_data;
    global_data.t0 = ns_now();
    time_t now = time(0);
    printf("Kicked off at %s", ctime(&now));
    fflush(stdout);

    if (global_data.daemonize)
        daemon(1, 1);
    else
       report();

    pthread_t thread[global_data.N];
    for (int i = 0; i < global_data.N; i++) {
        thread_data[i].stopped = false;
        thread_data[i].index = i;
        rtp_window_init(&thread_data[i].rtp_window);
        int err = pthread_create(&thread[i], NULL, run, &thread_data[i]);
        if (err) {
            fprintf(stderr, "pthread_create() failed for the %dth thread: %s\n", i + 1, strerror(err));
            exit(1);
        }
    }

    signal(SIGUSR1, sighandle);
    signal(SIGTERM, sighandle);
    signal(SIGINT, sighandle);

    for(;;) {
        int stopped = 0;
        for (int i = 0; i < global_data.N; i++)
            if (thread_data[i].stopped)
                stopped++;
        if (stopped == global_data.N)
            break;

        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        select(0, NULL, NULL, NULL, &tv);
        
        if (global_data.signum) {
            if (global_data.daemonize) {
              time_t now = time(0);
              printf("Caught signal %d at %s", global_data.signum, ctime(&now));
            }
            if (global_data.signum == SIGUSR1) {
                report();
            } else {
                global_data.killed = true;
                break;
            }
            global_data.signum = 0;
        }

        if (!global_data.daemonize)
            report();
    }

    for (int i = 0; i < global_data.N; i++)
        pthread_join(thread[i], NULL);
    
    report();

    now = time(0);
    printf("Stopped at %s", ctime(&now));

    return 0;
}

