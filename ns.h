#ifndef __NS_H__
#define __NS_H__

#include <stdint.h>
#include <time.h>

typedef uint64_t ns_t;

static inline ns_t ns_now() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return 1000000000ULL * ts.tv_sec + ts.tv_nsec;
}

static inline void ns_totimeval(ns_t ns, struct timeval *tv) {
    tv->tv_sec = ns / 1000000000ULL;
    tv->tv_usec = (ns / 1000ULL) % 1000000ULL;
}

#endif

