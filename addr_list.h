#ifndef __ADDR_LIST_H__
#define __ADDR_LIST_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct addr_list {
    struct sockaddr_in *data;
    int size;
};

static inline int addr_list_parse(struct addr_list *addr, char *argv) {
    char *arg;
    int size = 1;
    for (arg = argv; *arg; arg++)
        if (*arg == ',')
            size++;
    addr->size = 0;
    addr->data = calloc(size, sizeof(struct sockaddr_in)); 
    for (arg = strtok(argv,  ","); arg; arg = strtok(NULL, ",")) {   
        addr->data[addr->size].sin_family = AF_INET;
        if (inet_pton(AF_INET, arg, &addr->data[addr->size].sin_addr) != 1) {
            fprintf(stderr, "Not a valid IPv4-address: %s\n", arg);
            return -1;
        }
        addr->size++;
    }
    if (addr->size == 0) {
        fprintf(stderr, "Contains no valid IPv4-address: %s\n", argv);
        return -1;
    }
    return 0;
}

static inline void addr_list_cleanup(struct addr_list *addr) {
    free(addr->data);
}

static inline struct sockaddr_in *addr_list_get(struct addr_list *addr, int index) {
    return &addr->data[index % addr->size];
}

#endif

