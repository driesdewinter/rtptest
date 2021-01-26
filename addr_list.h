#ifndef __ADDR_LIST_H__
#define __ADDR_LIST_H__

#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
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

struct str_list {
    const char** data;
    int size;
};

static inline int str_list_parse(struct str_list *str, char *argv) {
    char *arg;
    int size = 1;
    for (arg = argv; arg; arg = strchr(arg, ',')) {
        size++;
        arg++; // move beyond the comma
    }
    str->size = 0;
    str->data = calloc(size, sizeof(const char*));
    for (arg = strtok(argv,  ","); arg; arg = strtok(NULL, ","))
        str->data[str->size++] = arg;
    if (str->size == 0) {
        fprintf(stderr, "Contains no valid string: %s\n", argv);
        return -1;
    }
    return 0;
}

static inline void str_list_cleanup(struct str_list *str) {
    free(str->data);
}

static inline const char* str_list_get(struct str_list *str, int index) {
    return str->data[index % str->size];
}

struct ether_addr_list {
    struct ether_addr* data;
    int size;
};

static inline int ether_addr_list_parse(struct ether_addr_list *addr, char *argv) {
    char *arg;
    int size = 1;
    for (arg = argv; arg; arg = strchr(arg, ',')) {
        size++;
        arg++; // move beyond the comma
    }
    addr->size = 0;
    addr->data = calloc(size, sizeof(struct ether_addr));
    for (arg = strtok(argv,  ","); arg; arg = strtok(NULL, ",")) {
        struct ether_addr* e = ether_aton(arg);
        if (e == NULL) {
            fprintf(stderr, "Invalid MAC address: %s", arg);
            return -1;
        }
        memcpy(&addr->data[addr->size++], e, sizeof(struct ether_addr));
    }
    if (addr->size == 0) {
        fprintf(stderr, "Contains no valid MAC address: %s\n", argv);
        return -1;
    }
    return 0;
}

static inline void ether_addr_list_cleanup(struct ether_addr_list *addr) {
    free(addr->data);
}

static inline struct ether_addr* ether_addr_list_get(struct ether_addr_list *addr, int index) {
    return &addr->data[index % addr->size];
}

#endif

