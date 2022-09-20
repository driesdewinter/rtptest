NETMAP ?= n
XDP ?= n
XDP_TOOLS_PATH?=../xdp-tools
HDRS = rtp_window.h addr_list.h ns.h Makefile bpfprog.h

CC?=gcc
BPFC?=clang -target bpf

default: rtptx rtprx

CFLAGS-y=$(CFLAGS)
CFLAGS-$(XDP) += -DXDP
CFLAGS-$(NETMAP) += -DNETMAP
LDFLAGS-y=$(LDFLAGS) -lrt
LDFLAGS-$(XDP) += -lbpf -lelf

# CFLAGS-$(XDP) += -DXDP -I$(XDP_TOOLS_PATH)/lib/libbpf/src/root/usr/include
# LDFLAGS-$(XDP) +=  -L$(XDP_TOOLS_PATH)/lib/libbpf/src -L$(XDP_TOOLS_PATH)/lib/libxdp/ -lxdp -lbpf


rtptx: rtptx.c $(HDRS)
	$(CC) -O3 -Wall -Wextra -pthread -o rtptx $(CFLAGS-y) rtptx.c $(LDFLAGS-y)

rtprx: rtprx.c $(HDRS)
	$(CC) -O3 -Wall -Wextra -pthread -o rtprx $(CFLAGS-y) rtprx.c $(LDFLAGS-y)

rtp_window_test: rtp_window_test.c $(HDRS)
	$(CC) -O0 -Wall -Wextra -pthread -o rtp_window_test $(CFLAGS-y) rtp_window_test.c $(LDFLAGS-y)

ifeq ($(XDP), y)

bpfprog.o: bpfprog.c $(HDRS)
	$(BPFC) -O2 -Wall -Wextra -c $(CFLAGS-y) bpfprog.c -o bpfprog.o

default: bpfprog.o

endif

test: rtp_window_test
	./rtp_window_test

upload: rtptx rtprx
	[ -z "${DCM_IP}" ] || scp rtprx rtptx ${DCM_IP}:
	[ -z "${dcms}" ] || for dcm in ${dcms}; do scp rtprx rtptx $$dcm: ; done

clean:
	rm -f rtptx rtprx rtp_window_test *.o

