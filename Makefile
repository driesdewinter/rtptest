
HDRS = rtp_window.h addr_list.h ns.h

default: rtptx rtprx

rtptx: rtptx.c $(HDRS)
	gcc -std=c11 -O3 -Wall -Wextra -pthread -o rtptx rtptx.c -lrt

rtprx: rtprx.c $(HDRS)
	gcc -std=c11 -O3 -Wall -Wextra -pthread -o rtprx rtprx.c -lrt

rtp_window_test: rtp_window_test.c $(HDRS)
	gcc -std=c11 -O0 -Wall -Wextra -pthread -o rtp_window_test rtp_window_test.c -lrt

test: rtp_window_test
	./rtp_window_test

upload: rtptx rtprx
	[ -z "${DCM_IP}" ] || scp rtprx rtptx ${DCM_IP}:
	[ -z "${dcms}" ] || for dcm in ${dcms}; do scp rtprx rtptx $$dcm: ; done

clean:
	rm -f rtptx rtprx rtp_window_test

