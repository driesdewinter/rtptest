
HDRS = rtp_window.h addr_list.h ns.h

default: rtptx rtprx

rtptx: rtptx.c $(HDRS)
	gcc -O3 -Wall -Wextra -pthread -o rtptx rtptx.c

rtprx: rtprx.c $(HDRS)
	gcc -O3 -Wall -Wextra -pthread -o rtprx rtprx.c

rtp_window_test: rtp_window_test.c $(HDRS)
	gcc -O0 -Wall -Wextra -pthread -o rtp_window_test rtp_window_test.c

test: rtp_window_test
	./rtp_window_test

upload: rtptx rtprx
	[ -z "${DCM_IP}" ] || scp rtprx rtptx ${DCM_IP}:
	[ -z "${dcms}" ] || for dcm in ${dcms}; do scp rtprx rtptx $$dcm: ; done

clean:
	rm -f rtptx rtprx rtp_window_test

