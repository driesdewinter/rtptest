#ifndef __RTP_WINDOW_H__
#define __RTP_WINDOW_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#define RTP_WINDOW_LEN 512
struct rtp_window {
	uint32_t mask[RTP_WINDOW_LEN / sizeof(uint32_t) / 8];
	
	uint16_t seqnr;
	bool firstpkt;

	uint32_t valid;
	uint32_t missing;
	uint32_t reordered;
	uint32_t duplicate;
	uint32_t reset;
};

static inline void rtp_window_init(struct rtp_window* window) {
	memset(window->mask, 0xff, RTP_WINDOW_LEN / 8);
	window->valid = 0;
	window->missing = 0;
	window->reordered = 0;
	window->duplicate = 0;
	window->reset = 0;
	window->firstpkt = true;
}

static inline bool rtp_window_has(struct rtp_window* window, uint16_t seqnr) {
	return window->mask[seqnr % RTP_WINDOW_LEN / sizeof(uint32_t) / 8] & (1 << seqnr % (sizeof(uint32_t) * 8));
}

static inline void rtp_window_set(struct rtp_window* window, uint16_t seqnr) {
	window->mask[seqnr % RTP_WINDOW_LEN / sizeof(uint32_t) / 8] |= (1 << seqnr % (sizeof(uint32_t) * 8));
}

static inline void rtp_window_clr(struct rtp_window* window, uint16_t seqnr) {
	window->mask[seqnr % RTP_WINDOW_LEN / sizeof(uint32_t) / 8] &= ~(1 << seqnr % (sizeof(uint32_t) * 8));
}

static inline void rtp_window_push(struct rtp_window* window, uint16_t seqnr) {
	if (window->firstpkt) {
		window->seqnr = seqnr;
		window->firstpkt = false;
	}
	
	int16_t diff = seqnr - window->seqnr;
	if (diff > RTP_WINDOW_LEN || diff < -RTP_WINDOW_LEN) {
		window->seqnr = seqnr + 1;
		memset(window->mask, 0xff, RTP_WINDOW_LEN / 8);
		window->reset++;
		window->valid++;
	} else if (diff >= 0) {
		for (; window->seqnr != seqnr; window->seqnr++) {
			rtp_window_clr(window, window->seqnr);
			window->missing++;
		}
		rtp_window_set(window, window->seqnr++);
		window->valid++;
	} else if (diff < 0) {
		if (rtp_window_has(window, seqnr)) {
			window->duplicate++;
		} else {
			window->reordered++;
			window->missing--;
			window->valid++;
			rtp_window_set(window, seqnr);
		}
	}
}

#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

static inline int get_nrqueues(const char* dev)
{
        struct ethtool_channels channels = { .cmd = ETHTOOL_GCHANNELS };
        struct ifreq ifr;
        int fd, err, ret;

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
                return -errno;

        ifr.ifr_data = (void *)&channels;
        memcpy(ifr.ifr_name, dev, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        err = ioctl(fd, SIOCETHTOOL, &ifr);

        if (err)
            fprintf(stderr, "ioctl(SIOCETHTOOL, {dev=%s cmd=ETHTOOL_GCHANNELS}) failed: %m\n", dev);

        if (err || channels.combined_count == 0)
                /* If the device says it has no channels, then all traffic
                 * is sent to a single stream, so max queues = 1.
                 */
                ret = 1;
        else
                ret = channels.combined_count;

        close(fd);
        return ret;
}


#endif

