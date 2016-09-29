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

#endif

