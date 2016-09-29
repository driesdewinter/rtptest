#include <assert.h>
#include "rtp_window.h"
#include <stdio.h>

int main() {
	int i;
	struct rtp_window window;
	rtp_window_init(&window);
	rtp_window_push(&window, 10000);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	assert(window.valid == 1);
	assert(window.missing == 0);
	assert(window.reordered == 0);
	assert(window.duplicate == 0);
	for (i = 1; i < 1000; i++)
		rtp_window_push(&window, 10000 + i);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	assert(window.valid == 1000);
	assert(window.missing == 0);
	assert(window.reordered == 0);
	assert(window.duplicate == 0);
	
	for (i = 0; i < 100; i++)
		rtp_window_push(&window, 11000 + i);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	
	assert(window.valid == 1100);
	assert(window.missing == 0);
	assert(window.reordered == 0);
	assert(window.duplicate == 0);

	for (i = 0; i < 100; i++)
		rtp_window_push(&window, 11000 + i);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
		
	assert(window.valid == 1100);
	assert(window.missing == 0);
	assert(window.reordered == 0);
	assert(window.duplicate == 100);
	
	rtp_window_push(&window, 11104);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	rtp_window_push(&window, 11103);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	rtp_window_push(&window, 11102);
	rtp_window_push(&window, 11101);
	rtp_window_push(&window, 11100);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	
	assert(window.valid == 1105);
	assert(window.missing == 0);
	assert(window.reordered == 4);
	assert(window.duplicate == 100);

	rtp_window_push(&window, 11104);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	rtp_window_push(&window, 11103);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	rtp_window_push(&window, 11102);
	rtp_window_push(&window, 11101);
	rtp_window_push(&window, 11100);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	
	assert(window.valid == 1105);
	assert(window.missing == 0);
	assert(window.reordered == 4);
	assert(window.duplicate == 105);

	rtp_window_push(&window, 11119);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	rtp_window_push(&window, 11115);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	rtp_window_push(&window, 11116);
	rtp_window_push(&window, 11117);
	rtp_window_push(&window, 11118);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	
	assert(window.valid == 1110);
	assert(window.duplicate == 105);
	assert(window.reordered == 8);
	assert(window.missing == 10);
	
	for (i = 0; i < 1000; i++)
		rtp_window_push(&window, 10000 + i);
	printf("seqnr=%d valid=%d missing=%d reordered=%d duplicates=%d\n", 
		window.seqnr, window.valid, window.missing, window.reordered, window.duplicate);
	
	assert(window.valid == 2110);
	assert(window.missing == 10);
	assert(window.reordered == 8);
	assert(window.duplicate == 105);
	assert(window.reset == 1);
	
	return 0;
}

