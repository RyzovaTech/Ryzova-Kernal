/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef MAC_M8_HEAP_H
#define MAC_M8_HEAP_H

enum { Mac8HeapBytes = 4*1024*1024, Mac8HeapBlocks = 32768 };

typedef struct Mac8Block Mac8Block;
struct Mac8Block {
    unsigned int offset, bytes, requested;
};

typedef struct Mac8Heap Mac8Heap;
struct Mac8Heap {
    unsigned int count;
    Mac8Block blocks[Mac8HeapBlocks];
};

/* Metadata is held outside the guest arena. Offsets returned from allocation
 * are aligned, with Mac8HeapBytes reserved as the failure sentinel. */
unsigned int mac8_alloc(Mac8Heap *, unsigned long long);
int mac8_free(Mac8Heap *, unsigned int);
int mac8_resize(Mac8Heap *, unsigned char *, unsigned int, unsigned long long, unsigned int *);

#endif
