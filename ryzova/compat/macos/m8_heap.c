/* SPDX-License-Identifier: AGPL-3.0-only */
#ifdef MAC_PLAN9
#include <u.h>
#include <libc.h>
#else
#include <string.h>
#endif
#include "m8_heap.h"

unsigned int
mac8_alloc(Mac8Heap *heap, unsigned long long bytes)
{
    unsigned int i, start = 0, size;
    Mac8Block *b;
    if(bytes>Mac8HeapBytes || heap->count==Mac8HeapBlocks)
        return Mac8HeapBytes;
    size = bytes ? ((unsigned int)bytes+15)&~15U : 16;
    for(i=0; i<heap->count; i++){
        b = &heap->blocks[i];
        if(size<=b->offset-start)
            break;
        start = b->offset+b->bytes;
    }
    if(size>Mac8HeapBytes-start)
        return Mac8HeapBytes;
    b = &heap->blocks[i];
    memmove(b+1, b, (heap->count-i)*sizeof(*b));
    b->offset = start;
    b->bytes = size;
    heap->count++;
    return start;
}

int
mac8_free(Mac8Heap *heap, unsigned int offset)
{
    unsigned int i;
    Mac8Block *b;
    for(i=0; i<heap->count; i++){
        b = &heap->blocks[i];
        if(b->offset==offset){
            heap->count--;
            memmove(b, b+1, (heap->count-i)*sizeof(*b));
            return 1;
        }
    }
    return 0;
}
