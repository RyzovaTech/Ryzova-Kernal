/* SPDX-License-Identifier: GPL-3.0-only */
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
    b->requested = bytes;
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


/* Invalid ownership is distinct from exhaustion. Failure leaves the old
 * block allocated. The C profile treats zero as a minimum allocation. */
int
mac8_resize(Mac8Heap *heap, unsigned char *memory, unsigned int offset,
            unsigned long long bytes, unsigned int *result)
{
    unsigned int i, size, end, copy;
    Mac8Block *b;
    for(i=0; i<heap->count && heap->blocks[i].offset!=offset; i++)
        ;
    if(i==heap->count)
        return 0;
    *result = Mac8HeapBytes;
    if(bytes>Mac8HeapBytes)
        return 1;
    b = &heap->blocks[i];
    size = bytes ? ((unsigned int)bytes+15)&~15U : 16;
    end = i+1<heap->count ? heap->blocks[i+1].offset : Mac8HeapBytes;
    if(size<=end-offset){
        b->bytes = size;
        b->requested = bytes;
        *result = offset;
        return 1;
    }
    copy = b->requested;
    *result = mac8_alloc(heap, bytes);
    if(*result!=Mac8HeapBytes){
        memmove(memory+*result, memory+offset, copy);
        mac8_free(heap, offset);
    }
    return 1;
}
