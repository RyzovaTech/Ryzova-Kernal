/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef MAC_M8_START_H
#define MAC_M8_START_H
#include "m8_image.h"
#include "m8_heap.h"

enum { Mac8OutputLimit = 256 };

typedef struct Mac8Stop Mac8Stop;
struct Mac8Stop {
    unsigned long long pc, last_pc, arg0, arg1;
    unsigned int steps, name, locale_calls, alloc_calls;
    unsigned int exit_code, stdout_bytes;
    unsigned char stdout_data[Mac8OutputLimit];
};

enum {
    Mac8StackBytes = 65536, Mac8ServiceBytes = 4096, Mac8WritableBytes = 4096,
    Mac8ArenaBytes = Mac8Limit+Mac8StackBytes+Mac8ServiceBytes+Mac8HeapBytes+Mac8WritableBytes
};

/* Start the pinned --version profile. A nonzero guest stack guard enables
 * C-locale service and its read-only guest data page. An unresolved import
 * returns 1, guest exit returns 2, and a guest fault or budget stop returns 0.
 * The caller supplies separate immutable image, arena and receipt storage. */
int mac8_start(const unsigned char *, unsigned int, unsigned char *,
               unsigned int, unsigned long long, Mac8Stop *);

#endif
