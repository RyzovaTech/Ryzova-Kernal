/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef MAC_M8_IMAGE_H
#define MAC_M8_IMAGE_H

enum {
    Mac8Limit = 1024*1024, Mac8Segments = 5, Mac8Imports = 256,
    Mac8Read = 1, Mac8Write = 2, Mac8Execute = 4
};

#define MAC8_BASE 0x200000ULL
#define MAC8_UNRESOLVED 0x10000ULL

typedef struct Mac8Segment Mac8Segment;
struct Mac8Segment {
    unsigned int offset, bytes, file_bytes, protection;
};

typedef struct Mac8Image Mac8Image;
struct Mac8Image {
    unsigned int cpu, page, entry, mapped_bytes;
    unsigned int imports, binds, rebases, fixup_pages;
    unsigned int bss, bss_bytes;
    unsigned int names[Mac8Imports]; /* Offsets in the original image. */
    Mac8Segment segments[Mac8Segments];
};

/* All spans and fixups are validated before any output is modified. The
 * caller supplies disjoint image, arena and plan storage. Tokens are guest
 * addresses outside the image, not pointers to host code. */
int mac8_load(const unsigned char *, unsigned int, unsigned char *,
              unsigned int, Mac8Image *);

/* A span must fit entirely in one segment with the requested guest rights. */
int mac8_access(const Mac8Image *, unsigned long long, unsigned int, unsigned int);

#endif
