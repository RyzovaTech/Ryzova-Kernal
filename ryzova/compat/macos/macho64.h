/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZOVA_MACHO64_H
#define RYZOVA_MACHO64_H
#include <stddef.h>
#include <stdint.h>
#define RYZ_MACHO_MAX_CMDS 32U
#define RYZ_MACHO_MAX_SEGMENTS 16U
typedef struct RyzMachoSegment {
    uint64_t virtual_address, virtual_bytes, file_offset, file_bytes;
    uint32_t protection;
} RyzMachoSegment;
typedef struct RyzMachoPlan {
    uint64_t entry;
    uint32_t segment_count;
    RyzMachoSegment segments[RYZ_MACHO_MAX_SEGMENTS];
} RyzMachoPlan;
/* Metadata only: NO dylib loading, executable mapping or app execution. */
int ryz_macho64_plan(const unsigned char *image, size_t length, RyzMachoPlan *out);
#endif
