/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZOVA_PE64_H
#define RYZOVA_PE64_H
#include <stdint.h>
#include <stddef.h>
#define RYZ_PE64_MAX_SECTIONS 16U
typedef struct RyzPe64Section {
    uint32_t rva, virtual_bytes, raw_offset, raw_bytes, flags;
} RyzPe64Section;
typedef struct RyzPe64Plan {
    uint64_t preferred_image_base;
    uint32_t entry_rva, image_size, section_count;
    RyzPe64Section sections[RYZ_PE64_MAX_SECTIONS];
} RyzPe64Plan;
/* Metadata only, no imported DLL support, relocations, TLS or execution. */
enum RyzPe64Status {
    RYZ_PE64_OK = 0, RYZ_PE64_BAD_HEADER = 1, RYZ_PE64_UNSUPPORTED = 2,
    RYZ_PE64_OUT_OF_BOUNDS = 3, RYZ_PE64_UNSAFE_MAPPING = 4
};
int ryz_pe64_plan(const unsigned char *file,size_t size,RyzPe64Plan *plan);
#endif
