/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZOVA_COMPACT_MACOS_MACHO_LINK_META_H
#define RYZOVA_COMPACT_MACOS_MACHO_LINK_META_H
#include <stddef.h>
#include <stdint.h>

/* MAC-3A: metadata-only dependency inventory. NEVER maps or links a dylib. */
#define RYZ_MAC3_MAX_INPUT (4U*1024U*1024U)
#define RYZ_MAC3_MAX_DEPENDENCIES 8U
#define RYZ_MAC3_MAX_RPATHS 4U
#define RYZ_MAC3_NAME_MAX 192U

typedef struct RyzMac3Manifest {
    uint32_t filetype;
    uint32_t segment_count;
    uint32_t dependency_count;
    uint32_t rpath_count;
    uint32_t dyld_seen;
    char dyld[RYZ_MAC3_NAME_MAX];
    char install_name[RYZ_MAC3_NAME_MAX];
    char dependencies[RYZ_MAC3_MAX_DEPENDENCIES][RYZ_MAC3_NAME_MAX];
    char rpaths[RYZ_MAC3_MAX_RPATHS][RYZ_MAC3_NAME_MAX];
} RyzMac3Manifest;

/* 0=metadata accepted; nonzero=malformed, over-limit or unsupported.
 * A positive result is NOT loadability, linking, code-signing or runtime
 * compatibility evidence. All paths remain inert strings. */
int ryz_mac3_scan(const unsigned char *image,size_t length,RyzMac3Manifest *out);
#endif
