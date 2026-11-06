/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZOVA_COMPACT_MACOS_STATIC_LINK_H
#define RYZOVA_COMPACT_MACOS_STATIC_LINK_H
#include <stddef.h>
#include <stdint.h>

/* MAC-3C narrow, independently authored *object-to-synthetic-image*
 * static linker. No dylib/dyld/libSystem, host symbol lookup or native
 * Ryzova guest execution. Inputs restricted to two AMD64 MH_OBJECT files,
 * one __TEXT,__text section each, external BRANCH rel32 relocations only. */
#define RYZ_MAC3C_OUTPUT_BYTES 4096U
#define RYZ_MAC3C_OBJECT_MAX (64U*1024U)
typedef struct RyzMac3LinkReport {
    uint32_t object_count;
    uint32_t applied_branch_relocations;
    uint32_t resolved_external_symbols;
    uint32_t output_code_bytes;
    uint32_t entry_file_offset;
    uint8_t executed_native_guest;
    uint8_t loaded_dylibs;
} RyzMac3LinkReport;

int ryz_mac3_link2(const unsigned char *first,size_t first_len,
                   const unsigned char *second,size_t second_len,
                   unsigned char *result,size_t result_cap,
                   RyzMac3LinkReport *report);
#endif
