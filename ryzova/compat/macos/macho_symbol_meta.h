/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZOVA_COMPACT_MACOS_SYMBOL_META_H
#define RYZOVA_COMPACT_MACOS_SYMBOL_META_H
#include <stddef.h>
#include <stdint.h>

/* MAC-3B: inert Mach-O MH_OBJECT symbol inventory only.
 * Never bind/rebase/execute; no host filesystem or dynamic library access. */
#define RYZ_MAC3_SYM_MAX 64U
#define RYZ_MAC3_SYM_NAME_MAX 96U
typedef struct RyzMac3Symbol {
    char name[RYZ_MAC3_SYM_NAME_MAX];
    uint64_t value;
    uint8_t kind;    /* 0: undefined import, 1: defined section */
    uint8_t section;
} RyzMac3Symbol;
typedef struct RyzMac3Symbols {
    uint32_t count;
    uint32_t defined_count;
    uint32_t undefined_count;
    uint32_t relocation_count;
    RyzMac3Symbol symbols[RYZ_MAC3_SYM_MAX];
} RyzMac3Symbols;
int ryz_mac3_symbols(const unsigned char *image, size_t length,
                     RyzMac3Symbols *out);
#endif
