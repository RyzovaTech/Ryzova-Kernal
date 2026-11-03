/* SPDX-License-Identifier: AGPL-3.0-only */
/*
 * Ryzova Phase 5.1: bounded Linux AMD64 ELF64 load-plan construction.
 * Portable userspace test library ONLY; no kernel hooks or execution.
 */
#ifndef RYZOVA_LINUX_ELF64_H
#define RYZOVA_LINUX_ELF64_H

#include "portable.h"

#define RYZ_ELF64_MAX_PHDR 32U
#define RYZ_ELF64_MAX_LOAD 16U
#define RYZ_ELF64_PAGE_SIZE UINT64_C(4096)
#define RYZ_ELF64_MAX_MAPPED (UINT64_C(64) * 1024U * 1024U)

enum RyzElf64Error {
    RYZ_ELF_OK = 0,
    RYZ_ELF_BAD_ARG,
    RYZ_ELF_BAD_HEADER,
    RYZ_ELF_UNSUPPORTED,
    RYZ_ELF_BOUNDS,
    RYZ_ELF_POLICY,
    RYZ_ELF_NO_ENTRY
};

typedef struct RyzElf64Segment {
    uint64_t file_offset;
    uint64_t file_bytes;
    uint64_t address;
    uint64_t memory_bytes;
    uint64_t map_start;
    uint64_t map_end;
    uint32_t flags;
} RyzElf64Segment;

typedef struct RyzElf64Plan {
    uint64_t entry;
    uint64_t mapped_bytes;
    uint32_t load_count;
    RyzElf64Segment loads[RYZ_ELF64_MAX_LOAD];
} RyzElf64Plan;

int ryz_elf64_plan_relocated(const unsigned char *,size_t,uint64_t,int,RyzElf64Plan *);
int ryz_elf64_plan(const unsigned char *image, size_t length, RyzElf64Plan *out);
int ryz_elf64_materialize(const unsigned char *image, size_t image_length,
                          const RyzElf64Segment *segment,
                          unsigned char *destination, size_t capacity);
const char *ryz_elf64_error(int error);

#endif
