/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZ_WINDOWS_RUNTIME_H
#define RYZ_WINDOWS_RUNTIME_H
#include <stddef.h>
#include <stdint.h>
#define CW_MAX_FILE (4U*1024U*1024U)
#define CW_MAX_MEMORY (64U*1024U*1024U)
#define CW_STACK 65536U
#define CW_MAX_SECTIONS 16U
#define CW_MAX_IMPORTS 32U
#define CW_MAX_STEPS 262144U
#define CW_R 1U
#define CW_W 2U
#define CW_X 4U
/* All guest addresses are numbers. No host executable mappings or DLL calls. */
typedef struct CwSection { uint32_t rva, size, raw, bytes, permissions; } CwSection;
typedef struct CwImport { uint32_t iat, api; } CwImport;
typedef struct CwPlan {
    uint64_t preferred_base, base;
    uint32_t image_bytes, headers, entry, count, reloc_rva, reloc_bytes;
    CwSection sections[CW_MAX_SECTIONS];
    uint32_t import_count, api_mask, iat_rva, iat_bytes;
    CwImport imports[CW_MAX_IMPORTS];
} CwPlan;
enum CwStatus { CW_OK, CW_HEADER, CW_UNSUPPORTED, CW_BOUNDS, CW_MAPPING,
    CW_RELOCATION, CW_MEMORY, CW_OPCODE, CW_BUDGET, CW_ABI, CW_API };
typedef struct CwMachine {
    CwPlan plan;
    unsigned char *image, *stack;
    uint64_t stack_base, initial_sp, r[16], ip, flags;
    unsigned char xmm[16][16];
    uint32_t instructions, exit_code;
    int exited, status;
    uint32_t exit_kind; /* 0: bootstrap RET, 1: ExitProcess */
    struct CwServices *services;
} CwMachine;
/* No allocation, mapping or execution on admission failure. */
int cw_plan(const unsigned char *, size_t, uint64_t, CwPlan *);
/* Caller owns arena: exactly plan.image_bytes + CW_STACK required. */
int cw_load(const unsigned char *, size_t, uint64_t, unsigned char *, size_t, CwMachine *);
/* Rights checked for each access, including instruction fetch; no host syscall. */
int cw_read(CwMachine *, uint64_t, unsigned char *, size_t, unsigned int);
int cw_write(CwMachine *, uint64_t, const unsigned char *, size_t);
int cw_run(CwMachine *, uint32_t);
/* Trusted API code uses this only after validating rights and full spans. */
unsigned char *cw_memory(CwMachine *,uint64_t,size_t,unsigned int);
#endif
