/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZ_WINDOWS_RUNTIME_H
#define RYZ_WINDOWS_RUNTIME_H
#include "portable.h"
#define CW_MAX_FILE (4U*1024U*1024U)
#define CW_MAX_MEMORY (64U*1024U*1024U)
#define CW_STACK 65536U
#define CW_MAX_SECTIONS 16U
#define CW_MAX_IMPORTS 32U
#define CW_MAX_STEPS 262144U
#define CW_TLS_LIMIT 4096U
#define CW_TLS_CALLBACKS 8U
#define CW_TLS_RESERVE 8192U
#define CW_TLS_RETURN (UINT64_MAX-1)
#define CW_R 1U
#define CW_W 2U
#define CW_X 4U
/* Recursive service/namespace references are opaque in the native linker
   signature, as with Plan 9 libc's Tzone. Their definitions remain checked
   normally by the compiler in each translation unit. */
typedef struct CwServices CwServices;
typedef struct CwFileNamespace CwFileNamespace;
#ifdef CW_PLAN9
#pragma incomplete CwServices
#pragma incomplete CwFileNamespace
#endif
/* All guest addresses are numbers. No host executable mappings or DLL calls. */
typedef struct CwSection { uint32_t rva, size, raw, bytes, permissions; } CwSection;
typedef struct CwImport { uint32_t iat, api; } CwImport;
typedef struct CwPlan {
    uint64_t preferred_base, base;
    uint32_t image_bytes, headers, entry, count, reloc_rva, reloc_bytes;
    CwSection sections[CW_MAX_SECTIONS];
    uint32_t import_count, api_mask, iat_rva, iat_bytes;
    CwImport imports[CW_MAX_IMPORTS];
    uint32_t tls_present, tls_rva, tls_bytes, tls_zero, tls_index, tls_count;
    uint32_t tls_callbacks[CW_TLS_CALLBACKS];
} CwPlan;
enum CwStatus { CW_OK, CW_HEADER, CW_UNSUPPORTED, CW_BOUNDS, CW_MAPPING,
    CW_RELOCATION, CW_MEMORY, CW_OPCODE, CW_BUDGET, CW_ABI, CW_API, CW_DIVIDE, CW_CRT };
typedef struct CwMachine {
    CwPlan plan;
    unsigned char *image, *stack;
    uint64_t stack_base, initial_sp, r[16], ip, flags;
    unsigned char xmm[16][16];
    uint32_t instructions, exit_code;
    int exited, status;
    uint32_t exit_kind; /* 0: bootstrap RET, 1: ExitProcess */
    struct CwServices *services;
    uint64_t last_guest_ip;
    uint32_t tls_next;
} CwMachine;
/* No allocation, mapping or execution on admission failure. */
/* The diagnostic reports UINT32_MAX when no unsupported directory is identified. */
int cw_plan_diagnostic(const unsigned char *, size_t, uint64_t, CwPlan *, uint32_t *);
int cw_plan(const unsigned char *, size_t, uint64_t, CwPlan *);
/* Caller owns arena: exactly plan.image_bytes + CW_STACK required. */
int cw_load(const unsigned char *, size_t, uint64_t, unsigned char *, size_t, CwMachine *);
/* Rights checked for each access, including instruction fetch; no host syscall. */
int cw_read(CwMachine *, uint64_t, unsigned char *, size_t, unsigned int);
int cw_write(CwMachine *, uint64_t, const unsigned char *, size_t);
int cw_run(CwMachine *, uint32_t);
/* Trusted synthetic return handling; guest code cannot map these tokens. */
int cw_bootstrap_return(CwMachine *,uint64_t,uint64_t);
const char *cw_status_name(int);
/* Trusted API code uses this only after validating rights and full spans. */
unsigned char *cw_memory(CwMachine *,uint64_t,size_t,unsigned int);
#endif
