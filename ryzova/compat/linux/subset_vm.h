/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZOVA_COMPAT_SUBSET_VM_H
#define RYZOVA_COMPAT_SUBSET_VM_H
#include <stddef.h>
#include <stdint.h>
#include "syscall.h"
#define RYZ_VM_MAX_SPAN (2U * 1024U * 1024U)
#define RYZ_VM_MAX_STEPS 2048U
enum RyzVmResultCode {
    RYZ_VM_OK = 0, RYZ_VM_BAD_INPUT = 1, RYZ_VM_MAP_ERROR = 2,
    RYZ_VM_OPCODE_UNSUPPORTED = 3, RYZ_VM_STEP_LIMIT = 4,
    RYZ_VM_SYSCALL_UNSUPPORTED = 5
};
typedef struct RyzVmResult {
    uint32_t executed_steps;
    uint32_t syscall_count;
    uint64_t last_rip;
    int exited;
    uint8_t exit_status;
} RyzVmResult;
/*
 * Execute a deliberately tiny x86-64 opcode subset via a software interpreter.
 * Never native-jump into ELF memory. No mmap(PROT_EXEC), execve or host syscall
 * forwarding. The caller owns all guest memory and the only output callback.
 */
int ryz_vm_run_static_elf(const unsigned char *elf, size_t elf_size,
    unsigned char *arena, size_t arena_size,
    RyzLinuxWrite output, void *opaque, RyzVmResult *result);
#endif
