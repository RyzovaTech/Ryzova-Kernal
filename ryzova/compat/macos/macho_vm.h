/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZOVA_COMPACT_MACOS_VM_H
#define RYZOVA_COMPACT_MACOS_VM_H
#include <stddef.h>
#include <stdint.h>

/* MAC-1 research runtime: host-side, bounded original AMD64 interpreter.
 * Not native Ryzova guest, Darwin/Mach IPC, dyld, or macOS app compatibility. */
#define RYZ_MAC1_INPUT_MAX (4U * 1024U * 1024U)
#define RYZ_MAC1_MAPPED_MAX (8U * 1024U * 1024U)
#define RYZ_MAC1_STEPS_MAX 4096U

enum RyzMac1Status {
    RYZ_MAC1_OK = 0,
    RYZ_MAC1_BAD_IMAGE = 1,
    RYZ_MAC1_RESOURCE_DENIED = 2,
    RYZ_MAC1_EXEC_DENIED = 3,
    RYZ_MAC1_OPCODE_DENIED = 4,
    RYZ_MAC1_SYSCALL_DENIED = 5,
    RYZ_MAC1_STEP_LIMIT = 6,
    RYZ_MAC1_READ_DENIED = 7,
    RYZ_MAC1_WRITE_DENIED = 8
};
typedef struct RyzMac1Result {
    uint64_t last_rip;
    uint32_t eax;
    uint32_t steps;
    uint8_t returned_from_test_entry;
} RyzMac1Result;

/* Executing LC_MAIN is restricted to a tiny test entry protocol ending
 * in RET. There is no real Darwin stack, argc/argv/env, or host syscall
 * passthrough; all unknown instructions and permission faults fail closed. */
int ryz_mac1_run(const unsigned char *image, size_t size,
                 uint32_t step_limit, RyzMac1Result *out);
#endif
