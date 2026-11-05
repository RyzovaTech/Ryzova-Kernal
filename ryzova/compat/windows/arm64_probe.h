/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZOVA_COMPACT_WINDOWS_ARM64_PROBE_H
#define RYZOVA_COMPACT_WINDOWS_ARM64_PROBE_H
#include <stddef.h>
#include <stdint.h>

/* W7: finite import-free classic Windows ARM64 PE32+ proof only.
 * No Arm64EC/Arm64X, kernel syscalls, real ARM64 hardware or generic Win32.
 * This interpreter consumes only caller-owned, untrusted PE bytes. */
enum {
    CW_A64_OK=0,
    CW_A64_BAD_PE=1,
    CW_A64_UNSUPPORTED=2,
    CW_A64_BAD_MEMORY=3,
    CW_A64_STEP_LIMIT=4
};
typedef struct {
    unsigned int status;
    uint32_t exit_code;
    uint32_t executed_steps;
    uint32_t last_rva;
    uint32_t last_opcode;
} CwArm64Result;
int cw_arm64_pe_execute(const unsigned char *file, size_t length,
                        CwArm64Result *result);
#endif
