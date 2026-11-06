/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZOVA_COMPACT_MACOS_DARWIN_H
#define RYZOVA_COMPACT_MACOS_DARWIN_H
#include "macho_vm.h"
#include <stdint.h>
/* MAC-2A opt-in isolated Darwin syscall simulation.
 * Never a native Ryzova guest, a Darwin kernel, or host syscall forwarding.
 * No files/network/process privileges. Captured output limit: 256 bytes. */
#define RYZ_MAC2_OUTPUT_MAX 256U
typedef struct RyzMac2Result {
    RyzMac1Result cpu;
    unsigned char captured_stdout[RYZ_MAC2_OUTPUT_MAX];
    uint32_t captured_stdout_bytes;
    uint8_t simulated_exited;
    uint8_t simulated_exit_code;
} RyzMac2Result;
int ryz_mac2_run(const unsigned char *image, size_t size,
                 uint32_t steps, RyzMac2Result *out);
#endif
