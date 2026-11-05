/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef MAC_ARM64_H
#define MAC_ARM64_H
#include "workload.h"
enum { MacArmOutput = 256 };
typedef struct MacArmResult MacArmResult;
struct MacArmResult {
    unsigned char output[MacArmOutput];
    unsigned int size, status, steps, calls, rebases;
};
int mac_arm64_run(const unsigned char *, unsigned int, MacArmResult *, MacFiles *);
#endif
