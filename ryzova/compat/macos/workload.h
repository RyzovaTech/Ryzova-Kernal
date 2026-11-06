/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef MAC_WORKLOAD_H
#define MAC_WORKLOAD_H

enum { WorkStack = 0x400000, WorkPage = 4096, WorkArgv = 256, WorkEnvp = 280 };
typedef struct MacFiles MacFiles;
struct MacFiles {
    const char *name, *note;
    int fd;
    unsigned long offset;
    unsigned int opens, reads, writes, closes, denied, stdout_calls, size;
    unsigned char output[256];
};

int mac_work_args(MacFiles *, unsigned char *);
long mac_work_call(MacFiles *, unsigned int, unsigned long long,
                   unsigned long long, unsigned long long, unsigned char *);
void mac_work_finish(MacFiles *);

#endif
