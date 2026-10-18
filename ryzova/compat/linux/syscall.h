/* SPDX-License-Identifier: AGPL-3.0-only */
/* Phase 5.2: emulated AMD64 Linux syscall ABI; no native trap integration. */
#ifndef RYZOVA_LINUX_SYSCALL_H
#define RYZOVA_LINUX_SYSCALL_H
#include <stddef.h>
#include <stdint.h>
#include "namespace.h"

#define RYZ_LINUX_FD_MAX 16U
#define RYZ_LINUX_IO_MAX 65536U
typedef struct RyzLinuxRegs {
    uint64_t rax, rdi, rsi, rdx, r10, r8, r9;
} RyzLinuxRegs;

typedef int64_t (*RyzLinuxWrite)(void *opaque, int fd,
                                 const unsigned char *bytes, size_t size);
typedef struct RyzLinuxFD {
    enum RyzLinuxNode node;
    int mode, open;
} RyzLinuxFD;
typedef struct RyzLinuxProcess {
    RyzLinuxNamespace ns;
    uint64_t guest_base;
    unsigned char *guest_bytes;
    size_t guest_size;
    RyzLinuxFD fds[RYZ_LINUX_FD_MAX];
    RyzLinuxWrite write_output;
    void *write_context;
    int exited;
    uint8_t exit_status;
} RyzLinuxProcess;

/* Isolated guest memory window, virtual file-descriptor table and namespace. */
int ryz_linux_process_init(RyzLinuxProcess *p, uint32_t namespace_id,
    uint32_t pid, uint32_t uid, uint32_t gid, uint64_t guest_base,
    unsigned char *guest_bytes, size_t guest_size,
    RyzLinuxWrite write_output, void *write_context);

/* Linux negative errno (never host errno); exit records status. */
int64_t ryz_linux_syscall(RyzLinuxProcess *p, const RyzLinuxRegs *regs);
#endif
