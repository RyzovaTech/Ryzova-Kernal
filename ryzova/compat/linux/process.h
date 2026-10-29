/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZ_COMPACT_PROCESS_H
#define RYZ_COMPACT_PROCESS_H
#include "subset_vm.h"
#include "elf64.h"
#define RYZ_PROCESS_MAX_SPAN (16U * 1024U * 1024U)
#define RYZ_PROCESS_IMAGE_MAX (4U * 1024U * 1024U)
#define RYZ_PROCESS_STACK 65536U
#define RYZ_PROCESS_STEPS 262144U
#define RYZ_PROCESS_ARGS 16U
#define RYZ_PAGE 4096U
#define RYZ_MAP 8U
#define RYZ_READ 4U
#define RYZ_WRITE 2U
#define RYZ_EXEC 1U
typedef struct RyzLinuxMemory {
    unsigned char *bytes;
    uint64_t base, size, heap, brk, stack;
    int dynamic;
    RyzLinuxProcess *process;
    unsigned char pages[RYZ_PROCESS_MAX_SPAN / RYZ_PAGE];
} RyzLinuxMemory;
typedef struct RyzProcessArgs {
    const char *const *argv, *const *envp;
    size_t argc, envc;
} RyzProcessArgs;
typedef struct RyzCpu {
    uint64_t r[16],ip,cur,flags,fsbase,gsbase,segment,tid_address;
    unsigned char xmm[16][16];
    uint32_t extra_steps;
    int repeat,operand16;
    unsigned int rex,rex_present,size;
    int fault;
    RyzLinuxMemory *m;
    RyzLinuxProcess *p;
    RyzVmResult *result;
} RyzCpu;
#define RYZ_CPU_BLOCKED 7
#define RYZ_JOB_DEADLOCK 8
#define RYZ_CPU_EXECUTED 9
#define RYZ_CPU_MOVED 10
void ryz_cpu_init(RyzCpu *,RyzLinuxProcess *,RyzLinuxMemory *,uint64_t,uint64_t,RyzVmResult *);
int ryz_cpu_tick(RyzCpu *);
int ryz_prepare_job(const unsigned char *,size_t,unsigned char *,size_t,const RyzProcessArgs *,RyzLinuxWorld *,RyzLinuxMemory *,uint64_t *,uint64_t *);
int ryz_prepare_process(const unsigned char *,size_t,unsigned char *,size_t,
    const RyzProcessArgs *,RyzLinuxMemory *,uint64_t *,uint64_t *);
int ryz_memory_access(RyzLinuxMemory *, uint64_t, uint64_t, unsigned int);
int64_t ryz_memory_call(void *, const RyzLinuxRegs *);
int ryz_memory_read(void *, uint64_t, uint64_t);
int ryz_memory_write(void *, uint64_t, uint64_t);
int ryz_cpu_run(RyzLinuxProcess *, RyzLinuxMemory *, uint64_t entry,
                uint64_t stack, RyzVmResult *);
int ryz_vm_run_process_elf(const unsigned char *, size_t,
    unsigned char *, size_t, RyzLinuxFiles *, const RyzProcessArgs *,
    RyzLinuxWrite, void *, RyzVmResult *);
#endif
