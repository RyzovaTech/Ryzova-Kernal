/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZ_LINUX_JOBS_H
#define RYZ_LINUX_JOBS_H
#include "process.h"
#define RYZ_JOB_TASKS 8U
#define RYZ_JOB_FORKS 32U
#define RYZ_JOB_EXECS 64U
#define RYZ_JOB_QUANTUM 1024U
typedef struct RyzJobConfig {
    const RyzLinuxExec *execs;
    size_t exec_count;
} RyzJobConfig;
int ryz_vm_run_jobs_elf(const unsigned char *,size_t,unsigned char *,size_t,
    RyzLinuxFiles *,const RyzProcessArgs *,const RyzJobConfig *,RyzLinuxWrite,void *,RyzVmResult *);
#endif
