/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZ_LINUX_JOBS_H
#define RYZ_LINUX_JOBS_H
#include "process.h"
#define RYZ_JOB_TASKS 8U
#define RYZ_JOB_FORKS 32U
#define RYZ_JOB_EXECS 64U
#define RYZ_JOB_QUANTUM 1024U
#define RYZ_JOB_NETWORK_LIMIT 11
#define RYZ_FS_SNAPSHOT_MAX (48U + RYZ_VFS_NODES*(80U+RYZ_NS_PATH_MAX+RYZ_LINUX_FILE_MAX))
typedef struct RyzFilesystemResources {
    const unsigned char *input;
    size_t input_size;
    unsigned char *output;
    size_t output_capacity,output_size;
} RyzFilesystemResources;
typedef struct RyzJobConfig {
    const RyzLinuxExec *execs;
    size_t exec_count;
    uint32_t max_steps;
    RyzLinuxRandom random;
    void *random_context;
    RyzFilesystemResources *filesystem;
    const RyzNetworkResources *network;
    const RyzFsResources *resources;
    unsigned int root_tree; /* 0: historical /tmp, 1: isolated guest root. */
} RyzJobConfig;
int ryz_vm_run_jobs_elf(const unsigned char *,size_t,unsigned char *,size_t,
    RyzLinuxFiles *,const RyzProcessArgs *,const RyzJobConfig *,RyzLinuxWrite,void *,RyzVmResult *);
#endif
