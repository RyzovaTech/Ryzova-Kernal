/* SPDX-License-Identifier: AGPL-3.0-only */
/* Phase 5.2: emulated AMD64 Linux syscall ABI; no native trap integration. */
#ifndef RYZOVA_LINUX_SYSCALL_H
#define RYZOVA_LINUX_SYSCALL_H
#include "portable.h"
#include "namespace.h"

#define RYZ_LINUX_FD_MAX 16U
#define RYZ_LINUX_IO_MAX 65536U
typedef struct RyzLinuxRegs {
    uint64_t rax, rdi, rsi, rdx, r10, r8, r9;
} RyzLinuxRegs;

typedef int64_t (*RyzLinuxWrite)(void *opaque, int fd,
                                 const unsigned char *bytes, size_t size);
#define RYZ_LINUX_FILE_MAX 65536U
typedef struct RyzLinuxFiles {
    const unsigned char *input;
    size_t input_size;
    unsigned char *output;
    size_t output_capacity, output_size;
} RyzLinuxFiles;
typedef int (*RyzLinuxMemoryWrite)(void *context, uint64_t address, uint64_t size);
typedef int64_t (*RyzLinuxMemoryCall)(void *context, const RyzLinuxRegs *regs);
typedef struct RyzLinuxFD {
    enum RyzLinuxNode node;
    int mode, open, cloexec, append, nonblock;
    unsigned int description;
    unsigned int pipe, vnode;
    size_t offset;
} RyzLinuxFD;
#define RYZ_WORLD_DESCRIPTIONS 64U
#define RYZ_WORLD_PIPES 4U
#define RYZ_LINUX_BLOCKED ((int64_t)-4096)
typedef struct RyzLinuxPipe {
    int used;size_t head,size;
    unsigned char bytes[RYZ_LINUX_FILE_MAX];
} RyzLinuxPipe;
typedef struct RyzLinuxDescription {
    RyzLinuxFD fd;unsigned int refs;int used;
} RyzLinuxDescription;
typedef struct RyzLinuxExec {
    const char *path;
    const unsigned char *image;
    size_t size;
} RyzLinuxExec;
#define RYZ_VFS_NODES 32U
typedef struct RyzVnode {
    int used, linked, directory;
    unsigned int parent, permissions;
    uint64_t inode;
    uint64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
    size_t size;
    char name[RYZ_NS_PATH_MAX];
    unsigned char bytes[RYZ_LINUX_FILE_MAX];
} RyzVnode;
typedef struct RyzLinuxWorld {
    RyzVnode nodes[RYZ_VFS_NODES];
    uint64_t next_inode, clock;
    RyzLinuxDescription descriptions[RYZ_WORLD_DESCRIPTIONS];
    RyzLinuxPipe pipes[RYZ_WORLD_PIPES];
    uint64_t output_bytes,pipe_bytes;
    const RyzLinuxExec *execs;
    size_t exec_count;
} RyzLinuxWorld;
typedef int (*RyzLinuxJobCall)(void *,void *,const RyzLinuxRegs *,int64_t *);
typedef struct RyzLinuxProcess {
    RyzLinuxNamespace ns;
    uint64_t guest_base;
    unsigned char *guest_bytes;
    size_t guest_size;
    RyzLinuxFD fds[RYZ_LINUX_FD_MAX];
    unsigned int next_description;
    RyzLinuxWrite write_output;
    void *write_context;
    uint64_t output_bytes;
    int cwd;
    unsigned int vfs_cwd, file_umask;
    uint32_t parent_pid,group_pid;
    RyzLinuxWorld *world;
    RyzLinuxJobCall job_call;
    void *job_context;
    uint64_t signal_mask;
    unsigned char signal_actions[64][32];
    RyzLinuxFiles *files;
    RyzLinuxMemoryWrite memory_write, memory_read;
    RyzLinuxMemoryCall memory_call;
    void *memory_context;
    int exited;
    uint8_t exit_status;
} RyzLinuxProcess;

/* Isolated guest memory window, virtual file-descriptor table and namespace. */
int ryz_linux_process_init(RyzLinuxProcess *p, uint32_t namespace_id,
    uint32_t pid, uint32_t uid, uint32_t gid, uint64_t guest_base,
    unsigned char *guest_bytes, size_t guest_size,
    RyzLinuxWrite write_output, void *write_context);

void ryz_world_attach(RyzLinuxProcess *,RyzLinuxWorld *);
void ryz_world_fork(RyzLinuxProcess *,RyzLinuxProcess *);
void ryz_world_close(RyzLinuxProcess *,int);

/* Linux negative errno (never host errno); exit records status. */
int64_t ryz_linux_syscall(RyzLinuxProcess *p, const RyzLinuxRegs *regs);
#endif
