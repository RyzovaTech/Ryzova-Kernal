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
    unsigned int pipe, vnode, socket;
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
    int used, linked, directory, symlink;
    unsigned int parent, permissions, backing;
    uint64_t inode;
    uint64_t atime, atime_ns, mtime, mtime_ns, ctime, ctime_ns;
    size_t size;
    char name[RYZ_NS_PATH_MAX];
    unsigned char bytes[RYZ_LINUX_FILE_MAX];
} RyzVnode;
/* Hardlink entries refer directly to an owned inode slot, never a chain. */
#define RYZ_VFS_INDEX(w,i) ((w)->nodes[(i)].backing?(w)->nodes[(i)].backing-1:(unsigned int)(i))
#define RYZ_VFS_NODE(w,i) (&(w)->nodes[RYZ_VFS_INDEX(w,i)])
#define RYZ_NET_SOCKETS 32U
#define RYZ_NET_BUFFER 4096U
#define RYZ_NET_BACKLOG 8U
#define RYZ_NETWORK_GRANTS 4U
/* Trusted embedding callbacks: bounded open; nonblocking/bounded ready/read/write;
 * negative Linux errno, read=0 EOF, ready uses 1/4/8/16/8192 only.
 * The core owns successful handles and closes each exactly once. */
typedef struct RyzNetworkOps {
    int64_t (*open)(void *);
    int (*ready)(void *,int64_t);
    int64_t (*read)(void *,int64_t,unsigned char *,size_t);
    int64_t (*write)(void *,int64_t,const unsigned char *,size_t);
    void (*close)(void *,int64_t);
} RyzNetworkOps;
typedef struct RyzNetworkGrant {
    unsigned char address[4];unsigned int port;
    const RyzNetworkOps *ops;void *context;
} RyzNetworkGrant;
typedef struct RyzNetworkResources {
    const RyzNetworkGrant *grants;size_t count;
    uint64_t (*now_ns)(void *);
    void (*wait)(void *);void *context;
    unsigned int wall_milliseconds;
} RyzNetworkResources;
typedef struct RyzLinuxSocket {
    int used,domain,bound,listening,connected,peer,read_closed,write_closed;
    int reuseaddr,keepalive,nodelay;
    unsigned int external;int external_eof,external_hup,external_error,external_no_fill;int64_t external_handle;
    unsigned int backlog,pending_count,pending[RYZ_NET_BACKLOG];
    unsigned int local_length,remote_length;
    unsigned char local[128],remote[128];
    size_t head,size;
    unsigned char bytes[RYZ_NET_BUFFER];
} RyzLinuxSocket;
typedef int64_t (*RyzLinuxRandom)(void *,unsigned char *,size_t);
typedef struct RyzLinuxWorld {
    RyzLinuxRandom random;
    void *random_context;
    RyzVnode nodes[RYZ_VFS_NODES];
    uint64_t next_inode, clock,random_bytes;
    unsigned int memory_barriers[8];
    RyzLinuxDescription descriptions[RYZ_WORLD_DESCRIPTIONS];
    RyzLinuxPipe pipes[RYZ_WORLD_PIPES];
    RyzLinuxSocket sockets[RYZ_NET_SOCKETS];
    uint64_t network_bytes;
    const RyzNetworkResources *network;
    uint64_t network_start,network_last;
    unsigned int network_waits,network_failed,network_busy[RYZ_NETWORK_GRANTS];
    unsigned int next_port;
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
    int cwd,barrier_registered;
    unsigned int vfs_cwd, file_umask;
    uint32_t parent_pid,group_pid,tgid;
    struct RyzLinuxProcess *fd_owner,*action_owner,*fs_owner;
    unsigned int fd_shares,memory_index;
    int fd_detached;
    RyzLinuxWorld *world;
    RyzLinuxJobCall job_call;
    void *job_context;
    uint64_t signal_mask,generated_signals;
    unsigned char signal_actions[64][32];
    RyzLinuxFiles *files;
    RyzLinuxMemoryWrite memory_write, memory_read;
    RyzLinuxMemoryCall memory_call;
    void *memory_context;
    int exited;
    uint8_t exit_status;
} RyzLinuxProcess;

#define RYZ_TICK(w) ((w)->clock==UINT64_MAX?UINT64_MAX:++(w)->clock)
int64_t ryz_world_random(RyzLinuxWorld *,unsigned char *,size_t);
#define RYZ_ACTION(p,i) ((p)->action_owner?(p)->action_owner->signal_actions[(i)]:(p)->signal_actions[(i)])

/* Isolated guest memory window, virtual file-descriptor table and namespace. */
int ryz_linux_process_init(RyzLinuxProcess *p, uint32_t namespace_id,
    uint32_t pid, uint32_t uid, uint32_t gid, uint64_t guest_base,
    unsigned char *guest_bytes, size_t guest_size,
    RyzLinuxWrite write_output, void *write_context);

int ryz_network_budget(RyzLinuxWorld *);
int ryz_network_idle(RyzLinuxWorld *);
/* Resolve guest namespace paths, following at most 40 symbolic links. */
int ryz_linux_path(RyzLinuxProcess *,uint64_t,uint64_t,char *,int,int *);
void ryz_world_attach(RyzLinuxProcess *,RyzLinuxWorld *);
void ryz_world_fork(RyzLinuxProcess *,RyzLinuxProcess *);
void ryz_world_close(RyzLinuxProcess *,int);

/* Linux negative errno (never host errno); exit records status. */
int64_t ryz_linux_syscall(RyzLinuxProcess *p, const RyzLinuxRegs *regs);
#endif
