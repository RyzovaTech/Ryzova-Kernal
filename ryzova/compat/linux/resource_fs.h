/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZ_RESOURCE_FS_H
#define RYZ_RESOURCE_FS_H
/* Trusted, bounded directory capabilities. Paths are relative, canonical and
 * never contain dot components. Backends must refuse host symbolic links.
 * call returns Linux -errno, never an unchecked guest pointer. */
#define RYZ_FS_MOUNTS 4U
#define RYZ_FS_READ 1U
#define RYZ_FS_WRITE 2U
#define RYZ_FS_TRAFFIC (4U*1024U*1024U)
#define RYZ_FS_CALLS 65536U
#define RYZ_FS_RESTRICT UINT64_C(0x46534e53)
enum RyzFsOperation { RYZ_FS_OPEN=1, RYZ_FS_CLOSE, RYZ_FS_STAT, RYZ_FS_READ_OP,
    RYZ_FS_WRITE_OP, RYZ_FS_LIST, RYZ_FS_MKDIR, RYZ_FS_UNLINK, RYZ_FS_RMDIR,
    RYZ_FS_RENAME, RYZ_FS_CHMOD, RYZ_FS_TRUNCATE, RYZ_FS_SYNC };
typedef struct RyzFsStat { uint64_t inode,size,mtime;unsigned int mode; } RyzFsStat;
typedef struct RyzFsCall {
    unsigned int operation,flags,mode;
    const char *path,*other;
    int64_t handle;
    uint64_t offset;
    unsigned char *bytes;
    size_t size;
    RyzFsStat stat;
    char name[RYZ_NS_PATH_MAX];
} RyzFsCall;
typedef struct RyzFsMount {
    const char *path;
    unsigned int rights;
    int (*allowed)(void *,unsigned int);
    int64_t (*call)(void *,RyzFsCall *);
    void *context;
} RyzFsMount;
typedef struct RyzFsView { const char *executable;unsigned int read_mask,write_mask; } RyzFsView;
typedef struct RyzFsResources {
    const RyzFsMount *mounts;size_t count;
    const RyzFsView *views;size_t view_count;
} RyzFsResources;
typedef struct RyzFsOpen {
    int used;unsigned int mount,directory;
    int64_t handle;
    char path[RYZ_NS_PATH_MAX];
} RyzFsOpen;
#endif
