/* SPDX-License-Identifier: AGPL-3.0-only */
#ifndef RYZ_WINDOWS_FILES_H
#define RYZ_WINDOWS_FILES_H
#include "runtime.h"
#define CW_DIRECTORY_GRANTS 8U
#define CW_FILE_HANDLES 30U /* two additional slots are reserved for stdout/stderr */
#define CW_FILE_LIMIT 65536U
#define CW_PATH_LIMIT 240U
#define CW_GRANT_READ 1U
#define CW_GRANT_WRITE 2U
#define CW_GRANT_CREATE 4U
#define CW_GRANT_METADATA 8U
#define CW_GRANT_LIST 16U
#define CW_FILE_READ 1U
#define CW_FILE_WRITE 2U
typedef struct CwDirectoryGrant { char ref[64];uint32_t drive,rights; } CwDirectoryGrant;
/* All provider methods return a Windows error code (zero is success).
   A provider is a trusted resource capability, not a guest-supplied host path.
   open must enforce sharing for its object identities before truncation. */
typedef struct CwFileOps {
    uint32_t (*open)(void *,uint32_t,const char *,uint32_t,uint32_t,uint32_t,uint32_t,uint64_t *,uint32_t *);
    uint32_t (*read)(void *,uint64_t,uint64_t,unsigned char *,uint32_t,uint32_t *);
    uint32_t (*write)(void *,uint64_t,uint64_t,const unsigned char *,uint32_t,uint32_t *);
    uint32_t (*size)(void *,uint64_t,uint64_t *);
    uint32_t (*flush)(void *,uint64_t);
    uint32_t (*close)(void *,uint64_t);
} CwFileOps;
typedef struct CwFileHandle { uint64_t token,resource,position;uint32_t access,mount; } CwFileHandle;
typedef struct CwFileNamespace {
    CwMachine *bound_machine;
    const CwFileOps *ops;void *context;
    uint32_t mount_count,serial;
    CwDirectoryGrant mounts[CW_DIRECTORY_GRANTS];
    CwFileHandle handles[CW_FILE_HANDLES];
    unsigned char scratch[CW_FILE_LIMIT];
} CwFileNamespace;
/* Namespace state must be zero-initialized; grants are copied and frozen. */
int cw_attach_files(CwMachine *,CwFileNamespace *,const CwDirectoryGrant *,uint32_t,const CwFileOps *,void *);
int cw_file_path(const uint16_t *,char *,uint32_t *);
uint64_t cw_file_call(CwMachine *,unsigned int,const uint64_t *);
void cw_files_close_all(CwMachine *);
#endif
