/* SPDX-License-Identifier: AGPL-3.0-only */
/* Phase 5.3: per-process virtual Linux namespace. No host filesystem mounts. */
#ifndef RYZOVA_LINUX_NAMESPACE_H
#define RYZOVA_LINUX_NAMESPACE_H
#include "portable.h"
#define RYZ_NS_PATH_MAX 256U
enum RyzLinuxNode {
    RYZ_NS_NONE = 0, RYZ_NS_DEV_NULL, RYZ_NS_DEV_ZERO,
    RYZ_NS_PROC_SELF, RYZ_NS_TMP, RYZ_NS_INPUT, RYZ_NS_OUTPUT, RYZ_NS_ROOT,
    RYZ_NS_STDIN, RYZ_NS_STDOUT, RYZ_NS_STDERR, RYZ_NS_PIPE, RYZ_NS_EXEC
};
typedef struct RyzLinuxNamespace {
    uint32_t pid, uid, gid, namespace_id;
} RyzLinuxNamespace;
/* Returns Linux-style -errno for absolute NUL-terminated path. */
int ryz_linux_ns_resolve(const RyzLinuxNamespace *ns, const char *path,
                         size_t length, enum RyzLinuxNode *kind);
#endif
