/* SPDX-License-Identifier: AGPL-3.0-only */
/* Host-independent virtual namespace: no underlying host or Plan 9 files. */
#include "namespace.h"
#include <string.h>
#define L_ENOENT 2
#define L_EINVAL 22
#define L_ENAMETOOLONG 36
#define L_EACCES 13

static int allowed(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
}
int ryz_linux_ns_resolve(const RyzLinuxNamespace *ns, const char *path,
                         size_t length, enum RyzLinuxNode *kind)
{
    char normalized[RYZ_NS_PATH_MAX];
    size_t input = 0, used = 0, start, n, i;
    static const char prefix[] = "/compat/linux";
    const size_t plen = sizeof(prefix) - 1;

    if (kind != NULL)
        *kind = RYZ_NS_NONE;
    if (ns == NULL || ns->namespace_id == 0 || kind == NULL ||
        path == NULL || length == 0)
        return -L_EINVAL;
    if (length > RYZ_NS_PATH_MAX)
        return -L_ENAMETOOLONG;
    if (path[0] != '/' || path[length-1] != '\0')
        return -L_EACCES;
    if (length == plen + 1 && memcmp(path, prefix, plen) == 0)
        return -L_ENOENT;
    if (length > plen + 1 && memcmp(path, prefix, plen) == 0 &&
        path[plen] == '/')
        input = plen;
    normalized[used++] = '/';
    while (input < length - 1) {
        while (input < length-1 && path[input] == '/')
            ++input;
        if (input == length-1)
            break;
        start = input;
        while (input < length-1 && path[input] != '/') {
            if (!allowed((unsigned char)path[input]))
                return -L_EACCES;
            ++input;
        }
        n = input - start;
        if (n == 1 && path[start] == '.')
            continue;
        if (n == 2 && path[start] == '.' && path[start+1] == '.')
            return -L_EACCES;
        if (used + n + 1 > sizeof(normalized))
            return -L_ENAMETOOLONG;
        if (used != 1)
            normalized[used++] = '/';
        for (i=0; i<n; ++i)
            normalized[used++] = path[start+i];
    }
    normalized[used] = '\0';
    if (strcmp(normalized, "/dev/null") == 0)
        *kind = RYZ_NS_DEV_NULL;
    else if (strcmp(normalized, "/dev/zero") == 0)
        *kind = RYZ_NS_DEV_ZERO;
    else if (strcmp(normalized, "/proc/self") == 0)
        *kind = RYZ_NS_PROC_SELF;
    else if (strcmp(normalized, "/tmp") == 0)
        *kind = RYZ_NS_TMP;
    else
        return -L_ENOENT;
    return 0;
}
