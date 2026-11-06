/* SPDX-License-Identifier: AGPL-3.0-only */
#ifdef MAC_PLAN9
#include <u.h>
#include <libc.h>
#else
#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/openat2.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif
#include "grant.h"

enum { MaxFile = 65536, MaxName = 63 };

#ifdef MAC_PLAN9
/* The bind pins the selected directory in this launcher's private namespace. */
static Dir *root_identity;
#else
static int rootfd = -1;
#endif

int
mac_grant_init(char *path)
{
#ifdef MAC_PLAN9
    if(rfork(RFNAMEG)<0 || bind(path, "/mnt", MREPL)<0)
        return 0;
    root_identity = dirstat("/mnt");
    return root_identity!=nil && (root_identity->mode&DMDIR)!=0;
#else
    rootfd = open(path, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    return rootfd>=0;
#endif
}

static int
valid_name(const char *name)
{
    unsigned int i;
    unsigned char c;

    /* Single ASCII basename. The first byte cannot start a dot component. */
    for(i=0; i<=MaxName && name[i]; i++){
        c = name[i];
        if((c>='a' && c<='z') || (c>='A' && c<='Z') || (c>='0' && c<='9'))
            continue;
        if(i==0 || (c!='.' && c!='_' && c!='-'))
            return 0;
    }
    return i>0 && i<=MaxName;
}

#ifdef MAC_PLAN9
static int
ordinary(Dir *file)
{
    return file!=nil && file->qid.type==0 && (file->mode&~0777UL)==0 &&
           file->type==root_identity->type && file->dev==root_identity->dev &&
           file->length>=0 && file->length<=MaxFile;
}
#endif

int
mac_grant_open(const char *name)
{
    int fd;
#ifdef MAC_PLAN9
    Dir *before, *after;
    char path[sizeof "/mnt/" + MaxName];

    if(root_identity==nil || !valid_name(name))
        return -1;
    snprint(path, sizeof path, "/mnt/%s", name);
    before = dirstat(path);
    if(!ordinary(before)){
        free(before);
        return -1;
    }
    fd = open(path, ORDWR);
    if(fd>=0){
        after = dirfstat(fd);
        if(!ordinary(after) || after->qid.path!=before->qid.path){
            close(fd);
            fd = -1;
        }
        free(after);
    }
    free(before);
#else
    struct open_how how = {
        .flags = O_RDWR|O_NONBLOCK|O_CLOEXEC,
        .resolve = RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_XDEV
    };
    struct stat file;

    if(rootfd<0 || !valid_name(name))
        return -1;
    fd = syscall(SYS_openat2, rootfd, name, &how, sizeof how);
    if(fd>=0 && (fstat(fd, &file)<0 || !S_ISREG(file.st_mode) ||
                 file.st_nlink!=1 || file.st_size<0 || file.st_size>MaxFile)){
        close(fd);
        fd = -1;
    }
#endif
    return fd;
}

long
mac_grant_read(int fd, void *data, unsigned int size, unsigned long offset)
{
    if(offset>MaxFile || size>MaxFile-offset)
        return -1;
    return pread(fd, data, size, offset);
}

long
mac_grant_write(int fd, const void *data, unsigned int size, unsigned long offset)
{
    if(offset>MaxFile || size>MaxFile-offset)
        return -1;
    return pwrite(fd, data, size, offset);
}

void
mac_grant_close(int fd)
{
    close(fd);
}
