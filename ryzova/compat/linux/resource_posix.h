/* SPDX-License-Identifier: AGPL-3.0-only */
/* Linux-host reference backend. Every traversal is rooted in an open dirfd;
 * intermediate/final host symlinks and special files fail closed. */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
typedef struct ResourceHost {int root,control;} ResourceHost;
static int resource_host_allowed(void *context,unsigned int rights)
{
    ResourceHost *h=context;char byte;(void)rights;
    return h->control<0 || (pread(h->control,&byte,1,0)==1 && byte=='1');
}
static int host_parent(ResourceHost *h,const char *path,char *leaf)
{
    char copy[RYZ_NS_PATH_MAX],*part,*end;int fd=dup(h->root),next;
    if(fd<0)return -errno;
    memcpy(copy,path,strlen(path)+1);part=copy;
    for(;;){end=strchr(part,'/');if(!end)break;*end=0;next=openat(fd,part,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);close(fd);if(next<0)return -errno;fd=next;part=end+1;}
    memcpy(leaf,*part?part:".",strlen(*part?part:".")+1);return fd;
}
static int host_stat(struct stat *s,RyzFsStat *out)
{
    if(S_ISLNK(s->st_mode))return -40;
    if(!S_ISREG(s->st_mode) && !S_ISDIR(s->st_mode))return -13;
    if(S_ISREG(s->st_mode) && s->st_size>RYZ_LINUX_FILE_MAX)return -27;
    out->inode=(uint64_t)s->st_ino;out->size=S_ISDIR(s->st_mode)?0:(uint64_t)s->st_size;out->mtime=(uint64_t)s->st_mtime;out->mode=(unsigned int)s->st_mode&0170777;return 0;
}
static int64_t resource_host_call(void *context,RyzFsCall *c)
{
    ResourceHost *h=context;struct stat s;int parent=-1,other=-1,fd=-1,error=0,flags;int64_t result=-95;char leaf[RYZ_NS_PATH_MAX],dest[RYZ_NS_PATH_MAX];
    if(c->operation==RYZ_FS_CLOSE)return close((int)c->handle)?-errno:0;
    if(c->handle>=0){if(fstat((int)c->handle,&s))return -errno;error=host_stat(&s,&c->stat);if(error)return error;}
    if(c->operation==RYZ_FS_READ_OP){ssize_t n=pread((int)c->handle,c->bytes,c->size,(off_t)c->offset);return n<0?-errno:(int64_t)n;}
    if(c->operation==RYZ_FS_WRITE_OP){ssize_t n=pwrite((int)c->handle,c->bytes,c->size,(off_t)c->offset);return n<0?-errno:(int64_t)n;}
    if(c->operation==RYZ_FS_SYNC)return fsync((int)c->handle)?-errno:0;
    if(c->operation==RYZ_FS_STAT && c->handle>=0)return 0;
    if(c->operation==RYZ_FS_LIST){
        DIR *d;struct dirent *e;uint64_t index=0;int copy=dup((int)c->handle);
        if(copy<0)return -errno;
        d=fdopendir(copy);if(!d){close(copy);return -errno;}rewinddir(d);errno=0;
        result=0;
        while((e=readdir(d))!=NULL){
            if(!strcmp(e->d_name,".") || !strcmp(e->d_name,".."))continue;
            if(index>=RYZ_VFS_NODES){result=-75;break;}
            if(index++!=c->offset)continue;
            if(strlen(e->d_name)>=sizeof c->name){result=-36;break;}
            if(fstatat((int)c->handle,e->d_name,&s,AT_SYMLINK_NOFOLLOW)){result=-errno;break;}
            error=host_stat(&s,&c->stat);if(error){result=error;break;}
            memcpy(c->name,e->d_name,strlen(e->d_name)+1);result=1;break;
        }
        if(!e && errno)result=-errno;
        closedir(d);return result;
    }
    if(c->handle>=0 && (c->operation==RYZ_FS_TRUNCATE || c->operation==RYZ_FS_CHMOD))return (c->operation==RYZ_FS_TRUNCATE?ftruncate((int)c->handle,(off_t)c->offset):fchmod((int)c->handle,(mode_t)c->mode))?-errno:0;
    parent=host_parent(h,c->path,leaf);if(parent<0)return parent;
    if(c->operation!=RYZ_FS_MKDIR){
        if(fstatat(parent,leaf,&s,AT_SYMLINK_NOFOLLOW)){
            if(!(c->operation==RYZ_FS_OPEN && (c->flags&0100) && errno==ENOENT)){result=-errno;goto done;}
        }else{error=host_stat(&s,&c->stat);if(error){result=error;goto done;}}
    }
    switch(c->operation){
    case RYZ_FS_OPEN:
        flags=(int)c->flags|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK;
        fd=openat(parent,leaf,flags,(mode_t)c->mode);if(fd<0){result=-errno;break;}
        if(fstat(fd,&s)){result=-errno;close(fd);break;}
        error=host_stat(&s,&c->stat);if(error){close(fd);result=error;break;}result=fd;break;
    case RYZ_FS_STAT:result=0;break;
    case RYZ_FS_MKDIR:result=mkdirat(parent,leaf,(mode_t)c->mode)?-errno:0;break;
    case RYZ_FS_UNLINK:case RYZ_FS_RMDIR:result=unlinkat(parent,leaf,c->operation==RYZ_FS_RMDIR?AT_REMOVEDIR:0)?-errno:0;break;
    case RYZ_FS_RENAME:
        other=host_parent(h,c->other,dest);if(other<0){result=other;other=-1;break;}
        if(!fstatat(other,dest,&s,AT_SYMLINK_NOFOLLOW)){error=host_stat(&s,&c->stat);if(error){result=error;break;}}
        else if(errno!=ENOENT){result=-errno;break;}
        result=renameat(parent,leaf,other,dest)?-errno:0;break;
    case RYZ_FS_CHMOD:result=fchmodat(parent,leaf,(mode_t)c->mode,AT_SYMLINK_NOFOLLOW)?-errno:0;break;
    case RYZ_FS_TRUNCATE:
        fd=openat(parent,leaf,O_WRONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
        if(fd<0){result=-errno;break;}
        result=ftruncate(fd,(off_t)c->offset)?-errno:0;close(fd);break;
    }
 done:
    if(other>=0)close(other);
    close(parent);return result;
}
static int resource_host_open(ResourceHost *h,const char *path,const char *control)
{
    h->root=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);h->control=-1;
    if(h->root<0)return 0;
    if(control){h->control=open(control,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(h->control<0){close(h->root);return 0;}}
    return 1;
}
static void resource_host_close(ResourceHost *h)
{if(h->control>=0)close(h->control);close(h->root);}
