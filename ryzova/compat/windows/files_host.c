/* SPDX-License-Identifier: AGPL-3.0-only */
/* Descriptor-rooted Linux test transport. No guest string is a global host path.
   openat2 is mandatory: fail closed on kernels without required resolution flags. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "files_host.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <linux/openat2.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#define HOST_OPENS 64U
typedef struct HostOpen { uint64_t token;int fd;uint32_t access,share;dev_t device;ino_t inode; } HostOpen;
struct CwFileHost { int roots[CW_DIRECTORY_GRANTS];uint32_t root_count,serial;HostOpen handles[HOST_OPENS]; };
static uint32_t win_error(int e) {
    switch(e){case ENOENT:return 2;case ENOTDIR:return 3;case EEXIST:return 80;
    case EMFILE:case ENFILE:return 4;case ENOSPC:case EDQUOT:return 112;
    case ENOMEM:return 8;case EINVAL:return 87;case ENOSYS:case EOPNOTSUPP:return 50;
    case ELOOP:case EXDEV:case EACCES:case EPERM:return 5;default:return 1117;}
}
static int secure_open(int root,const char *name,int flags,unsigned int mode) {
    struct open_how how;
    memset(&how,0,sizeof(how));how.flags=(uint64_t)(unsigned int)(flags|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY);
    how.mode=mode;how.resolve=RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV;
    return (int)syscall(SYS_openat2,root,name,&how,sizeof(how));
}
static int same(const char *a,const char *b) {
    while(*a && *b) {
        unsigned char x=(unsigned char)*a++,y=(unsigned char)*b++;
        if(x>='A' && x<='Z')x=(unsigned char)(x+32);
        if(y>='A' && y<='Z')y=(unsigned char)(y+32);
        if(x!=y)return 0;
    }
    return *a==*b;
}
/* Case-insensitive ASCII lookup with explicit collision/scan limits. */
static uint32_t lookup(int fd,const char *key,char *actual,int *found) {
    DIR *directory;struct dirent *entry;uint32_t count=0,error=0;int fresh=secure_open(fd,".",O_RDONLY|O_DIRECTORY,0);
    if(fresh<0)return win_error(errno);
    directory=fdopendir(fresh);if(!directory){int e=errno;close(fresh);return win_error(e);}
    *found=0;errno=0;
    while((entry=readdir(directory))!=NULL) {
        if(!strcmp(entry->d_name,".") || !strcmp(entry->d_name,".."))continue;
        if(++count>256){error=8;break;}
        if(same(entry->d_name,key)) {
            if(*found){error=123;break;}
            if(strlen(entry->d_name)>CW_PATH_LIMIT){error=123;break;}
            strcpy(actual,entry->d_name);*found=1;
        }
    }
    if(!error && errno)error=win_error(errno);
    closedir(directory);return error;
}
static uint32_t parent(CwFileHost *host,uint32_t mount,const char *path,int *out,char *last,int *found) {
    char copy[CW_PATH_LIMIT+1],actual[CW_PATH_LIMIT+1],*part,*next;int fd,newfd;uint32_t error;
    if(mount>=host->root_count || !path || !*path || strlen(path)>CW_PATH_LIMIT)return 123;
    strcpy(copy,path);fd=fcntl(host->roots[mount],F_DUPFD_CLOEXEC,3);if(fd<0)return win_error(errno);
    part=copy;
    for(;;) {
        next=strchr(part,'/');if(next)*next=0;
        /* Also validate at transport entry, even though core already canonicalizes. */
        if(!*part || !strcmp(part,".") || !strcmp(part,"..") || strchr(part,'\\') || strchr(part,':')){close(fd);return 123;}
        error=lookup(fd,part,actual,found);if(error){close(fd);return error;}
        if(!next){strcpy(last,*found?actual:part);*out=fd;return 0;}
        if(!*found){close(fd);return 3;}
        newfd=secure_open(fd,actual,O_RDONLY|O_DIRECTORY,0);
        if(newfd<0){error=win_error(errno);close(fd);return error;}
        close(fd);fd=newfd;part=next+1;
    }
}
CwFileHost *cw_file_host_new(void) {
    CwFileHost *host=(CwFileHost *)calloc(1,sizeof(*host));uint32_t i;
    if(host)for(i=0;i<CW_DIRECTORY_GRANTS;i++)host->roots[i]=-1;
    return host;
}
int cw_file_host_add_root(CwFileHost *host,int fd) {
    struct stat st;int copy;
    if(!host || host->root_count==CW_DIRECTORY_GRANTS || fstat(fd,&st) || !S_ISDIR(st.st_mode))return -1;
    copy=fcntl(fd,F_DUPFD_CLOEXEC,3);if(copy<0)return -1;
    host->roots[host->root_count]=copy;return (int)host->root_count++;
}
static HostOpen *opened(CwFileHost *host,uint64_t token) {
    uint32_t i;for(i=0;i<HOST_OPENS;i++)if(host->handles[i].token==token && token)return &host->handles[i];return NULL;
}
static uint32_t checked(HostOpen *h,struct stat *st) {
    if(!h)return 6;
    if(fstat(h->fd,st))return win_error(errno);
    if(!S_ISREG(st->st_mode) || st->st_nlink!=1 || st->st_dev!=h->device || st->st_ino!=h->inode)return 5;
    if(st->st_size<0 || (uint64_t)st->st_size>CW_FILE_LIMIT)return 223;
    return 0;
}
static uint32_t open_file(void *context,uint32_t mount,const char *path,uint32_t access,uint32_t share,uint32_t mode,uint32_t rights,uint64_t *token,uint32_t *notice) {
    CwFileHost *host=(CwFileHost *)context;int directory=-1,fd=-1,exists=0,flags;char name[CW_PATH_LIMIT+1];struct stat st;
    uint32_t i,slot,error;
    if(!host || access&~3U || share&~3U || mode<1 || mode>5 || (access&~rights&3U))return 87;
    for(slot=0;slot<HOST_OPENS;slot++)if(!host->handles[slot].token)break;
    if(slot==HOST_OPENS || host->serial==UINT32_MAX)return 4;
    error=parent(host,mount,path,&directory,name,&exists);if(error)return error;
    if((exists && mode==1) || (!exists && (mode==3 || mode==5))){close(directory);return exists?80:2;}
    if(!exists && !(rights&CW_GRANT_CREATE)){close(directory);return 5;}
    if((mode==2 || mode==5) && (!(rights&CW_GRANT_WRITE) || !(access&CW_FILE_WRITE))){close(directory);return 5;}
    flags=(access&CW_FILE_WRITE)?((access&CW_FILE_READ)?O_RDWR:O_WRONLY):O_RDONLY;
    if(!exists)flags|=O_CREAT|O_EXCL;
    fd=secure_open(directory,name,flags,!exists?0600:0);error=fd<0?win_error(errno):0;close(directory);if(error)return error;
    if(fstat(fd,&st)){error=win_error(errno);close(fd);return error;}
    if(!S_ISREG(st.st_mode) || st.st_nlink!=1){close(fd);return 5;}
    if(st.st_size<0 || (uint64_t)st.st_size>CW_FILE_LIMIT){close(fd);return 223;}
    for(i=0;i<HOST_OPENS;i++) {
        HostOpen *old=&host->handles[i];
        if(old->token && old->device==st.st_dev && old->inode==st.st_ino && ((access&~old->share) || (old->access&~share))){close(fd);return 32;}
    }
    /* Destructive truncation happens only after type/link/size/sharing validation. */
    if((mode==2 || mode==5) && ftruncate(fd,0)){error=win_error(errno);close(fd);return error;}
    host->handles[slot].fd=fd;host->handles[slot].access=access;host->handles[slot].share=share;host->handles[slot].device=st.st_dev;host->handles[slot].inode=st.st_ino;
    *token=host->handles[slot].token=((uint64_t)++host->serial<<8)|slot;
    *notice=exists && (mode==2 || mode==4)?183:0;return 0;
}
static uint32_t read_file(void *context,uint64_t token,uint64_t at,unsigned char *out,uint32_t n,uint32_t *actual) {
    HostOpen *h=opened((CwFileHost *)context,token);struct stat st;ssize_t got;uint32_t error=checked(h,&st);
    if(error)return error;
    if(!(h->access&CW_FILE_READ))return 5;
    if(at>CW_FILE_LIMIT || n>CW_FILE_LIMIT)return 87;
    do{got=pread(h->fd,out,n,(off_t)at);}while(got<0 && errno==EINTR);
    if(got<0)return win_error(errno);
    *actual=(uint32_t)got;return 0;
}
static uint32_t write_file(void *context,uint64_t token,uint64_t at,const unsigned char *in,uint32_t n,uint32_t *actual) {
    HostOpen *h=opened((CwFileHost *)context,token);struct stat st;ssize_t got;uint32_t error=checked(h,&st);
    if(error)return error;
    if(!(h->access&CW_FILE_WRITE))return 5;
    if(at>CW_FILE_LIMIT || n>CW_FILE_LIMIT-at)return 223;
    do{got=pwrite(h->fd,in,n,(off_t)at);}while(got<0 && errno==EINTR);
    if(got<0)return win_error(errno);
    *actual=(uint32_t)got;return 0;
}
static uint32_t file_size(void *context,uint64_t token,uint64_t *out) {
    HostOpen *h=opened((CwFileHost *)context,token);struct stat st;uint32_t error=checked(h,&st);
    if(error)return error;
    *out=(uint64_t)st.st_size;return 0;
}
static uint32_t flush_file(void *context,uint64_t token) {
    HostOpen *h=opened((CwFileHost *)context,token);struct stat st;uint32_t error=checked(h,&st);
    if(error)return error;
    if(!(h->access&CW_FILE_WRITE))return 5;
    return fsync(h->fd)?win_error(errno):0;
}
static uint32_t close_file(void *context,uint64_t token) {
    HostOpen *h=opened((CwFileHost *)context,token);int fd;
    if(!h)return 6;
    fd=h->fd;memset(h,0,sizeof(*h));return close(fd)?win_error(errno):0;
}
void cw_file_host_destroy(CwFileHost *host) {
    uint32_t i;if(!host)return;
    for(i=0;i<HOST_OPENS;i++)if(host->handles[i].token)close(host->handles[i].fd);
    for(i=0;i<host->root_count;i++)close(host->roots[i]);
    free(host);
}
uint32_t cw_file_host_open_count(const CwFileHost *host) { uint32_t i,n=0;for(i=0;i<HOST_OPENS;i++)if(host->handles[i].token)n++;return n; }
const CwFileOps *cw_file_host_ops(void) { static const CwFileOps ops={open_file,read_file,write_file,file_size,flush_file,close_file};return &ops; }
