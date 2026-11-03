/* SPDX-License-Identifier: AGPL-3.0-only */
/* Native directory capabilities: local/9P namespace paths explicitly selected
 * by the trusted launcher. Native Plan 9 has no host symbolic-link traversal.
 * Same-directory rename is atomic and never removes an existing destination;
 * replacement/cross-directory rename and durability barriers fail explicitly. */
typedef struct ResourceHost {char root[1024];int control;} ResourceHost;
static int host_error(void)
{
    char error[ERRMAX];rerrstr(error,sizeof error);
    if(strstr(error,"exist") && !strstr(error,"not exist"))return -17;
    if(strstr(error,"not exist") || strstr(error,"not found"))return -2;
    if(strstr(error,"permission") || strstr(error,"denied"))return -13;
    if(strstr(error,"not empty"))return -39;
    if(strstr(error,"not a directory"))return -20;
    return -5;
}
static int resource_host_allowed(void *context,unsigned int rights)
{
    ResourceHost *h=context;char byte;(void)rights;
    return h->control<0 || (pread(h->control,&byte,1,0)==1 && byte=='1');
}
static int host_path(ResourceHost *h,const char *relative,char *out)
{
    size_t n=strlen(h->root),k=strlen(relative);
    if(n+k+2>1024)return 0;
    memcpy(out,h->root,n);if(k){out[n++]='/';memcpy(out+n,relative,k+1);}else out[n]=0;return 1;
}
static int host_stat(Dir *d,RyzFsStat *s)
{
    if(!(d->mode&DMDIR) && (d->length<0 || d->length>RYZ_LINUX_FILE_MAX))return -27;
    s->inode=d->qid.path;s->size=(d->mode&DMDIR)?0:(uint64_t)d->length;s->mtime=d->mtime;s->mode=(d->mode&DMDIR?0040000:0100000)|(d->mode&0777);return 0;
}
static int64_t resource_host_call(void *context,RyzFsCall *c)
{
    ResourceHost *h=context;char path[1024],other[1024],*a,*b;Dir *d,*entries,change;int fd,mode,error,n,i;uint64_t index;long result;
    if(c->operation==RYZ_FS_CLOSE)return close((int)c->handle)<0?-5:0;
    if(c->operation==RYZ_FS_SYNC)return -95;
    if(!host_path(h,c->path,path))return -36;
    d=c->handle>=0?dirfstat((int)c->handle):dirstat(path);
    if(!d && c->operation!=RYZ_FS_MKDIR && !(c->operation==RYZ_FS_OPEN && (c->flags&0100)))return host_error();
    if(d){error=host_stat(d,&c->stat);if(error){free(d);return error;}}
    switch(c->operation){
    case RYZ_FS_OPEN:
        if(d && (c->flags&0300)==0300){free(d);return -17;}
        if((c->flags&0200000) && (!d || !(d->mode&DMDIR))){free(d);return -20;}
        if(d && (d->mode&DMDIR) && ((c->flags&3) || (c->flags&01000))){free(d);return -21;}
        mode=(int)(c->flags&3);if(c->flags&01000)mode|=OTRUNC;
        fd=d?open(path,mode):create(path,mode|OEXCL,c->mode);free(d);
        if(fd<0)return host_error();d=dirfstat(fd);if(!d){close(fd);return -5;}
        error=host_stat(d,&c->stat);free(d);if(error){close(fd);return error;}return fd;
    case RYZ_FS_STAT:free(d);return 0;
    case RYZ_FS_READ_OP:case RYZ_FS_WRITE_OP:
        if(d->mode&DMDIR){free(d);return -21;}free(d);
        result=c->operation==RYZ_FS_READ_OP?pread((int)c->handle,c->bytes,(long)c->size,(vlong)c->offset):pwrite((int)c->handle,c->bytes,(long)c->size,(vlong)c->offset);
        return result<0?host_error():result;
    case RYZ_FS_LIST:
        if(!(d->mode&DMDIR)){free(d);return -20;}free(d);
        if(seek((int)c->handle,0,0)<0)return -5;
        index=0;
        while((n=dirread((int)c->handle,&entries))>0){
            for(i=0;i<n;i++){
                if(index>=RYZ_VFS_NODES){free(entries);return -75;}
                if(index++!=c->offset)continue;
                if(strlen(entries[i].name)>=sizeof c->name){free(entries);return -36;}
                memcpy(c->name,entries[i].name,strlen(entries[i].name)+1);error=host_stat(&entries[i],&c->stat);free(entries);return error?error:1;
            }
            free(entries);
        }
        return n<0?host_error():0;
    case RYZ_FS_MKDIR:
        if(d){free(d);return -17;}fd=create(path,OREAD|OEXCL,DMDIR|c->mode);if(fd<0)return host_error();close(fd);return 0;
    case RYZ_FS_UNLINK:case RYZ_FS_RMDIR:
        if((c->operation==RYZ_FS_RMDIR)!=((d->mode&DMDIR)!=0)){error=(d->mode&DMDIR)?-21:-20;free(d);return error;}
        free(d);return remove(path)<0?host_error():0;
    case RYZ_FS_RENAME:
        free(d);if(!host_path(h,c->other,other))return -36;
        a=strrchr(path,'/');b=strrchr(other,'/');if(!a || !b || a-path!=b-other || strncmp(path,other,(size_t)(a-path)))return -18;
        d=dirstat(other);if(d){free(d);return -17;}
        nulldir(&change);change.name=b+1;return dirwstat(path,&change)<0?host_error():0;
    case RYZ_FS_CHMOD:case RYZ_FS_TRUNCATE:
        if(c->operation==RYZ_FS_TRUNCATE && (d->mode&DMDIR)){free(d);return -21;}
        nulldir(&change);if(c->operation==RYZ_FS_TRUNCATE)change.length=c->offset;else change.mode=(d->mode&DMDIR)|c->mode;free(d);
        result=c->handle>=0?dirfwstat((int)c->handle,&change):dirwstat(path,&change);return result<0?host_error():0;
    }
    free(d);return -95;
}
static int resource_host_open(ResourceHost *h,const char *path,const char *control)
{
    Dir *d;size_t n=strlen(path);h->control=-1;
    if(!n || n>=sizeof h->root || path[0]!='/')return 0;
    d=dirstat(path);if(!d)return 0;if(!(d->mode&DMDIR)){free(d);return 0;}free(d);
    while(n>1 && path[n-1]=='/')n--;memcpy(h->root,path,n);h->root[n]=0;
    if(control){h->control=open(control,OREAD);if(h->control<0)return 0;}return 1;
}
static void resource_host_close(ResourceHost *h)
{if(h->control>=0)close(h->control);}
