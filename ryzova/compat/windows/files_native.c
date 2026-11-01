/* SPDX-License-Identifier: AGPL-3.0-only */
#include "files_native.h"
#define NATIVE_OPENS 64U
typedef struct NativeOpen { uint64_t token,path;uint32_t access,share,dev,type;int fd; } NativeOpen;
struct CwFileNative {
    char root[256];int rootfd,syncfd;uint64_t path;uint32_t dev,type,serial,peak;
    NativeOpen handles[NATIVE_OPENS];
};
static uint32_t native_error(void) {
    char text[ERRMAX];rerrstr(text,sizeof text);
    if(strstr(text,"not exist") || strstr(text,"not found"))return 2;
    if(strstr(text,"exist"))return 80;
    if(strstr(text,"permission") || strstr(text,"denied"))return 5;
    return 1117;
}
static int same(const char *a,const char *b) {
    while(*a && *b) {
        unsigned int x=(unsigned char)*a++,y=(unsigned char)*b++;
        if(x>='A' && x<='Z')x+=32;
        if(y>='A' && y<='Z')y+=32;
        if(x!=y)return 0;
    }
    return *a==*b;
}
static int root_valid(CwFileNative *h) {
    Dir *d=dirstat(h->root);int ok;
    if(!d)return 0;
    ok=(d->mode&DMDIR) && d->qid.path==h->path && d->dev==h->dev && d->type==h->type;free(d);return ok;
}
static uint32_t resolve(CwFileNative *h,const char *relative,char *out,int *exists) {
    char copy[CW_PATH_LIMIT+1],*part,*next,name[CW_PATH_LIMIT+1];int fd,n,i,count;Dir *entries,*d;size_t length;
    if(!root_valid(h) || !*relative || strlen(relative)>CW_PATH_LIMIT)return 5;
    strcpy(copy,relative);strcpy(out,h->root);part=copy;
    for(;;) {
        next=strchr(part,'/');if(next)*next=0;
        if(!*part || !strcmp(part,".") || !strcmp(part,"..") || strchr(part,':') || strchr(part,'\\'))return 123;
        fd=open(out,OREAD);if(fd<0)return native_error();count=0;*exists=0;
        while((n=dirread(fd,&entries))>0) {
            for(i=0;i<n;i++) {
                if(++count>256){free(entries);close(fd);return 8;}
                if(same(entries[i].name,part)) {
                    if(*exists || strlen(entries[i].name)>CW_PATH_LIMIT){free(entries);close(fd);return 123;}
                    strcpy(name,entries[i].name);*exists=1;
                }
            }
            free(entries);
        }
        close(fd);if(n<0)return native_error();
        length=strlen(out);if(length+1+strlen(*exists?name:part)>=512)return 123;
        out[length++]='/';strcpy(out+length,*exists?name:part);
        if(!next)return 0;
        if(!*exists)return 3;
        d=dirstat(out);if(!d)return native_error();
        i=(d->mode&DMDIR) && d->dev==h->dev && d->type==h->type;free(d);if(!i)return 5;
        part=next+1;
    }
}
CwFileNative *cw_file_native_new(const char *path,int syncfd) {
    CwFileNative *h;Dir *d;size_t n=strlen(path);
    if(!n || n>=256 || path[0]!='/')return nil;
    d=dirstat(path);if(!d)return nil;
    if(!(d->mode&DMDIR)){free(d);return nil;}
    h=mallocz(sizeof(*h),1);if(!h){free(d);return nil;}
    strcpy(h->root,path);h->path=d->qid.path;h->dev=d->dev;h->type=d->type;free(d);
    h->syncfd=syncfd>=0?dup(syncfd,-1):-1;h->rootfd=open(path,OREAD);
    if(h->rootfd<0){if(h->syncfd>=0)close(h->syncfd);free(h);return nil;}
    return h;
}
static NativeOpen *opened(CwFileNative *h,uint64_t token) {
    uint32_t i;for(i=0;i<NATIVE_OPENS;i++)if(h->handles[i].token==token && token)return &h->handles[i];return nil;
}
static uint32_t checked(NativeOpen *o,Dir **out) {
    Dir *d;if(!o)return 6;
    d=dirfstat(o->fd);if(!d)return native_error();
    if(d->qid.type || d->qid.path!=o->path || d->dev!=o->dev || d->type!=o->type){free(d);return 5;}
    if(d->length<0 || d->length>CW_FILE_LIMIT){free(d);return 223;}
    *out=d;return 0;
}
static uint32_t nopen(void *context,uint32_t mount,const char *relative,uint32_t access,uint32_t share,uint32_t mode,uint32_t rights,uint64_t *token,uint32_t *notice) {
    CwFileNative *h=context;char path[512];uint32_t i,slot,error;int exists=0,fd,omode;Dir *d,change;
    if(mount || (access&~rights&3U))return 5;
    for(slot=0;slot<NATIVE_OPENS;slot++)if(!h->handles[slot].token)break;
    if(slot==NATIVE_OPENS || h->serial==UINT32_MAX)return 4;
    error=resolve(h,relative,path,&exists);if(error)return error;
    if((exists && mode==1) || (!exists && (mode==3 || mode==5)))return exists?80:2;
    if(!exists && !(rights&CW_GRANT_CREATE))return 5;
    omode=(access&CW_FILE_WRITE)?((access&CW_FILE_READ)?ORDWR:OWRITE):OREAD;
    fd=exists?open(path,omode):create(path,omode|OEXCL,0600);
    if(fd<0)return native_error();
    d=dirfstat(fd);if(!d){close(fd);return native_error();}
    if(d->qid.type || d->dev!=h->dev || d->type!=h->type){free(d);close(fd);return 5;}
    if(d->length<0 || d->length>CW_FILE_LIMIT){free(d);close(fd);return 223;}
    for(i=0;i<NATIVE_OPENS;i++) {
        NativeOpen *old=&h->handles[i];
        if(old->token && old->path==d->qid.path && old->dev==d->dev && old->type==d->type && ((access&~old->share) || (old->access&~share))){free(d);close(fd);return 32;}
    }
    if(mode==2 || mode==5) {
        nulldir(&change);change.length=0;
        if(dirfwstat(fd,&change)<0){free(d);close(fd);return native_error();}
    }
    h->handles[slot].fd=fd;h->handles[slot].access=access;h->handles[slot].share=share;
    h->handles[slot].path=d->qid.path;h->handles[slot].dev=d->dev;h->handles[slot].type=d->type;free(d);
    *token=h->handles[slot].token=((uint64_t)++h->serial<<8)|slot;
    *notice=exists && (mode==2 || mode==4)?183:0;
    i=cw_file_native_open_count(h);if(i>h->peak)h->peak=i;return 0;
}
static uint32_t nread(void *context,uint64_t token,uint64_t at,unsigned char *out,uint32_t n,uint32_t *actual) {
    NativeOpen *o=opened(context,token);Dir *d;long count;uint32_t error=checked(o,&d);
    if(error)return error;free(d);
    if(!(o->access&CW_FILE_READ) || at>CW_FILE_LIMIT || n>CW_FILE_LIMIT)return 5;
    count=pread(o->fd,out,n,at);if(count<0)return native_error();*actual=count;return 0;
}
static uint32_t nwrite(void *context,uint64_t token,uint64_t at,const unsigned char *in,uint32_t n,uint32_t *actual) {
    NativeOpen *o=opened(context,token);Dir *d;long count;uint32_t error=checked(o,&d);
    if(error)return error;free(d);
    if(!(o->access&CW_FILE_WRITE))return 5;
    if(at>CW_FILE_LIMIT || n>CW_FILE_LIMIT-at)return 223;
    count=pwrite(o->fd,in,n,at);if(count<0)return native_error();*actual=count;return 0;
}
static uint32_t nsize(void *context,uint64_t token,uint64_t *out) {
    NativeOpen *o=opened(context,token);Dir *d;uint32_t error=checked(o,&d);
    if(error)return error;*out=d->length;free(d);return 0;
}
static uint32_t nflush(void *context,uint64_t token) {
    CwFileNative *h=context;NativeOpen *o=opened(h,token);Dir *d;uint32_t error=checked(o,&d);
    if(error)return error;free(d);
    if(!(o->access&CW_FILE_WRITE))return 5;
    /* Empty wstat is optional in 9P; hjfs command pipes do not acknowledge
       completed sync. No native durability capability has been qualified. */
    USED(h);return 50;
}
static uint32_t nclose(void *context,uint64_t token) {
    NativeOpen *o=opened(context,token);int fd;if(!o)return 6;
    fd=o->fd;memset(o,0,sizeof(*o));return close(fd)<0?1117:0;
}
void cw_file_native_destroy(CwFileNative *h) {
    uint32_t i;if(!h)return;
    for(i=0;i<NATIVE_OPENS;i++)if(h->handles[i].token)close(h->handles[i].fd);
    if(h->rootfd>=0)close(h->rootfd);if(h->syncfd>=0)close(h->syncfd);free(h);
}
uint32_t cw_file_native_open_count(CwFileNative *h) { uint32_t i,n=0;for(i=0;i<NATIVE_OPENS;i++)if(h->handles[i].token)n++;return n; }
const CwFileOps *cw_file_native_ops(void) { static CwFileOps ops={nopen,nread,nwrite,nsize,nflush,nclose};return &ops; }

uint32_t cw_file_native_peak_count(CwFileNative *h) { return h->peak; }
