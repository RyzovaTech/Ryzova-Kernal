/* SPDX-License-Identifier: AGPL-3.0-only */
#include "api.h"
#include "files.h"
#include <string.h>
static uint64_t failed(CwServices *s,uint32_t error,int create) { s->last_error=error;return create?UINT64_MAX:0; }
static int overlap(const void *a,size_t an,const void *b,size_t bn) {
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    return an && bn && (x<=y?y-x<an:x-y<bn);
}
static int reference(const char *s) {
    unsigned int i;
    for(i=0;i<64;i++) {
        unsigned char c=(unsigned char)s[i];
        if(!c)return i>0;
        if(!((c>='A' && c<='Z') || (c>='a' && c<='z') || (i && c>='0' && c<='9') || (i && (c=='_' || c=='-' || c=='.'))))return 0;
        if(c=='.' && i && s[i-1]=='.')return 0;
    }
    return 0;
}
int cw_attach_files(CwMachine *m,CwFileNamespace *ns,const CwDirectoryGrant *grants,uint32_t count,const CwFileOps *ops,void *context) {
    CwDirectoryGrant copy[CW_DIRECTORY_GRANTS];uint32_t i,j;CwServices *s;
    if(!m || !(s=m->services) || s->bound_machine!=m || !ns || ns->bound_machine || s->files || m->instructions || m->exited || !count || count>CW_DIRECTORY_GRANTS || !grants || !ops || !context)return CW_API;
    if(!ops->open || !ops->read || !ops->write || !ops->size || !ops->flush || !ops->close)return CW_API;
    if(overlap(ns,sizeof(*ns),m->image,(size_t)m->plan.image_bytes+CW_STACK) || overlap(ns,sizeof(*ns),s,sizeof(*s)) || overlap(ns,sizeof(*ns),s->heap,s->heap_bytes) || overlap(ns,sizeof(*ns),m,sizeof(*m)) || overlap(grants,count*sizeof(*grants),m->image,(size_t)m->plan.image_bytes+CW_STACK) || overlap(grants,count*sizeof(*grants),s->heap,s->heap_bytes) || overlap(ops,sizeof(*ops),m->image,(size_t)m->plan.image_bytes+CW_STACK) || overlap(ops,sizeof(*ops),s->heap,s->heap_bytes) || overlap(context,1,m->image,(size_t)m->plan.image_bytes+CW_STACK) || overlap(context,1,s->heap,s->heap_bytes))return CW_API;
    memcpy(copy,grants,count*sizeof(*grants));
    for(i=0;i<count;i++) {
        if(!reference(copy[i].ref) || !copy[i].rights || (copy[i].rights&~31U))return CW_API;
        if(copy[i].drive>='a' && copy[i].drive<='z')copy[i].drive-=32;
        if(copy[i].drive<'A' || copy[i].drive>'Z')return CW_API;
        for(j=0;j<i;j++)if(copy[i].drive==copy[j].drive || !strcmp(copy[i].ref,copy[j].ref))return CW_API;
    }
    memset(ns,0,sizeof(*ns));memcpy(ns->mounts,copy,count*sizeof(*grants));ns->mount_count=count;ns->ops=ops;ns->context=context;ns->bound_machine=m;s->files=ns;return CW_OK;
}
static int reserved(const char *s,unsigned int n) {
    unsigned int i=0;char stem[64];
    while(i<n && s[i]!='.'){stem[i]=s[i];i++;}stem[i]=0;
    if(!strcmp(stem,"con") || !strcmp(stem,"prn") || !strcmp(stem,"aux") || !strcmp(stem,"nul") || !strcmp(stem,"conin$") || !strcmp(stem,"conout$") || !strcmp(stem,"clock$"))return 1;
    return i==4 && (!memcmp(stem,"com",3) || !memcmp(stem,"lpt",3)) && stem[3]>='1' && stem[3]<='9';
}
int cw_file_path(const uint16_t *input,char *out,uint32_t *drive) {
    unsigned int i=0,n=0,component=0,parts=0;char current[64];
    *drive='C';
    if(!input || !input[0])return 123;
    if(input[0]=='/' || input[0]=='\\')return 123;
    if(input[1]==':') {
        if(!((input[0]>='a' && input[0]<='z') || (input[0]>='A' && input[0]<='Z')) || input[2]!='\\')return 123;
        *drive=input[0]>='a'?(uint32_t)input[0]-32:(uint32_t)input[0];i=3;
    }
    for(;i<=CW_PATH_LIMIT;i++) {
        uint16_t c=input[i];
        if(!c || c=='/' || c=='\\') {
            if(!component || current[component-1]==' ' || current[component-1]=='.' || reserved(current,component) || ++parts>16)return 123;
            if(n+component+(c?1U:0U)>CW_PATH_LIMIT)return 123;
            memcpy(out+n,current,component);n+=component;component=0;
            if(!c){out[n]=0;return 0;}
            out[n++]='/';continue;
        }
        if(c<32 || c>=127 || c==':' || c=='<' || c=='>' || c=='"' || c=='|' || c=='?' || c=='*' || c=='~' || component>=63)return 123;
        current[component++]=(char)(c>='A' && c<='Z'?c+32:c);
    }
    return 123;
}
static CwFileNamespace *namespace_for(CwMachine *m) {
    CwServices *s=m->services;
    if(!s || s->bound_machine!=m || !s->files || s->files->bound_machine!=m)return NULL;
    return s->files;
}
static CwFileHandle *handle(CwFileNamespace *ns,uint64_t token) {
    uint32_t i;if(!ns)return NULL;
    for(i=0;i<CW_FILE_HANDLES;i++)if(ns->handles[i].token==token && token)return &ns->handles[i];
    return NULL;
}
static void put(unsigned char *out,uint64_t value,unsigned int n) { unsigned int i;for(i=0;i<n;i++)out[i]=(unsigned char)(value>>(i*8)); }
static uint64_t create(CwMachine *m,const uint64_t *a) {
    CwServices *s=m->services;CwFileNamespace *ns=namespace_for(m);uint16_t wide[CW_PATH_LIMIT+1];char path[CW_PATH_LIMIT+1];
    uint32_t i,drive,access=0,share=(uint32_t)a[2],mode=(uint32_t)a[4],rights,error,notice=0,slot;
    uint64_t resource=0;
    if(!ns)return failed(s,5,1);
    if(((uint32_t)a[1]&~0xc0000000U) || share&~3U || a[3] || a[6] || ((uint32_t)a[5]!=0 && (uint32_t)a[5]!=0x80) || mode<1 || mode>5)return failed(s,87,1);
    if((uint32_t)a[1]&0x80000000U)access|=CW_FILE_READ;
    if((uint32_t)a[1]&0x40000000U)access|=CW_FILE_WRITE;
    if(mode!=3 && !(access&CW_FILE_WRITE))return failed(s,5,1); /* bounded creation/truncation profile */
    for(i=0;i<=CW_PATH_LIMIT;i++) {
        unsigned char *p;if(a[0]>UINT64_MAX-i*2)return failed(s,998,1);
        p=cw_memory(m,a[0]+i*2,2,CW_R);if(!p)return failed(s,998,1);
        wide[i]=(uint16_t)(p[0]|(uint16_t)p[1]<<8);if(!wide[i])break;
    }
    if(i>CW_PATH_LIMIT)return failed(s,123,1);
    error=(uint32_t)cw_file_path(wide,path,&drive);if(error)return failed(s,error,1);
    for(i=0;i<ns->mount_count;i++)if(ns->mounts[i].drive==drive)break;
    if(i==ns->mount_count)return failed(s,5,1);
    rights=ns->mounts[i].rights;
    if((access&~rights&3U) || (!access && !(rights&CW_GRANT_METADATA)) || ((mode==2 || mode==5) && !(rights&CW_GRANT_WRITE)))return failed(s,5,1);
    for(slot=0;slot<CW_FILE_HANDLES;slot++)if(!ns->handles[slot].token)break;
    if(slot==CW_FILE_HANDLES || ns->serial==UINT32_MAX)return failed(s,4,1);
    error=ns->ops->open(ns->context,i,path,access,share,mode,rights,&resource,&notice);
    if(error)return failed(s,error,1);
    ns->handles[slot].token=UINT64_C(0x0200000000000000)|((uint64_t)++ns->serial<<8)|slot;
    ns->handles[slot].resource=resource;ns->handles[slot].position=0;ns->handles[slot].access=access;ns->handles[slot].mount=i;
    if(mode==2 || mode==4)s->last_error=notice;
    return ns->handles[slot].token;
}
uint64_t cw_file_call(CwMachine *m,unsigned int id,const uint64_t *a) {
    CwServices *s=m->services;CwFileNamespace *ns=namespace_for(m);CwFileHandle *h;
    unsigned char *count=NULL,*buffer=NULL,*result=NULL;uint32_t error=0,actual=0,n=(uint32_t)a[2];uint64_t value=0,base;
    if(id==CW_CREATE_FILE)return create(m,a);
    if(id==CW_CLOSE_HANDLE && (a[0]==0x10001 || a[0]==0x10002)) {
        uint32_t bit=a[0]==0x10001?1:2;
        if(!(s->launch.console_mask&bit) || (s->console_closed&bit))return failed(s,6,0);
        s->console_closed|=bit;return 1;
    }
    if(id==CW_READ_FILE || id==CW_WRITE_FILE) {
        count=cw_memory(m,a[3],4,CW_W);if(!count)return failed(s,a[3]?998:87,0);
        put(count,0,4);
    }
    h=handle(ns,a[0]);if(!h)return failed(s,6,0);
    if(id==CW_CLOSE_HANDLE) {
        uint64_t resource=h->resource;memset(h,0,sizeof(*h));error=ns->ops->close(ns->context,resource);return error?failed(s,error,0):1;
    }
    if(id==CW_READ_FILE || id==CW_WRITE_FILE) {
        uint32_t right=id==CW_READ_FILE?CW_FILE_READ:CW_FILE_WRITE;
        if(!(h->access&right))return failed(s,5,0);
        if(a[4])return failed(s,50,0);
        if(n>CW_FILE_LIMIT)return failed(s,87,0);
        if(id==CW_WRITE_FILE && n>CW_FILE_LIMIT-h->position)return failed(s,223,0);
        if(n && !(buffer=cw_memory(m,a[1],n,id==CW_READ_FILE?CW_W:CW_R)))return failed(s,998,0);
        if(!n)return 1;
        if(id==CW_READ_FILE)error=ns->ops->read(ns->context,h->resource,h->position,ns->scratch,n,&actual);
        else {memcpy(ns->scratch,buffer,n);error=ns->ops->write(ns->context,h->resource,h->position,ns->scratch,n,&actual);}
        if(error)return failed(s,error,0);
        if(actual>n || actual>CW_FILE_LIMIT-h->position)return failed(s,13,0);
        if(id==CW_READ_FILE && actual)memcpy(buffer,ns->scratch,actual);
        h->position+=actual;put(count,actual,4);return 1;
    }
    if(id==CW_GET_FILE_SIZE) {
        if(!(ns->mounts[h->mount].rights&CW_GRANT_METADATA))return failed(s,5,0);
        result=cw_memory(m,a[1],8,CW_W);if(!result)return failed(s,998,0);
        error=ns->ops->size(ns->context,h->resource,&value);
    }else if(id==CW_SET_FILE_POINTER) {
        if(!h->access)return failed(s,5,0);
        if(a[2] && !(result=cw_memory(m,a[2],8,CW_W)))return failed(s,998,0);
        switch((uint32_t)a[3]) {
        case 0:base=0;break;
        case 1:base=h->position;break;
        case 2:
            if(!(ns->mounts[h->mount].rights&CW_GRANT_METADATA))return failed(s,5,0);
            error=ns->ops->size(ns->context,h->resource,&base);if(error)return failed(s,error,0);break;
        default:return failed(s,87,0);
        }
        if(base>CW_FILE_LIMIT)return failed(s,223,0);
        if(a[1]>>63){uint64_t magnitude=(~a[1])+1;if(magnitude>base)return failed(s,131,0);value=base-magnitude;}
        else {if(a[1]>CW_FILE_LIMIT-base)return failed(s,223,0);value=base+a[1];}
        h->position=value;
    }else if(id==CW_FLUSH_FILE_BUFFERS) {
        if(!(h->access&CW_FILE_WRITE))return failed(s,5,0);
        error=ns->ops->flush(ns->context,h->resource);
    }else return failed(s,6,0);
    if(error)return failed(s,error,0);
    if(value>CW_FILE_LIMIT)return failed(s,223,0);
    if(result)put(result,value,8);
    return 1;
}
void cw_files_close_all(CwMachine *m) {
    CwFileNamespace *ns;uint32_t i;
    if(!m || !(ns=namespace_for(m)))return;
    for(i=0;i<CW_FILE_HANDLES;i++)if(ns->handles[i].token) {
        uint64_t resource=ns->handles[i].resource;memset(&ns->handles[i],0,sizeof(ns->handles[i]));
        (void)ns->ops->close(ns->context,resource);
    }
}
