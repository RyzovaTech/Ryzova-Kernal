/* SPDX-License-Identifier: AGPL-3.0-only */
/* Guest-owned bounded objects. Never pass handles/pointers to the host OS. */
#include "api.h"
#include "files.h"
#ifndef CW_PLAN9
#include <string.h>
#endif
#define EVENT 1U
#define SEMAPHORE 2U
#define PROCESS 3U
#define THREAD 4U
#define MODIFY 2U
#define SYNCHRONIZE 0x100000U
#define OBJECT_ACCESS 0x1f0003U
#define IDENTITY_ACCESS 0x1fffffU
#define HANDLE_BASE UINT64_C(0x0300000000000000)
static uint64_t fail(CwServices *s,uint32_t error) { s->last_error=error;return 0; }
static void put32(unsigned char *p,uint32_t v) { unsigned int i;for(i=0;i<4;i++)p[i]=(unsigned char)(v>>(8*i)); }
static void put64(unsigned char *p,uint64_t v) { unsigned int i;for(i=0;i<8;i++)p[i]=(unsigned char)(v>>(8*i)); }
static uint64_t get64(const unsigned char *p) { unsigned int i;uint64_t v=0;for(i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v; }
int cw_sync_handle_family(uint64_t value) { return (value>>56)==3; }
static CwSyncHandle *handle(CwServices *s,uint64_t token) {
    unsigned int i;
    for(i=0;i<CW_SYNC_HANDLES;i++)if(token && s->sync_handles[i].token==token)return &s->sync_handles[i];
    return NULL;
}
static CwSyncObject *object(CwServices *s,CwSyncHandle *h) {
    if(!h || !h->object || h->object>CW_SYNC_OBJECTS)return NULL;
    return s->sync_objects[h->object-1].refs?&s->sync_objects[h->object-1]:NULL;
}
static uint64_t new_handle(CwServices *s,unsigned int index,uint32_t access,uint32_t flags) {
    unsigned int i;CwSyncHandle *h;
    for(i=0;i<CW_SYNC_HANDLES;i++)if(!s->sync_handles[i].token)break;
    if(i==CW_SYNC_HANDLES || s->sync_serial==UINT32_MAX)return fail(s,8);
    h=&s->sync_handles[i];h->token=HANDLE_BASE|((uint64_t)++s->sync_serial<<8)|i;
    h->object=index+1;h->access=access;h->flags=flags;s->sync_objects[index].refs++;
    return h->token;
}
static uint64_t close_handle(CwServices *s,uint64_t token) {
    CwSyncHandle *h=handle(s,token);CwSyncObject *o=object(s,h);
    if(!o)return fail(s,6);
    if(!--o->refs)memset(o,0,sizeof(*o));
    memset(h,0,sizeof(*h));return 1;
}
static uint64_t create_object(CwServices *s,unsigned int type,const uint64_t *a) {
    unsigned int i;CwSyncObject *o;uint64_t token;
    if(a[0] || a[3])return fail(s,50); /* security descriptors/names need a separate profile */
    if(type==SEMAPHORE && ((int32_t)a[1]<0 || (int32_t)a[2]<=0 || (uint32_t)a[1]>(uint32_t)a[2]))return fail(s,87);
    for(i=0;i<CW_SYNC_OBJECTS;i++)if(!s->sync_objects[i].refs)break;
    if(i==CW_SYNC_OBJECTS)return fail(s,8);
    o=&s->sync_objects[i];o->type=type;
    o->flags=type==EVENT?!!(uint32_t)a[1]:0;
    o->count=type==EVENT?!!(uint32_t)a[2]:(uint32_t)a[1];
    o->maximum=type==EVENT?1:(uint32_t)a[2];
    token=new_handle(s,i,OBJECT_ACCESS,0);
    if(!token)memset(o,0,sizeof(*o));
    return token;
}
static int process_handle(CwServices *s,uint64_t token) {
    CwSyncHandle *h;CwSyncObject *o;
    if(token==UINT64_MAX)return 1;
    h=handle(s,token);o=object(s,h);
    if(!o || o->type!=PROCESS)return 0;
    return (h->access&0x40)?1:-1;
}
static uint64_t duplicate_object(CwMachine *m,const uint64_t *a) {
    CwServices *s=m->services;CwSyncHandle *h;CwSyncObject *o;
    uint32_t options=(uint32_t)a[6],access,index,type=0;unsigned char *out;int source,target;
    uint64_t token;
    if(options&~3U)return fail(s,87);
    source=process_handle(s,a[0]);target=process_handle(s,a[2]);
    if(source<0 || target<0)return fail(s,5);
    if(!source || !target)return fail(s,6);
    out=cw_memory(m,a[3],8,CW_W);if(!out)return fail(s,a[3]?998:87);
    if(a[1]==UINT64_MAX)type=PROCESS;
    else if(a[1]==UINT64_MAX-1)type=THREAD;
    h=handle(s,a[1]);o=object(s,h);
    if(!type && !o)return fail(s,(a[1]>>56)==2?50:6);
    access=type?IDENTITY_ACCESS:h->access;
    if(!(options&2U)){
        if((uint32_t)a[4]&~access)return fail(s,5);
        access=(uint32_t)a[4];
    }
    if(type){
        for(index=0;index<CW_SYNC_OBJECTS;index++)if(s->sync_objects[index].refs && s->sync_objects[index].type==type)break;
        if(index==CW_SYNC_OBJECTS){
            for(index=0;index<CW_SYNC_OBJECTS;index++)if(!s->sync_objects[index].refs)break;
            if(index==CW_SYNC_OBJECTS)return fail(s,8);
        }
        o=&s->sync_objects[index];o->type=type;
    }else index=h->object-1;
    token=new_handle(s,index,access,!!(uint32_t)a[5]);
    if(!token){if(!o->refs)memset(o,0,sizeof(*o));return 0;}
    put64(out,token);return 1;
}
static uint64_t duplicate(CwMachine *m,const uint64_t *a) {
    uint64_t result=duplicate_object(m,a);uint32_t error=m->services->last_error;
    /* DUPLICATE_CLOSE_SOURCE closes the source even when duplication fails. */
    if(((uint32_t)a[6]&1) && handle(m->services,a[1]))close_handle(m->services,a[1]);
    else if(((uint32_t)a[6]&1) && (a[1]>>56)==2){
        uint64_t close_args[7]={0,0,0,0,0,0,0};close_args[0]=a[1];
        cw_file_call(m,CW_CLOSE_HANDLE,close_args);
    }
    m->services->last_error=error;return result;
}
static int object_ready(const CwSyncObject *o) { return (o->type==EVENT || o->type==SEMAPHORE) && o->count!=0; }
static void object_consume(CwSyncObject *o) { if(o->type==SEMAPHORE)o->count--;else if(o->type==EVENT && !o->flags)o->count=0; }
static int wait_objects(CwMachine *m,unsigned int id,const uint64_t *a,uint64_t *result) {
    CwServices *s=m->services;CwSyncObject *objects[16],pseudo[2];
    uint64_t tokens[16];uint32_t count,all,timeout,i,j;unsigned char *list=NULL;
    memset(pseudo,0,sizeof(pseudo));pseudo[0].type=PROCESS;pseudo[1].type=THREAD;
    if(id==CW_WAIT_SINGLE){count=1;all=0;timeout=(uint32_t)a[1];tokens[0]=a[0];}
    else {
        count=(uint32_t)a[0];all=!!(uint32_t)a[2];timeout=(uint32_t)a[3];
        if(!count || count>16){fail(s,87);*result=UINT32_MAX;return CW_OK;}
        list=cw_memory(m,a[1],count*8,CW_R);
        if(!list){fail(s,998);*result=UINT32_MAX;return CW_OK;}
        for(i=0;i<count;i++)tokens[i]=get64(list+i*8);
    }
    for(i=0;i<count;i++){
        if(tokens[i]==UINT64_MAX)objects[i]=&pseudo[0];
        else if(tokens[i]==UINT64_MAX-1)objects[i]=&pseudo[1];
        else {
            CwSyncHandle *h=handle(s,tokens[i]);objects[i]=object(s,h);
            if(!objects[i]){fail(s,6);*result=UINT32_MAX;return CW_OK;}
            if(!(h->access&SYNCHRONIZE)){fail(s,5);*result=UINT32_MAX;return CW_OK;}
        }
        for(j=0;j<i;j++)if(objects[j]==objects[i]){fail(s,87);*result=UINT32_MAX;return CW_OK;}
    }
    if(all){
        for(i=0;i<count;i++)if(!object_ready(objects[i]))break;
        if(i==count){for(i=0;i<count;i++)object_consume(objects[i]);*result=0;return CW_OK;}
    }else for(i=0;i<count;i++)if(object_ready(objects[i])){object_consume(objects[i]);*result=i;return CW_OK;}
    if(timeout)return CW_API; /* no scheduler: never pretend a blocking wait completed */
    *result=258;return CW_OK;
}
static int critical(CwMachine *m,unsigned int id,uint64_t address,uint64_t *result) {
    CwServices *s=m->services;CwCritical *c=NULL;unsigned int i;unsigned char *bytes=cw_memory(m,address,40,CW_W);
    if(!bytes)return CW_MEMORY;
    for(i=0;i<CW_CRITICAL_LIMIT;i++)if(s->criticals[i].address==address){c=&s->criticals[i];break;}
    if(id==CW_CRITICAL_INIT){
        if(c)return CW_API;
        for(i=0;i<CW_CRITICAL_LIMIT;i++)if(!s->criticals[i].address)break;
        if(i==CW_CRITICAL_LIMIT)return CW_API;
        c=&s->criticals[i];c->address=address;c->depth=0;memset(bytes,0,40);
    }else if(!c)return CW_API;
    else if(id==CW_CRITICAL_DELETE){
        if(c->depth)return CW_API;
        memset(c,0,sizeof(*c));memset(bytes,0,40);*result=0;return CW_OK;
    }else if(id==CW_CRITICAL_LEAVE){if(!c->depth)return CW_API;c->depth--;}
    else {if(c->depth==UINT32_MAX)return CW_API;c->depth++;}
    put32(bytes+8,c->depth?UINT32_MAX-1:UINT32_MAX);put32(bytes+12,c->depth);put64(bytes+16,c->depth?1:0);
    *result=id==CW_CRITICAL_TRY?1:0;return CW_OK;
}
int cw_sync_call(CwMachine *m,unsigned int id,const uint64_t *a,uint64_t *result) {
    CwServices *s=m->services;CwSyncHandle *h;CwSyncObject *o;
    *result=0;
    switch(id){
    case CW_GET_THREAD_PRIORITY:case CW_SET_THREAD_PRIORITY:{
        int get=id==CW_GET_THREAD_PRIORITY;
        int32_t priority=(int32_t)a[1];
        if(get)*result=0x7fffffff;
        if(a[0]!=UINT64_MAX-1){
            h=handle(s,a[0]);o=object(s,h);
            if(!o || o->type!=THREAD){fail(s,6);return CW_OK;}
            if(!(h->access&(get?0x840U:0x420U))){fail(s,5);return CW_OK;}
        }
        if(get)*result=(uint32_t)s->thread_priority;
        else {
            if(priority!= -15 && priority!=15 && (priority< -2 || priority>2)){fail(s,87);return CW_OK;}
            s->thread_priority=priority;
            *result=1;
        }
        return CW_OK;
    }
    case CW_CURRENT_PROCESS:*result=UINT64_MAX;return CW_OK;
    case CW_CURRENT_THREAD:*result=UINT64_MAX-1;return CW_OK;
    case CW_CURRENT_PROCESS_ID:case CW_CURRENT_THREAD_ID:*result=1;return CW_OK;
    case CW_CREATE_EVENT:*result=create_object(s,EVENT,a);return CW_OK;
    case CW_CREATE_SEMAPHORE:*result=create_object(s,SEMAPHORE,a);return CW_OK;
    case CW_DUPLICATE_HANDLE:*result=duplicate(m,a);return CW_OK;
    case CW_CLOSE_HANDLE:*result=close_handle(s,a[0]);return CW_OK;
    case CW_WAIT_SINGLE:case CW_WAIT_MULTIPLE:return wait_objects(m,id,a,result);
    case CW_CRITICAL_INIT:case CW_CRITICAL_DELETE:case CW_CRITICAL_ENTER:case CW_CRITICAL_LEAVE:case CW_CRITICAL_TRY:
        return critical(m,id,a[0],result);
    case CW_SET_EVENT:case CW_RESET_EVENT:case CW_RELEASE_SEMAPHORE:
        h=handle(s,a[0]);o=object(s,h);
        if(!o){*result=fail(s,6);return CW_OK;}
        if(!(h->access&MODIFY)){*result=fail(s,5);return CW_OK;}
        if(id==CW_RELEASE_SEMAPHORE){
            unsigned char *previous=NULL;uint32_t release=(uint32_t)a[1];
            if(o->type!=SEMAPHORE){*result=fail(s,6);return CW_OK;}
            if((int32_t)release<=0){*result=fail(s,87);return CW_OK;}
            if(release>o->maximum-o->count){*result=fail(s,298);return CW_OK;}
            if(a[2] && !(previous=cw_memory(m,a[2],4,CW_W))){*result=fail(s,998);return CW_OK;}
            if(previous)put32(previous,o->count);
            o->count+=release;
        }else {
            if(o->type!=EVENT){*result=fail(s,6);return CW_OK;}
            o->count=id==CW_SET_EVENT;
        }
        *result=1;return CW_OK;
    default:return CW_API;
    }
}
