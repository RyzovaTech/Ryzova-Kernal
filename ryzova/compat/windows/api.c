/* SPDX-License-Identifier: AGPL-3.0-only */
#include "api.h"
#include "files.h"
#include <string.h>
#define ERR_INVALID_HANDLE 6U
#define ERR_MEMORY 8U
#define ERR_UNSUPPORTED 50U
#define ERR_PARAMETER 87U
#define ERR_ENVIRONMENT 203U
#define ERR_ADDRESS 487U
#define ERR_NOACCESS 998U
static const char *const names[CW_API_COUNT]={"GetStdHandle","WriteFile","ExitProcess","GetLastError","SetLastError","GetCommandLineW","GetEnvironmentVariableW","VirtualAlloc","VirtualFree","CreateFileW","ReadFile","CloseHandle","SetFilePointerEx","GetFileSizeEx","FlushFileBuffers"};
int cw_api_id(const char *name) {
    unsigned int i;for(i=0;i<CW_API_COUNT;i++)if(!strcmp(name,names[i]))return (int)i;
    return -1;
}
const char *cw_api_name(unsigned int id) { return id<CW_API_COUNT?names[id]:NULL; }
uint64_t cw_api_token(unsigned int id) { return id<CW_API_COUNT?CW_THUNK_BASE+16U*id:0; }
static int span(uint64_t size,uint64_t at,uint64_t bytes) { return at<=size && bytes<=size-at; }
static int utf16_length(const uint16_t *text,unsigned int capacity,int name) {
    unsigned int i;
    for(i=0;i<capacity;i++) {
        uint16_t c=text[i];if(!c)return (int)i;
        if(name && !((c>='A' && c<='Z') || (c>='a' && c<='z') || c=='_' || (i && c>='0' && c<='9')))return -1;
        if(c>=0xd800 && c<=0xdbff){if(i+1>=capacity || text[i+1]<0xdc00 || text[i+1]>0xdfff)return -1;i++;}
        else if(c>=0xdc00 && c<=0xdfff)return -1;
    }
    return -1;
}
static int same_name(const uint16_t *a,const uint16_t *b) {
    unsigned int i;
    for(i=0;i<64;i++) {
        uint16_t x=a[i],y=b[i];if(x>='a' && x<='z')x=(uint16_t)(x-32);if(y>='a' && y<='z')y=(uint16_t)(y-32);
        if(x!=y)return 0;
        if(!x)return 1;
    }
    return 0;
}
static int overlap(const void *a,size_t an,const void *b,size_t bn) {
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    if(!an || !bn)return 0;
    return x<=y?y-x<an:x-y<bn;
}
int cw_attach_services(CwMachine *m,CwServices *s,const CwLaunch *launch,unsigned char *heap,size_t heap_bytes) {
    unsigned int i,j;int length;CwLaunch copy;
    if(!m || !m->image || !s || !launch || s->bound_machine || m->services || m->instructions || m->exited)return CW_API;
    if((launch->api_mask&~CW_ALL_APIS) || (m->plan.api_mask&~launch->api_mask) ||
       (launch->console_mask&~3U) || launch->environment_count>CW_ENV_COUNT ||
       heap_bytes>CW_HEAP_LIMIT || heap_bytes%4096 || (heap_bytes && !heap) ||
       (size_t)m->plan.image_bytes+CW_STACK+4096+heap_bytes>CW_MAX_MEMORY)return CW_API;
    length=utf16_length(launch->command_line,CW_COMMAND_UNITS,0);if(length<0)return CW_API;
    for(i=0;i<launch->environment_count;i++) {
        if(utf16_length(launch->environment[i].name,64,1)<=0 || utf16_length(launch->environment[i].value,256,0)<0)return CW_API;
        for(j=0;j<i;j++)if(same_name(launch->environment[i].name,launch->environment[j].name))return CW_API;
    }
    /* Guest-writable backing must not alias trusted service/policy/machine state. */
    {
        size_t used=(size_t)m->plan.image_bytes+CW_STACK;
        if(overlap(m,sizeof(*m),m->image,used) || overlap(s,sizeof(*s),m,sizeof(*m)) || overlap(s,sizeof(*s),m->image,used) ||
           overlap(launch,sizeof(*launch),m->image,used) ||
           overlap(heap,heap_bytes,m->image,used) || overlap(heap,heap_bytes,m,sizeof(*m)) ||
           overlap(heap,heap_bytes,s,sizeof(*s)) || overlap(heap,heap_bytes,launch,sizeof(*launch)))return CW_API;
    }
    copy=*launch;
    memset(s,0,sizeof(*s));s->launch=copy;s->heap=heap;s->heap_bytes=heap_bytes;
    s->command_base=(m->stack_base+CW_STACK+4096+65535)&~UINT64_C(65535);
    s->heap_base=s->command_base+65536;
    for(i=0;i<=(unsigned int)length;i++){s->command_bytes[2*i]=(unsigned char)copy.command_line[i];s->command_bytes[2*i+1]=(unsigned char)(copy.command_line[i]>>8);}
    if(heap_bytes)memset(heap,0,heap_bytes);
    s->bound_machine=m;m->services=s;return CW_OK;
}
unsigned char *cw_service_memory(CwMachine *m,uint64_t at,size_t n,unsigned int rights) {
    CwServices *s=m->services;uint64_t off;size_t first,last,i;
    if(!s || s->bound_machine!=m || !n)return NULL;
    if(at>=s->command_base && span(sizeof(s->command_bytes),at-s->command_base,n))
        return rights==CW_R?s->command_bytes+(size_t)(at-s->command_base):NULL;
    if(at<s->heap_base || !span(s->heap_bytes,at-s->heap_base,n) || rights==CW_X)return NULL;
    off=at-s->heap_base;first=(size_t)(off/4096);last=(size_t)((off+n-1)/4096);
    for(i=first;i<=last;i++)if(!s->owner[i] || !(s->protection[i]&rights))return NULL;
    return s->heap+(size_t)off;
}
static uint64_t fail(CwServices *s,uint32_t error) { s->last_error=error;return 0; }
static void put32(unsigned char *p,uint32_t v) {
    unsigned int i;for(i=0;i<4;i++)p[i]=(unsigned char)(v>>(i*8));
}
static uint64_t get64(const unsigned char *p) {
    unsigned int i;uint64_t v=0;for(i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;
}
static uint64_t write_file(CwMachine *m,const uint64_t *a) {
    CwServices *s=m->services;unsigned char *written,*input=NULL;uint32_t n=(uint32_t)a[2];unsigned int stream;
    written=cw_memory(m,a[3],4,CW_W);if(!written)return fail(s,a[3]?ERR_NOACCESS:ERR_PARAMETER);
    put32(written,0);
    if(a[0]==UINT64_C(0x10001))stream=0;
    else if(a[0]==UINT64_C(0x10002))stream=1;
    else return fail(s,ERR_INVALID_HANDLE);
    if(!(s->launch.console_mask&(1U<<stream)) || (s->console_closed&(1U<<stream)))return fail(s,ERR_INVALID_HANDLE);
    if(a[4])return fail(s,ERR_UNSUPPORTED);
    if(n>CW_OUTPUT_LIMIT)return fail(s,ERR_PARAMETER);
    if(n && !(input=cw_memory(m,a[1],n,CW_R)))return fail(s,ERR_NOACCESS);
    if(n>CW_OUTPUT_LIMIT-s->output_bytes[0]-s->output_bytes[1])return fail(s,ERR_MEMORY);
    if(n)memcpy(s->output[stream]+s->output_bytes[stream],input,n);
    s->output_bytes[stream]+=n;put32(written,n);return 1;
}
static uint64_t environment(CwMachine *m,const uint64_t *a) {
    CwServices *s=m->services;uint16_t name[64];unsigned int i,n;uint32_t capacity=(uint32_t)a[2];
    for(i=0;i<64;i++) {
        unsigned char *p;if(a[0]>UINT64_MAX-i*2)return fail(s,ERR_NOACCESS);
        p=cw_memory(m,a[0]+i*2,2,CW_R);if(!p)return fail(s,ERR_NOACCESS);
        name[i]=(uint16_t)(p[0]|(uint16_t)p[1]<<8);if(!name[i])break;
    }
    if(i==64 || utf16_length(name,64,1)<=0)return fail(s,ERR_PARAMETER);
    for(i=0;i<s->launch.environment_count;i++)if(same_name(name,s->launch.environment[i].name)) {
        unsigned char *out;const uint16_t *value=s->launch.environment[i].value;
        n=(unsigned int)utf16_length(value,256,0);
        if(capacity<n+1)return n+1;
        out=cw_memory(m,a[1],(n+1)*2,CW_W);if(!out)return fail(s,ERR_NOACCESS);
        for(i=0;i<=n;i++){out[i*2]=(unsigned char)value[i];out[i*2+1]=(unsigned char)(value[i]>>8);}
        if(!n)s->last_error=0;
        return n;
    }
    return fail(s,ERR_ENVIRONMENT);
}
static unsigned int protection(uint32_t windows) {
    switch(windows){case 1:return 0;case 2:return CW_R;case 4:return CW_R|CW_W;default:return 256;}
}
static uint64_t virtual_alloc(CwMachine *m,const uint64_t *a) {
    CwServices *s=m->services;uint64_t address=a[0],size=a[1],offset;uint32_t type=(uint32_t)a[2];
    unsigned int rights=protection((uint32_t)a[3]);size_t first,pages,i,slot=16;int reserve;
    if(!size || !type || (type&~0x3000U) || rights==256)return fail(s,ERR_PARAMETER);
    if(size>s->heap_bytes)return fail(s,ERR_MEMORY);
    reserve=!!(type&0x2000U) || !address;
    if(reserve) {
        pages=(size_t)((size+4095)/4096);
        for(i=0;i<16;i++)if(!s->allocations[i].pages){slot=i;break;}
        if(slot==16)return fail(s,ERR_MEMORY);
        if(address) {
            if(address<s->heap_base || (address&65535) || !span(s->heap_bytes,address-s->heap_base,pages*4096))return fail(s,ERR_ADDRESS);
            first=(size_t)((address-s->heap_base)/4096);
            for(i=0;i<pages;i++)if(s->owner[first+i])return fail(s,ERR_ADDRESS);
        }else {
            for(first=0;first+pages<=s->heap_bytes/4096;first+=16) {
                for(i=0;i<pages;i++)if(s->owner[first+i])break;
                if(i==pages)break;
            }
            if(first+pages>s->heap_bytes/4096)return fail(s,ERR_MEMORY);
        }
        s->allocations[slot].first=(uint32_t)first;s->allocations[slot].pages=(uint32_t)pages;
        for(i=0;i<pages;i++)s->owner[first+i]=(unsigned char)(slot+1);
    }else {
        if(address<s->heap_base || !span(s->heap_bytes,address-s->heap_base,size))return fail(s,ERR_ADDRESS);
        offset=address-s->heap_base;first=(size_t)(offset/4096);pages=(size_t)((offset%4096+size+4095)/4096);
        slot=s->owner[first]?s->owner[first]-1U:16;
        if(slot==16)return fail(s,ERR_ADDRESS);
        for(i=0;i<pages;i++)if(s->owner[first+i]!=slot+1)return fail(s,ERR_ADDRESS);
    }
    if(type&0x1000U)for(i=0;i<pages;i++) {
        /* A private high bit distinguishes committed PAGE_NOACCESS from reserved. */
        if(!(s->protection[first+i]&128U)) {
            memset(s->heap+(first+i)*4096,0,4096);
            s->protection[first+i]=(unsigned char)(rights|128U);
        }
    }
    return s->heap_base+first*4096;
}
static uint64_t virtual_free(CwMachine *m,const uint64_t *a) {
    CwServices *s=m->services;uint64_t offset,size=a[1];uint32_t type=(uint32_t)a[2];size_t first,pages,slot,i;
    if(type!=0x8000 && type!=0x4000)return fail(s,ERR_PARAMETER);
    if(a[0]<s->heap_base || !span(s->heap_bytes,a[0]-s->heap_base,1))return fail(s,ERR_ADDRESS);
    offset=a[0]-s->heap_base;first=(size_t)(offset/4096);slot=s->owner[first]?s->owner[first]-1U:16;
    if(slot==16)return fail(s,ERR_ADDRESS);
    if(type==0x8000 || !size) {
        if(offset!=(uint64_t)s->allocations[slot].first*4096 || (type==0x8000 && size))return fail(s,ERR_PARAMETER);
        first=s->allocations[slot].first;pages=s->allocations[slot].pages;
    }else {
        if(!span(s->heap_bytes,offset,size))return fail(s,ERR_ADDRESS);
        pages=(size_t)((offset%4096+size+4095)/4096);
        for(i=0;i<pages;i++)if(s->owner[first+i]!=slot+1)return fail(s,ERR_ADDRESS);
    }
    for(i=0;i<pages;i++) {
        s->protection[first+i]=0;memset(s->heap+(first+i)*4096,0,4096);
        if(type==0x8000)s->owner[first+i]=0;
    }
    if(type==0x8000)s->allocations[slot].pages=0;
    return 1;
}
int cw_api_dispatch(CwMachine *m) {
    uint64_t token=m->ip;unsigned int id;uint64_t a[7],result=0,ret;unsigned char *stack;
    CwServices *s=m->services;
    if(token<CW_THUNK_BASE || token-CW_THUNK_BASE>=16U*CW_API_COUNT || (token-CW_THUNK_BASE)%16)return CW_MEMORY;
    id=(unsigned int)((token-CW_THUNK_BASE)/16);
    if(!s || s->bound_machine!=m || !(m->plan.api_mask&(1U<<id)) || !(s->launch.api_mask&(1U<<id)))return CW_API;
    if((m->r[4]&15)!=8 || m->r[4]<m->stack_base || m->r[4]-m->stack_base>CW_STACK-40 || !(stack=cw_memory(m,m->r[4],40,CW_R)))return CW_ABI;
    if(!cw_memory(m,m->r[4]+8,32,CW_W))return CW_ABI;
    a[0]=m->r[1];a[1]=m->r[2];a[2]=m->r[8];a[3]=m->r[9];a[4]=a[5]=a[6]=0;
    if(id==CW_WRITE_FILE || id==CW_READ_FILE || id==CW_CREATE_FILE) {
        unsigned int count=id==CW_CREATE_FILE?3U:1U,i;
        unsigned char *extra=cw_memory(m,m->r[4]+40,count*8,CW_R);if(!extra)return CW_ABI;
        for(i=0;i<count;i++)a[4+i]=get64(extra+i*8);
    }
    ret=get64(stack);s->calls[id]++;
    switch(id) {
    case CW_GET_STD_HANDLE:
        if((uint32_t)a[0]==UINT32_MAX-10)result=(s->launch.console_mask&1)?0x10001:0;
        else if((uint32_t)a[0]==UINT32_MAX-11)result=(s->launch.console_mask&2)?0x10002:0;
        else if((uint32_t)a[0]==UINT32_MAX-9)result=0; /* stdin absent */
        else {s->last_error=ERR_PARAMETER;result=UINT64_MAX;}
        break;
    case CW_WRITE_FILE:
        result=(a[0]==0x10001 || a[0]==0x10002)?write_file(m,a):cw_file_call(m,id,a);break;
    case CW_EXIT_PROCESS:cw_files_close_all(m);m->exit_code=(uint32_t)a[0];m->exited=1;m->exit_kind=1;return CW_OK;
    case CW_GET_LAST_ERROR:result=s->last_error;break;
    case CW_SET_LAST_ERROR:s->last_error=(uint32_t)a[0];break;
    case CW_GET_COMMAND_LINE:result=s->command_base;break;
    case CW_GET_ENVIRONMENT_VARIABLE:result=environment(m,a);break;
    case CW_VIRTUAL_ALLOC:result=virtual_alloc(m,a);break;
    case CW_VIRTUAL_FREE:result=virtual_free(m,a);break;
    case CW_CREATE_FILE:case CW_READ_FILE:case CW_CLOSE_HANDLE:
    case CW_SET_FILE_POINTER:case CW_GET_FILE_SIZE:case CW_FLUSH_FILE_BUFFERS:
        result=cw_file_call(m,id,a);break;
    default:return CW_API;
    }
    m->r[0]=result;m->r[4]+=8;
    if(ret==UINT64_MAX) {
        if(m->r[4]-8!=m->initial_sp)return CW_ABI;
        m->exited=1;m->exit_code=(uint32_t)result;
    }else m->ip=ret;
    /* Nonvolatile integer/vector state remains intact; volatile state is unspecified. */
    return CW_OK;
}
