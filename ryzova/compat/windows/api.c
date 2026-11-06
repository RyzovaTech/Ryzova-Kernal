/* SPDX-License-Identifier: AGPL-3.0-only */
#include "api.h"
#include "files.h"
#ifndef CW_PLAN9
#include <string.h>
#endif
#define ERR_INVALID_HANDLE 6U
#define ERR_MEMORY 8U
#define ERR_UNSUPPORTED 50U
#define ERR_PARAMETER 87U
#define ERR_ENVIRONMENT 203U
#define ERR_ADDRESS 487U
#define ERR_NOACCESS 998U
static const char *const names[]={"GetStdHandle","WriteFile","ExitProcess","GetLastError","SetLastError","GetCommandLineW","GetEnvironmentVariableW","VirtualAlloc","VirtualFree","CreateFileW","ReadFile","CloseHandle","SetFilePointerEx","GetFileSizeEx","FlushFileBuffers","memcpy","memmove","memset","memcmp","strlen","strcmp","strncmp","wcslen","malloc","calloc","realloc","free","_errno","AreFileApisANSI","SetFileApisToANSI","SetFileApisToOEM","TlsAlloc","TlsFree","TlsGetValue","TlsSetValue","CreateEventA","SetEvent","ResetEvent","CreateSemaphoreA","ReleaseSemaphore","WaitForSingleObject","WaitForMultipleObjects","InitializeCriticalSection","DeleteCriticalSection","EnterCriticalSection","LeaveCriticalSection","TryEnterCriticalSection","GetCurrentProcess","GetCurrentProcessId","GetCurrentThread","GetCurrentThreadId","DuplicateHandle","SetUnhandledExceptionFilter","_set_invalid_parameter_handler","_set_app_type","__p__fmode","__p__commode","_initterm","_initterm_e","_initialize_wide_environment","_configure_wide_argv","__p___argc","__p___wargv","__p__wenviron","_set_new_mode","_crt_atexit","_cexit","exit","_exit","GetModuleHandleA","GetProcAddress","rand_s","WideCharToMultiByte","setlocale"};
typedef char CwApiRegistryCount[(sizeof(names)/sizeof(names[0])==CW_API_COUNT)?1:-1];
int cw_api_id(const char *name) {
    unsigned int i;for(i=0;i<CW_API_COUNT;i++)if(names[i] && !strcmp(name,names[i]))return (int)i;
    return -1;
}
const char *cw_api_module(unsigned int id) { return id>=CW_API_COUNT?NULL:(cw_crt_export(id)?"ucrtbase.dll":"kernel32.dll"); }
uint32_t cw_api_word_mask(unsigned int word) {
    unsigned int remaining;
    if(word>=CW_API_WORDS || word*32>=CW_API_COUNT)return 0;
    remaining=CW_API_COUNT-word*32;
    return remaining>=32?UINT32_MAX:(1U<<remaining)-1U;
}
int cw_plan_has_api(const CwPlan *p,unsigned int id) {
    uint32_t word;
    if(id>=CW_API_COUNT)return 0;
    word=id<32?p->api_mask:p->api_mask_high[id/32-1];return !!(word&(1U<<(id%32)));
}
void cw_plan_add_api(CwPlan *p,unsigned int id) {
    if(id>=CW_API_COUNT)return;
    if(id<32)p->api_mask|=1U<<id;
    else p->api_mask_high[id/32-1]|=1U<<(id%32);
}
int cw_launch_allows_plan(const CwLaunch *launch,const CwPlan *p) {
    unsigned int i;
    if((launch->profile_flags&~CW_PROFILE_TRACE) || (p->profile_flags&~launch->profile_flags))return 0;
    if((launch->api_mask&~cw_api_word_mask(0)) || (p->api_mask&~launch->api_mask))return 0;
    for(i=1;i<CW_API_WORDS;i++)if((launch->api_mask_high[i-1]&~cw_api_word_mask(i)) ||
        (p->api_mask_high[i-1]&~launch->api_mask_high[i-1]))return 0;
    return 1;
}
int cw_api_module_id(const char *name) {
    static const char *const modules[]={"kernel32.dll","ucrtbase.dll",
        "api-ms-win-crt-heap-l1-1-0.dll","api-ms-win-crt-private-l1-1-0.dll",
        "api-ms-win-crt-string-l1-1-0.dll","api-ms-win-crt-runtime-l1-1-0.dll",
        "api-ms-win-crt-stdio-l1-1-0.dll","api-ms-win-crt-environment-l1-1-0.dll","api-ms-win-crt-utility-l1-1-0.dll","api-ms-win-crt-locale-l1-1-0.dll"};
    unsigned int i;for(i=0;i<sizeof(modules)/sizeof(modules[0]);i++)if(!strcmp(name,modules[i]))return (int)i+1;
    return 0;
}
int cw_api_module_matches(unsigned int id,const char *module) {
    const char *alias;
    if(id>=CW_API_COUNT || !cw_api_module_id(module))return 0;
    if(!strcmp(cw_api_module(id),module))return 1;
    alias=cw_crt_alias(id);return alias && !strcmp(alias,module);
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
    if(!cw_launch_allows_plan(launch,&m->plan) ||
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
    memset(s,0,sizeof(*s));s->launch=copy;s->heap=heap;s->heap_bytes=heap_bytes;s->file_apis_ansi=1;s->crt_globals[1]=0x40;
    s->command_base=(m->stack_base+CW_STACK+4096+65535)&~UINT64_C(65535);
    s->heap_base=s->command_base+65536;
    for(i=0;i<=(unsigned int)length;i++){s->command_bytes[2*i]=(unsigned char)copy.command_line[i];s->command_bytes[2*i+1]=(unsigned char)(copy.command_line[i]>>8);}
    if(heap_bytes)memset(heap,0,heap_bytes);
    s->bound_machine=m;m->services=s;return CW_OK;
}
unsigned char *cw_service_memory(CwMachine *m,uint64_t at,size_t n,unsigned int rights) {
    static unsigned char c_locale[2]={'C',0};
    CwServices *s=m->services;uint64_t off;size_t first,last,i;
    if(!s || s->bound_machine!=m || !n)return NULL;
    if(at>=s->command_base && span(sizeof(s->command_bytes),at-s->command_base,n))
        return rights==CW_R?s->command_bytes+(size_t)(at-s->command_base):NULL;
    if(at>=s->command_base+4096 && span(4,at-s->command_base-4096,n))
        return rights==CW_X?NULL:s->errno_bytes+(size_t)(at-s->command_base-4096);
    if(at>=s->command_base+4112 && span(sizeof(s->crt_globals),at-s->command_base-4112,n))
        return (rights&CW_X)?NULL:s->crt_globals+(size_t)(at-s->command_base-4112);
    if(at>=s->command_base+8192 && span(sizeof(s->crt_argv),at-s->command_base-8192,n))
        return (rights&CW_X)?NULL:s->crt_argv+(size_t)(at-s->command_base-8192);
    if(at>=s->command_base+16384 && span(sizeof(s->crt_environment),at-s->command_base-16384,n))
        return (rights&CW_X)?NULL:s->crt_environment+(size_t)(at-s->command_base-16384);
    if(at>=s->command_base+6144 && span(2,at-s->command_base-6144,n))
        return rights==CW_R?c_locale+(size_t)(at-s->command_base-6144):NULL;
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
uint64_t cw_heap_allocate(CwMachine *m,uint64_t bytes) {
    uint64_t args[4]={0,bytes,0x3000,4},value;uint32_t error=m->services->last_error;
    value=virtual_alloc(m,args);m->services->last_error=error;return value;
}
int cw_heap_release(CwMachine *m,uint64_t at) {
    uint64_t args[3]={at,0,0x8000};int result;uint32_t error=m->services->last_error;
    result=(int)virtual_free(m,args);m->services->last_error=error;return result;
}
/* Bounded UTF-16 -> UTF-8 conversion; CP_UTF8 has no default-character channel. */
static uint64_t wide_to_multi(CwMachine *m,const uint64_t *a) {
    CwServices *s=m->services;unsigned char *input,*output;uint32_t units,i,needed=0,at=0,c,low,pass;
    int32_t count=(int32_t)a[3],capacity=(int32_t)a[5];
    if((uint32_t)a[0]!=65001 || (a[1]&~UINT64_C(0x80)) || a[6] || a[7] || !a[2] || !count || count< -1 || capacity<0)
        return fail(s,ERR_PARAMETER);
    if(count==-1) {
        for(units=0;units<32768;units++) {
            if(a[2]>UINT64_MAX-(uint64_t)units*2 || !(input=cw_memory(m,a[2]+(uint64_t)units*2,2,CW_R)))return fail(s,ERR_NOACCESS);
            if(!input[0] && !input[1]){units++;break;}
        }
        if(units==32768)return fail(s,ERR_PARAMETER);
    }else units=(uint32_t)count;
    if(units>32768 || !(input=cw_memory(m,a[2],(size_t)units*2,CW_R)))return fail(s,ERR_NOACCESS);
    output=NULL;
    for(pass=0;pass<2;pass++) {
        for(i=0;i<units;i++) {
            c=input[i*2]|(uint32_t)input[i*2+1]<<8;
            if(c>=0xd800 && c<=0xdbff && i+1<units && (low=input[(i+1)*2]|(uint32_t)input[(i+1)*2+1]<<8)>=0xdc00 && low<=0xdfff) {
                c=0x10000+((c-0xd800)<<10)+low-0xdc00;i++;
            }else if(c>=0xd800 && c<=0xdfff){if(a[1]&0x80)return fail(s,1113);c=0xfffd;}
            if(!pass)needed+=c<128?1:c<2048?2:c<65536?3:4;
            else {
                if(c<128)output[at++]=(unsigned char)c;
                else if(c<2048){output[at++]=(unsigned char)(0xc0|(c>>6));output[at++]=(unsigned char)(0x80|(c&63));}
                else if(c<65536){output[at++]=(unsigned char)(0xe0|(c>>12));output[at++]=(unsigned char)(0x80|((c>>6)&63));output[at++]=(unsigned char)(0x80|(c&63));}
                else {output[at++]=(unsigned char)(0xf0|(c>>18));output[at++]=(unsigned char)(0x80|((c>>12)&63));output[at++]=(unsigned char)(0x80|((c>>6)&63));output[at++]=(unsigned char)(0x80|(c&63));}
            }
        }
        if(!pass) {
            if(!capacity)return needed;
            if((uint32_t)capacity<needed)return fail(s,122);
            if(!a[4] || !(output=cw_memory(m,a[4],needed,CW_W)))return fail(s,ERR_NOACCESS);
            if(a[2]<=a[4]?a[4]-a[2]<(uint64_t)units*2:a[2]-a[4]<needed)return fail(s,ERR_PARAMETER);
        }
    }
    return needed;
}
/* Opaque handles identify the sandbox's built-in service contracts, not host DLLs. */
static int import_string(CwMachine *m,uint64_t at,char *out,unsigned int capacity,int lower) {
    unsigned int i;unsigned char *p;
    for(i=0;i<capacity;i++) {
        if(at>UINT64_MAX-i || !(p=cw_memory(m,at+i,1,CW_R)))return 0;
        if(*p>127)return 0;
        out[i]=(char)*p;if(lower && out[i]>='A' && out[i]<='Z')out[i]=(char)(out[i]+32);
        if(!out[i])return 1;
    }
    return 0;
}
static int service_module(CwMachine *m,uint64_t at,uint64_t *result) {
    char name[128];int module;
    if(!at){*result=m->plan.base;return CW_OK;}
    if(!import_string(m,at,name,sizeof(name),1))return CW_API;
    module=cw_api_module_id(name);
    if(!module){m->services->last_error=126;*result=0;}
    else *result=UINT64_C(0x20000)+(unsigned int)module;
    return CW_OK;
}
static int service_address(CwMachine *m,const uint64_t *a,uint64_t *result) {
    static const char *const modules[]={"kernel32.dll","ucrtbase.dll",
        "api-ms-win-crt-heap-l1-1-0.dll","api-ms-win-crt-private-l1-1-0.dll",
        "api-ms-win-crt-string-l1-1-0.dll","api-ms-win-crt-runtime-l1-1-0.dll",
        "api-ms-win-crt-stdio-l1-1-0.dll","api-ms-win-crt-environment-l1-1-0.dll","api-ms-win-crt-utility-l1-1-0.dll","api-ms-win-crt-locale-l1-1-0.dll"};
    CwServices *s=m->services;char name[128];int id;uint64_t module=a[0]-UINT64_C(0x20001);
    *result=0;
    if(module>=sizeof(modules)/sizeof(modules[0])){s->last_error=126;return CW_OK;}
    if(a[1]<=65535){s->last_error=127;return CW_OK;}
    if(!import_string(m,a[1],name,sizeof(name),0))return CW_API;
    id=cw_api_id(name);
    if(id<0 || !cw_api_module_matches((unsigned int)id,modules[module])){s->last_error=127;return CW_OK;}
    if(!((id<32?s->launch.api_mask:s->launch.api_mask_high[id/32-1])&(1U<<(id%32)))){s->last_error=5;return CW_OK;}
    s->dynamic_apis[id/32]|=1U<<(id%32);*result=cw_api_token((unsigned int)id);return CW_OK;
}
int cw_api_dispatch(CwMachine *m) {
    uint64_t token=m->ip;unsigned int id;uint64_t a[8],result=0,ret;unsigned char *stack;
    CwServices *s=m->services;
    if(token==CW_CRT_RETURN)return cw_crt_continue(m);
    if(token>=CW_MISSING_IMPORT_BASE && token-CW_MISSING_IMPORT_BASE<16U*CW_MAX_IMPORTS && !((token-CW_MISSING_IMPORT_BASE)%16)){
        unsigned int slot=(unsigned int)((token-CW_MISSING_IMPORT_BASE)/16);
        if(!s || s->bound_machine!=m || !(m->plan.profile_flags&CW_PROFILE_DEFER_IMPORTS) ||
           !(s->launch.profile_flags&CW_PROFILE_DEFER_IMPORTS) || slot>=m->plan.import_count ||
           m->plan.imports[slot].api!=UINT32_MAX)return CW_API;
        m->stop_import=slot+1;return CW_UNIMPLEMENTED;
    }
    if(token<CW_THUNK_BASE || token-CW_THUNK_BASE>=16U*CW_API_COUNT || (token-CW_THUNK_BASE)%16)return CW_MEMORY;
    id=(unsigned int)((token-CW_THUNK_BASE)/16);
    if(!s || s->bound_machine!=m || !(cw_plan_has_api(&m->plan,id) || (s->dynamic_apis[id/32]&(1U<<(id%32)))) ||
       !((id<32?s->launch.api_mask:s->launch.api_mask_high[id/32-1])&(1U<<(id%32))))return CW_API;
    if((m->r[4]&15)!=8 || m->r[4]<m->stack_base || m->r[4]-m->stack_base>CW_STACK-40 || !(stack=cw_memory(m,m->r[4],40,CW_R)))return CW_ABI;
    if(!cw_memory(m,m->r[4]+8,32,CW_W))return CW_ABI;
    a[0]=m->r[1];a[1]=m->r[2];a[2]=m->r[8];a[3]=m->r[9];a[4]=a[5]=a[6]=a[7]=0;
    if(id==CW_WRITE_FILE || id==CW_READ_FILE || id==CW_CREATE_FILE || id==CW_DUPLICATE_HANDLE || id==CW_WIDE_TO_MULTI) {
        unsigned int count=id==CW_WIDE_TO_MULTI?4U:(id==CW_CREATE_FILE || id==CW_DUPLICATE_HANDLE)?3U:1U,i;
        unsigned char *extra=cw_memory(m,m->r[4]+40,count*8,CW_R);if(!extra)return CW_ABI;
        for(i=0;i<count;i++)a[4+i]=get64(extra+i*8);
    }
    ret=get64(stack);s->calls[id]++;
    switch(id) {
    case CW_WIDE_TO_MULTI:result=wide_to_multi(m,a);break;
    case CW_MODULE_HANDLE_A:{int status=service_module(m,a[0],&result);if(status)return status;break;}
    case CW_PROC_ADDRESS:{int status=service_address(m,a,&result);if(status)return status;break;}
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
    case CW_SET_UNHANDLED_FILTER:
        if(a[0] && !cw_memory(m,a[0],1,CW_X))return CW_ABI;
        result=s->exception_filter;s->exception_filter=a[0];break;
    case CW_FILE_APIS_ANSI:result=s->file_apis_ansi;break;
    case CW_FILE_APIS_SET_ANSI:s->file_apis_ansi=1;break;
    case CW_FILE_APIS_SET_OEM:s->file_apis_ansi=0;break;
    case CW_TLS_ALLOC:{
        unsigned int i;
        for(i=0;i<CW_DYNAMIC_TLS_SLOTS;i++)if(!(s->tls_used[i/32]&(1U<<(i%32))))break;
        if(i==CW_DYNAMIC_TLS_SLOTS){s->last_error=ERR_MEMORY;result=UINT32_MAX;}
        else {s->tls_used[i/32]|=1U<<(i%32);s->tls_values[i]=0;result=i;}
        break;
    }
    case CW_TLS_FREE:case CW_TLS_GET:case CW_TLS_SET:{
        uint32_t index=(uint32_t)a[0];
        if(index>=CW_DYNAMIC_TLS_SLOTS || (id==CW_TLS_FREE && !(s->tls_used[index/32]&(1U<<(index%32)))))result=fail(s,ERR_PARAMETER);
        else if(id==CW_TLS_FREE){s->tls_used[index/32]&=~(1U<<(index%32));s->tls_values[index]=0;result=1;}
        else if(id==CW_TLS_SET){s->tls_values[index]=a[1];result=1;}
        else {result=s->tls_values[index];s->last_error=0;}
        break;
    }
    case CW_GET_COMMAND_LINE:result=s->command_base;break;
    case CW_GET_ENVIRONMENT_VARIABLE:result=environment(m,a);break;
    case CW_VIRTUAL_ALLOC:result=a[0] && cw_crt_owned(m,a[0])?fail(s,ERR_ADDRESS):virtual_alloc(m,a);break;
    case CW_VIRTUAL_FREE:result=cw_crt_owned(m,a[0])?fail(s,ERR_ADDRESS):virtual_free(m,a);break;
    case CW_CLOSE_HANDLE:
        if(cw_sync_handle_family(a[0])){int status=cw_sync_call(m,id,a,&result);if(status)return status;}
        else result=cw_file_call(m,id,a);
        break;
    case CW_CREATE_FILE:case CW_READ_FILE:
    case CW_SET_FILE_POINTER:case CW_GET_FILE_SIZE:case CW_FLUSH_FILE_BUFFERS:
        result=cw_file_call(m,id,a);break;
    default:
        if(cw_crt_export(id)){int status=cw_crt_call(m,id,a,&result);if(status==CW_CRT_PENDING)return CW_OK;if(status)return status;}
        else if(id>=CW_CREATE_EVENT && id<=CW_DUPLICATE_HANDLE){int status=cw_sync_call(m,id,a,&result);if(status)return status;}
        else return CW_API;
    }
    m->r[0]=result;m->r[4]+=8;
    if(ret>=CW_TLS_RETURN)return cw_bootstrap_return(m,ret,m->r[4]-8);
    else m->ip=ret;
    /* Nonvolatile integer/vector state remains intact; volatile state is unspecified. */
    return CW_OK;
}
