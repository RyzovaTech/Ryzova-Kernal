/* SPDX-License-Identifier: AGPL-3.0-only */
/* Selected CRT contracts, implemented inside the guest boundary, never forwarded. */
#include "api.h"
#include "files.h"
#ifndef CW_PLAN9
#include <string.h>
#endif
#define CRT_LIMIT 65536U
int cw_crt_export(unsigned int id) { return (id>=CW_MEMCPY && id<=CW_ERRNO) || (id>=CW_CRT_INVALID_HANDLER && id<=CW_CRT_QUICK_EXIT) || id==CW_CRT_RAND_S || id==CW_CRT_SETLOCALE; }
const char *cw_crt_alias(unsigned int id) {
    if(id==CW_CRT_SETLOCALE)return "api-ms-win-crt-locale-l1-1-0.dll";
    if(id==CW_CRT_RAND_S)return "api-ms-win-crt-utility-l1-1-0.dll";
    if(id==CW_CRT_NEW_MODE)return "api-ms-win-crt-heap-l1-1-0.dll";
    if(id>=CW_MALLOC && id<=CW_FREE)return "api-ms-win-crt-heap-l1-1-0.dll";
    if(id==CW_MEMCPY || id==CW_MEMMOVE || id==CW_MEMCMP)return "api-ms-win-crt-private-l1-1-0.dll";
    if(id==CW_MEMSET || (id>=CW_STRLEN && id<=CW_WCSLEN))return "api-ms-win-crt-string-l1-1-0.dll";
    if(id==CW_CRT_WENV)return "api-ms-win-crt-environment-l1-1-0.dll";
    if(id==CW_CRT_FMODE || id==CW_CRT_COMMODE)return "api-ms-win-crt-stdio-l1-1-0.dll";
    if(id==CW_ERRNO || (id>=CW_CRT_INVALID_HANDLER && id<=CW_CRT_APP_TYPE) || id==CW_CRT_INITTERM || (id>=CW_CRT_INITTERM_E && id<=CW_CRT_WARGV) || (id>=CW_CRT_ATEXIT && id<=CW_CRT_QUICK_EXIT))return "api-ms-win-crt-runtime-l1-1-0.dll";
    return NULL;
}
static void error_number(CwServices *s,uint32_t value) { unsigned int i;for(i=0;i<4;i++)s->errno_bytes[i]=(unsigned char)(value>>(8*i)); }
int cw_crt_owned(CwMachine *m,uint64_t at) {
    unsigned int i;CwServices *s=m->services;
    for(i=0;i<16;i++)if(s->crt_blocks[i].base && at>=s->crt_blocks[i].base && at-s->crt_blocks[i].base<s->crt_blocks[i].capacity)return 1;
    return 0;
}
static CwCrtBlock *block(CwServices *s,uint64_t at) {
    unsigned int i;for(i=0;i<16;i++)if(s->crt_blocks[i].base==at && at)return &s->crt_blocks[i];return NULL;
}
static uint64_t allocate(CwMachine *m,uint64_t size) {
    CwServices *s=m->services;unsigned int i;uint64_t at,bytes=size?size:1;
    if(bytes>CW_HEAP_LIMIT){error_number(s,12);return 0;}
    for(i=0;i<16;i++)if(!s->crt_blocks[i].base)break;
    if(i==16 || !(at=cw_heap_allocate(m,bytes))){error_number(s,12);return 0;}
    s->crt_blocks[i].base=at;s->crt_blocks[i].size=size;s->crt_blocks[i].capacity=(bytes+4095)&~UINT64_C(4095);return at;
}
static int release(CwMachine *m,uint64_t at) {
    CwCrtBlock *b;if(!at)return CW_OK;
    b=block(m->services,at);if(!b || !cw_heap_release(m,at))return CW_CRT;
    memset(b,0,sizeof(*b));return CW_OK;
}
static int unit(CwMachine *m,uint64_t at,unsigned int width,uint64_t index,uint32_t *out) {
    unsigned char *p;if(index>(UINT64_MAX-at)/width)return CW_CRT;
    p=cw_memory(m,at+index*width,width,CW_R);if(!p)return CW_CRT;
    *out=p[0]|(width==2?(uint32_t)p[1]<<8:0);return CW_OK;
}
/* Initializer callbacks execute through the same CPU and budget as the image.
   Only trusted frames hold the continuation; no guest address is a host function. */
static uint64_t word64(const unsigned char *p) {
    uint64_t v=0;unsigned int i;for(i=0;i<8;i++)v|=(uint64_t)p[i]<<(8*i);return v;
}
static int init_next(CwMachine *m,int returned) {
    CwServices *s=m->services;CwCrtInit *f=&s->crt_initializers[s->crt_init_depth-1];
    unsigned char *p;uint64_t target,value=returned && f->checked==1?(uint32_t)m->r[0]:0;
    if(!value)for(;;) {
        if(f->checked>=2) {
            if(!s->crt_exit_count)break;
            target=s->crt_exit_callbacks[--s->crt_exit_count];
        }else {
            if(f->cursor==f->end)break;
            p=cw_memory(m,f->cursor,8,CW_R);if(!p)return CW_CRT;
            target=word64(p);f->cursor+=8;if(!target)continue;
        }
        if(!cw_memory(m,target,1,CW_X) || f->stack<m->stack_base+48)return CW_CRT;
        p=cw_memory(m,f->stack-48,40,CW_W);if(!p)return CW_CRT;
        memset(p,0,40);{unsigned int i;for(i=0;i<8;i++)p[i]=(unsigned char)(CW_CRT_RETURN>>(i*8));}
        m->r[4]=f->stack-48;m->ip=target;return CW_CRT_PENDING;
    }
    if(f->checked==3) {
        cw_files_close_all(m);m->exit_code=f->code;m->exited=1;m->exit_kind=1;
        s->crt_init_depth--;return CW_CRT_PENDING;
    }
    m->r[0]=value;m->r[4]=f->stack+8;m->ip=f->ret;s->crt_init_depth--;
    if(m->ip>=CW_TLS_RETURN){int status=cw_bootstrap_return(m,m->ip,m->r[4]-8);if(status)return status;}
    return CW_CRT_PENDING;
}
int cw_crt_continue(CwMachine *m) {
    CwServices *s=m->services;int status;
    if(!s || s->bound_machine!=m || !s->crt_init_depth || s->crt_init_depth>CW_CRT_INIT_DEPTH ||
       m->r[4]!=s->crt_initializers[s->crt_init_depth-1].stack-40)return CW_API;
    status=init_next(m,1);return status==CW_CRT_PENDING?CW_OK:status;
}
static int initializers(CwMachine *m,const uint64_t *a,int checked) {
    CwServices *s=m->services;CwCrtInit *f;unsigned char *p;
    if((a[0]&7) || (a[1]&7) || a[1]<a[0] || a[1]-a[0]>2048 ||
       (a[1]!=a[0] && !cw_memory(m,a[0],(size_t)(a[1]-a[0]),CW_R)) || s->crt_init_depth>=CW_CRT_INIT_DEPTH)return CW_CRT;
    p=cw_memory(m,m->r[4],8,CW_R);if(!p)return CW_CRT;
    f=&s->crt_initializers[s->crt_init_depth++];f->cursor=a[0];f->end=a[1];
    f->stack=m->r[4];f->ret=word64(p);f->checked=(uint32_t)checked;f->code=0;
    return init_next(m,0);
}
static int terminate(CwMachine *m,uint32_t code,int callbacks,int returning) {
    CwServices *s=m->services;CwCrtInit *f;unsigned char *p;
    if(!callbacks){cw_files_close_all(m);m->exit_code=code;m->exited=1;m->exit_kind=1;return CW_CRT_PENDING;}
    if(s->crt_init_depth>=CW_CRT_INIT_DEPTH)return CW_CRT;
    p=cw_memory(m,m->r[4],8,CW_R);if(!p)return CW_CRT;
    f=&s->crt_initializers[s->crt_init_depth++];memset(f,0,sizeof(*f));
    f->stack=m->r[4];f->ret=word64(p);f->checked=returning?2:3;f->code=code;
    return init_next(m,0);
}
static void store(unsigned char *p,uint64_t v,unsigned int n) {
    unsigned int i;for(i=0;i<n;i++)p[i]=(unsigned char)(v>>(8*i));
}
static int wide_environment(CwServices *s) {
    unsigned int i,j,at=136;uint64_t base=s->command_base+16384;
    if(s->crt_environment_ready)return CW_OK;
    memset(s->crt_environment,0,sizeof(s->crt_environment));
    for(i=0;i<s->launch.environment_count;i++) {
        store(s->crt_environment+i*8,base+at,8);
        for(j=0;s->launch.environment[i].name[j];j++,at+=2)store(s->crt_environment+at,s->launch.environment[i].name[j],2);
        store(s->crt_environment+at,'=',2);at+=2;
        for(j=0;s->launch.environment[i].value[j];j++,at+=2)store(s->crt_environment+at,s->launch.environment[i].value[j],2);
        at+=2;
    }
    store(s->crt_globals+24,base,8);s->crt_environment_ready=1;return CW_OK;
}
static int wide_arguments(CwServices *s,unsigned int mode) {
    const uint16_t *c=s->launch.command_line;unsigned int i=0,argc=0,at=1032,quoted,n,k;uint16_t ch;
    unsigned char out[4096];uint64_t base=s->command_base+8192;
    if(mode>1)return CW_CRT; /* Wildcard expansion needs a separate filesystem contract. */
    if(s->crt_argv_ready)return s->crt_argv_ready==mode+1?CW_OK:CW_CRT;
    memset(out,0,sizeof(out));
    while(mode && c[i]) {
        while(c[i]==' ' || c[i]=='\t')i++;
        if(!c[i])break;
        if(argc==128)return CW_CRT;
        store(out+argc*8,base+at,8);quoted=0;
        while(c[i]) {
            ch=c[i];
            if(!quoted && (ch==' ' || ch=='\t'))break;
            if(!argc) { /* argv[0] quotes group spaces; backslashes are literal. */
                i++;if(ch=='"'){quoted=!quoted;continue;}
            }else {
                n=0;while(c[i]=='\\'){n++;i++;}
                if(c[i]=='"') {
                    for(k=0;k<n/2;k++){if(at+2>=sizeof(out))return CW_CRT;store(out+at,'\\',2);at+=2;}
                    if(n&1){ch='"';i++;}
                    else {i++;if(quoted && c[i]=='"'){ch='"';i++;}else {quoted=!quoted;continue;}}
                }else {
                    for(k=0;k<n;k++){if(at+2>=sizeof(out))return CW_CRT;store(out+at,'\\',2);at+=2;}
                    ch=c[i];if(!ch || (!quoted && (ch==' ' || ch=='\t')))break;i++;
                }
            }
            if(at+2>=sizeof(out))return CW_CRT;
            store(out+at,ch,2);at+=2;
        }
        at+=2;argc++;
    }
    memcpy(s->crt_argv,out,sizeof(out));store(s->crt_globals+8,argc,4);
    store(s->crt_globals+16,base,8);s->crt_argv_ready=mode+1;return CW_OK;
}
int cw_crt_call(CwMachine *m,unsigned int id,const uint64_t *a,uint64_t *result) {
    CwServices *s=m->services;unsigned char *dst,*src;uint64_t n=a[2],i;uint32_t x,y;unsigned int width;
    *result=0;
    switch(id) {
    case CW_CRT_SETLOCALE:
        if((uint32_t)a[0]>5)return CW_OK;
        if(a[1]) {
            unsigned char *p=cw_memory(m,a[1],1,CW_R);if(!p)return CW_CRT;
            if(*p) {
                char name[7];unsigned int k;
                for(k=0;k<sizeof(name);k++){p=cw_memory(m,a[1]+k,1,CW_R);if(!p)return CW_CRT;name[k]=(char)*p;if(!*p)break;}
                if(k==sizeof(name) || (strcmp(name,"C") && strcmp(name,"POSIX")))return CW_OK;
            }
        }
        *result=s->command_base+6144;return CW_OK;
    case CW_CRT_RAND_S:
        dst=cw_memory(m,a[0],4,CW_W);if(!dst)return CW_CRT;
        if(!s->random_read)return CW_API;
        {unsigned char random[4];
            if(!s->random_read(s->random_context,random,4)){memset(dst,0,4);error_number(s,22);*result=22;return CW_OK;}
            memcpy(dst,random,4);return CW_OK;
        }
    case CW_CRT_ATEXIT:
        if(!a[0] || !cw_memory(m,a[0],1,CW_X))return CW_CRT;
        if(s->crt_exit_count==32){*result=UINT32_MAX;return CW_OK;}
        s->crt_exit_callbacks[s->crt_exit_count++]=a[0];return CW_OK;
    case CW_CRT_CEXIT:return terminate(m,0,1,1);
    case CW_CRT_EXIT:return terminate(m,(uint32_t)a[0],1,0);
    case CW_CRT_QUICK_EXIT:return terminate(m,(uint32_t)a[0],0,0);
    case CW_CRT_NEW_MODE:
        if(a[0]>1){error_number(s,22);*result=UINT32_MAX;return CW_OK;}
        *result=s->crt_new_mode;s->crt_new_mode=(uint32_t)a[0];return CW_OK;
    case CW_CRT_WENV:*result=s->command_base+4136;return CW_OK;
    case CW_CRT_WENV_INIT:return wide_environment(s);
    case CW_CRT_WARGV_CONFIG:return wide_arguments(s,(uint32_t)a[0]);
    case CW_CRT_ARGC:*result=s->command_base+4120;return CW_OK;
    case CW_CRT_WARGV:*result=s->command_base+4128;return CW_OK;
    case CW_CRT_INITTERM:case CW_CRT_INITTERM_E:return initializers(m,a,id==CW_CRT_INITTERM_E);
    case CW_CRT_FMODE:*result=s->command_base+4112;return CW_OK;
    case CW_CRT_COMMODE:*result=s->command_base+4116;return CW_OK;
    case CW_CRT_APP_TYPE:
        if(a[0]>2)return CW_CRT;
        s->crt_app_type=(uint32_t)a[0];return CW_OK;
    case CW_CRT_INVALID_HANDLER:
        if(a[0] && !cw_memory(m,a[0],1,CW_X))return CW_CRT;
        *result=s->invalid_parameter_handler;s->invalid_parameter_handler=a[0];return CW_OK;
    case CW_MEMCPY:case CW_MEMMOVE:case CW_MEMSET:case CW_MEMCMP:
        if(n>CRT_LIMIT)return CW_CRT;
        if(!n){*result=id==CW_MEMCMP?0:a[0];return CW_OK;}
        dst=cw_memory(m,a[0],(size_t)n,id==CW_MEMCMP?CW_R:CW_W);if(!dst)return CW_CRT;
        if(id==CW_MEMSET){memset(dst,(int)(a[1]&255),(size_t)n);*result=a[0];return CW_OK;}
        src=cw_memory(m,a[1],(size_t)n,CW_R);if(!src)return CW_CRT;
        if(id==CW_MEMCPY) {
            if(a[0]<a[1]?a[1]-a[0]<n:a[0]-a[1]<n)return CW_CRT;
            memcpy(dst,src,(size_t)n);
        }else if(id==CW_MEMMOVE)memmove(dst,src,(size_t)n);
        else {for(i=0;i<n;i++)if(dst[i]!=src[i]){*result=(uint32_t)((int)dst[i]-(int)src[i]);break;}return CW_OK;}
        *result=a[0];return CW_OK;
    case CW_STRLEN:case CW_WCSLEN:
        width=id==CW_WCSLEN?2:1;
        for(i=0;i<CRT_LIMIT/width;i++){if(unit(m,a[0],width,i,&x))return CW_CRT;if(!x){*result=i;return CW_OK;}}return CW_CRT;
    case CW_STRCMP:case CW_STRNCMP:
        n=id==CW_STRNCMP?a[2]:CRT_LIMIT;if(n>CRT_LIMIT)return CW_CRT;
        for(i=0;i<n;i++) {
            if(unit(m,a[0],1,i,&x) || unit(m,a[1],1,i,&y))return CW_CRT;
            if(x!=y){*result=(uint32_t)((int)x-(int)y);return CW_OK;}
            if(!x)return CW_OK;
        }
        return id==CW_STRNCMP?CW_OK:CW_CRT;
    case CW_MALLOC:*result=allocate(m,a[0]);return CW_OK;
    case CW_CALLOC:
        if(a[0] && a[1]>UINT64_MAX/a[0]){error_number(s,12);return CW_OK;}
        *result=allocate(m,a[0]*a[1]);return CW_OK; /* new committed pages are zero */
    case CW_FREE:return release(m,a[0]);
    case CW_REALLOC: {
        CwCrtBlock *old;uint64_t at,bytes;
        if(!a[0]){*result=allocate(m,a[1]);return CW_OK;}
        old=block(s,a[0]);if(!old)return CW_CRT;
        if(!a[1])return release(m,a[0]);
        if(a[1]<=old->capacity){old->size=a[1];*result=a[0];return CW_OK;}
        at=allocate(m,a[1]);if(!at)return CW_OK;
        bytes=old->size<a[1]?old->size:a[1];dst=cw_memory(m,at,(size_t)bytes,CW_W);src=cw_memory(m,a[0],(size_t)bytes,CW_R);
        if(bytes && (!dst || !src))return CW_CRT;
        if(bytes)memcpy(dst,src,(size_t)bytes);
        if(release(m,a[0]))return CW_CRT;
        *result=at;return CW_OK;
    }
    case CW_ERRNO:*result=s->command_base+4096;return CW_OK;
    default:return CW_API;
    }
}
