/* SPDX-License-Identifier: AGPL-3.0-only */
/* Selected CRT contracts, implemented inside the guest boundary, never forwarded. */
#include "api.h"
#include <string.h>
#define CRT_LIMIT 65536U
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
int cw_crt_call(CwMachine *m,unsigned int id,const uint64_t *a,uint64_t *result) {
    CwServices *s=m->services;unsigned char *dst,*src;uint64_t n=a[2],i;uint32_t x,y;unsigned int width;
    *result=0;
    switch(id) {
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
