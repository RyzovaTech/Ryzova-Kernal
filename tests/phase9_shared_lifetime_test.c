/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../ryzova/compat/linux/jobs.h"
#include <stdlib.h>
#include <stdio.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"lifetime line %d\n",__LINE__);return 1;}}while(0)
int main(void)
{
 RyzLinuxWorld *w=calloc(1,sizeof(*w));RyzLinuxMemory *m=calloc(1,sizeof(*m));RyzLinuxProcess *p=calloc(1,sizeof(*p));
 RyzLinuxRegs r;RyzFutexKey key,reused,private_key;unsigned char *arena=calloc(1,RYZ_PROCESS_MAX_SPAN);long at,other;unsigned int i;
 CHECK(w && m && p && arena);m->bytes=arena;m->base=0x400000;m->size=RYZ_PROCESS_MAX_SPAN;m->heap=m->brk=m->base+4096;m->stack=m->base+m->size-65536;m->dynamic=1;m->world=w;m->process=p;p->address_limit=RYZ_PROCESS_MAX_SPAN;
 memset(&r,0,sizeof r);r.rax=9;r.rsi=4096;r.rdx=3;r.r10=33;r.r8=UINT64_MAX;
 at=ryz_memory_call(m,&r);CHECK(at>0 && w->shared_live==1);
 CHECK(!ryz_memory_futex_key(m,(uint64_t)at,0,&key) && key.kind==1 && key.identity);
 CHECK(!ryz_memory_futex_key(m,(uint64_t)at,1,&private_key) && !private_key.kind);
 ryz_memory_key_ref(w,&key,1);r.rax=11;r.rdi=(uint64_t)at;CHECK(!ryz_memory_call(m,&r) && w->shared_live==1 && w->shared_pages[key.index].refs==1);
 r.rax=9;r.rdi=0;r.rsi=63*4096;other=ryz_memory_call(m,&r);CHECK(other>0 && w->shared_live==64);
 r.rsi=4096;CHECK(ryz_memory_call(m,&r)==-12);ryz_memory_key_ref(w,&key,-1);CHECK(w->shared_live==63);
 at=ryz_memory_call(m,&r);CHECK(at>0 && !ryz_memory_futex_key(m,(uint64_t)at,0,&reused));CHECK(reused.index==key.index && reused.identity!=key.identity);
 ryz_memory_drop(m);CHECK(w->shared_live==0);for(i=0;i<64;i++)CHECK(!w->shared_pages[i].refs);
 free(arena);free(p);free(m);free(w);puts("FLEX_SHARED_LIFETIME_PASS");return 0;
}
