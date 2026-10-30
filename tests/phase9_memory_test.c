/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../ryzova/compat/linux/process.h"
#include <stdio.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"failed line %d\n",__LINE__);return 1;}}while(0)
static unsigned char bytes[RYZ_VM_MAX_SPAN];
static int64_t call(RyzLinuxMemory *m,uint64_t nr,uint64_t a,uint64_t b,uint64_t c)
{
    RyzLinuxRegs r={0};
    r.rax=nr;r.rdi=a;r.rsi=b;r.rdx=c;r.r10=34;r.r8=UINT64_MAX;
    return ryz_memory_call(m,&r);
}
int main(void)
{
    RyzLinuxMemory m;
    uint64_t p,q,base=0x400000,brk;
    memset(&m,0,sizeof(m));m.bytes=bytes;m.base=base;m.size=sizeof(bytes);
    m.heap=m.brk=base+4096;m.stack=base+sizeof(bytes)-RYZ_PROCESS_STACK;
    m.pages[0]=RYZ_MAP|RYZ_READ|RYZ_EXEC;
    brk=m.brk;
    CHECK(call(&m,12,0,0,0)==(int64_t)brk);
    CHECK(call(&m,12,UINT64_MAX,0,0)==(int64_t)brk);
    CHECK(call(&m,12,brk+4096,0,0)==(int64_t)brk+4096);
    CHECK(ryz_memory_access(&m,brk,4096,RYZ_WRITE));
    CHECK(!ryz_memory_access(&m,base,1,RYZ_WRITE));
    CHECK(!ryz_memory_access(&m,base-1,1,RYZ_READ));
    CHECK(!ryz_memory_access(&m,UINT64_MAX-1,8,RYZ_READ));
    CHECK(!ryz_memory_access(&m,m.stack-4096,4096,RYZ_READ));
    p=(uint64_t)call(&m,9,0,8192,3);
    CHECK(p>brk && ryz_memory_access(&m,p,8192,RYZ_READ|RYZ_WRITE));
    bytes[p-base]=99;
    CHECK(call(&m,10,p,4096,1)==0);
    CHECK(ryz_memory_access(&m,p,1,RYZ_READ));
    CHECK(!ryz_memory_access(&m,p,1,RYZ_WRITE));
    CHECK(!ryz_memory_access(&m,p+4095,2,RYZ_WRITE));
    CHECK(call(&m,10,p,4096,7)==-1);
    CHECK(!ryz_memory_access(&m,p,1,RYZ_EXEC));
    CHECK(call(&m,11,p+4096,4096,0)==0);
    CHECK(call(&m,10,p,8192,3)==-12);
    CHECK(!ryz_memory_access(&m,p,1,RYZ_WRITE)); /* failed mprotect is atomic */
    CHECK(call(&m,10,p,4096,0)==0);
    CHECK(!ryz_memory_access(&m,p,1,RYZ_READ));
    CHECK(call(&m,10,p,4096,3)==0 && bytes[p-base]==99);
    CHECK(call(&m,11,p,4096,0)==0);
    CHECK(!ryz_memory_access(&m,p,1,RYZ_READ));
    q=(uint64_t)call(&m,9,0,8192,3);
    CHECK(q==p && bytes[p-base]==0);
    CHECK(call(&m,9,0,UINT64_MAX,3)==-22);
    CHECK(call(&m,9,0,4096,4)==-1);
    CHECK(call(&m,11,p+1,4096,0)==-22);
    CHECK(call(&m,10,UINT64_MAX,4096,3)==-22);
    CHECK(call(&m,12,brk,0,0)==(int64_t)brk);
    CHECK(!ryz_memory_access(&m,brk,1,RYZ_READ));
    puts("FLEX_MEMORY_MODEL_TESTS_PASS");
    return 0;
}
