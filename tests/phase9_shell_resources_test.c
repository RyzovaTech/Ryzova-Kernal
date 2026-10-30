/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../ryzova/compat/linux/syscall.h"
#include <stdio.h>
#define CHECK(x) do { if(!(x)){fprintf(stderr,"shell resource assertion line %d\n",__LINE__);return 1;} } while(0)
static unsigned char memory[8192], output[65536];
static int64_t call(RyzLinuxProcess *p,uint64_t nr,uint64_t a,uint64_t b,uint64_t c,uint64_t d)
{
    RyzLinuxRegs r={0};r.rax=nr;r.rdi=a;r.rsi=b;r.rdx=c;r.r10=d;return ryz_linux_syscall(p,&r);
}
static uint64_t word(unsigned char *b,unsigned int n)
{
    uint64_t v=0;unsigned int i;for(i=0;i<n;i++)v|=(uint64_t)b[i]<<(8*i);return v;
}
static int64_t memory_call(void *p,const RyzLinuxRegs *r){(void)p;(void)r;return -38;}
static int readonly(void *p,uint64_t at,uint64_t n){(void)p;return at>=0x400000 && at+n<=0x401000;}
int main(void)
{
    RyzLinuxProcess p,q;
    RyzLinuxFiles files;
    int64_t fd,alias;
    memset(&files,0,sizeof files);files.input=(const unsigned char *)"abc";files.input_size=3;
    files.output=output;files.output_capacity=sizeof output;
    CHECK(ryz_linux_process_init(&p,1,1000,1000,1000,0x400000,memory,sizeof memory,NULL,NULL)==0);
    CHECK(ryz_linux_process_init(&q,2,2000,2000,2000,0x400000,memory,sizeof memory,NULL,NULL)==0);
    p.files=&files;p.memory_call=memory_call;
    memcpy(memory,"input",6);
    fd=call(&p,2,0x400000,0,0,0);CHECK(fd==3);
    alias=call(&p,32,fd,0,0,0);CHECK(alias==4);
    CHECK(call(&p,0,fd,0x400200,1,0)==1 && memory[512]=='a');
    CHECK(call(&p,0,alias,0x400200,2,0)==2 && memcmp(memory+512,"bc",2)==0);
    CHECK(call(&p,3,fd,0,0,0)==0);
    CHECK(call(&p,2,0x400000,0,0,0)==3);
    CHECK(call(&p,0,alias,0x400200,1,0)==0);
    CHECK(call(&p,0,3,0x400200,1,0)==1 && memory[512]=='a');
    CHECK(call(&p,8,alias,(uint64_t)-2,2,0)==1);
    CHECK(call(&p,0,alias,0x400200,2,0)==2 && memcmp(memory+512,"bc",2)==0);
    CHECK(call(&p,72,alias,2,1,0)==0 && call(&p,72,3,1,0,0)==0);
    CHECK(call(&p,292,alias,15,02000000,0)==15 && call(&p,72,15,1,0,0)==1);
    CHECK(call(&p,292,alias,alias,0,0)==-22 && call(&p,33,alias,16,0,0)==-9);
    memset(memory+1024,0xcc,144);
    CHECK(call(&p,5,alias,0x400400,0,0)==0);
    CHECK(word(memory+1024+24,4)==(0100000|0444));
    CHECK(word(memory+1024+28,4)==1000 && word(memory+1024+48,8)==3);
    CHECK(memory[1024+143]==0);
    p.memory_write=readonly;
    memset(memory+4096,0xcc,144);
    CHECK(call(&p,5,alias,0x401000,0,0)==-14 && memory[4096]==0xcc);
    p.memory_write=NULL;
    CHECK(call(&p,105,0,0,0,0)==-1 && p.ns.uid==1000);
    CHECK(call(&p,106,1000,0,0,0)==0 && p.ns.gid==1000);
    CHECK(call(&p,117,1000,(uint64_t)-1,0,0)==-1 && p.ns.uid==1000);
    memset(memory+1024,0xff,8);
    CHECK(call(&p,14,2,0x400400,0x400408,8)==0 && word(memory+1032,8)==0);
    CHECK((p.signal_mask & ((UINT64_C(1)<<8)|(UINT64_C(1)<<18)))==0 && q.signal_mask==0);
    CHECK(call(&p,14,0,0,0x400408,7)==-22);
    CHECK(call(&p,14,0,0,0x400408,8)==0 && word(memory+1032,8)==p.signal_mask);
    memset(memory+1024,0,32);memory[1024]=1;
    CHECK(call(&p,13,2,0x400400,0x400420,8)==0 && memory[1056]==0);
    CHECK(call(&p,13,2,0,0x400420,8)==0 && memory[1056]==1);
    CHECK(q.signal_actions[1][0]==0 && call(&p,13,9,0x400400,0,8)==-22);
    memcpy(memory,"output",7);
    CHECK(call(&p,2,0x400000,577,0,0)==5);
    CHECK(call(&p,33,5,1,0,0)==1);
    memcpy(memory+512,"xy",2);
    CHECK(call(&p,1,1,0x400200,2,0)==2 && memcmp(output,"xy",2)==0);
    CHECK(call(&p,8,5,0,0,0)==0);
    CHECK(call(&p,72,1,4,02000,0)==0 && call(&p,72,5,3,0,0)==02001);
    CHECK(call(&p,1,5,0x400200,2,0)==2 && memcmp(output,"xyxy",4)==0);
    memset(memory+1024,0,16);memory[1024]=3;memory[1028]=1;
    memory[1032]=0xff;memory[1033]=0xff;memory[1034]=0xff;memory[1035]=0xff;
    CHECK(call(&p,7,0x400400,2,(uint64_t)-1,0)==1 && memory[1030]==1 && memory[1038]==0);
    CHECK(call(&p,7,0x401fff,1,0,0)==-14);
    CHECK(call(&p,7,0,0,(uint64_t)-1,0)==-38);
    CHECK(call(&p,40,1,3,0,0)==-38);
    puts("FLEX_SHELL_RESOURCES_PASS");return 0;
}
