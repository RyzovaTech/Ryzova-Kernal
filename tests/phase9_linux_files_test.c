/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../ryzova/compat/linux/subset_vm.h"
#include <stdio.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"failed line %d\n",__LINE__); return 1; } } while (0)
static unsigned char memory[8192], output[65536], other[65536];
static int64_t sink(void *context, int fd, const unsigned char *bytes, size_t size)
{
    (void)context; (void)fd; (void)bytes;
    return (int64_t)size;
}
static int64_t call(RyzLinuxProcess *p, uint64_t nr, uint64_t a, uint64_t b, uint64_t c)
{
    RyzLinuxRegs r = {0};
    r.rax=nr; r.rdi=a; r.rsi=b; r.rdx=c;
    return ryz_linux_syscall(p,&r);
}
int main(void)
{
    RyzLinuxProcess p, q;
    RyzLinuxFiles f, g;
    RyzVmResult result;
    int i;
    int64_t fd;
    memset(&f,0,sizeof(f));
    f.input=(const unsigned char *)"abc"; f.input_size=3;
    f.output=output; f.output_capacity=sizeof(output);
    g=f; g.output=other;
    CHECK(ryz_linux_process_init(&p,1,1,1,1,0x400000,memory,sizeof(memory),NULL,NULL)==0);
    CHECK(ryz_linux_process_init(&q,2,2,2,2,0x400000,memory,sizeof(memory),NULL,NULL)==0);
    p.files=&f; q.files=&g;
    memcpy(memory,"input",6);
    CHECK(call(&p,257,(uint64_t)-100,0x400000,1)==-13);
    fd=call(&p,257,(uint64_t)-100,0x400000,0);
    CHECK(fd==3);
    CHECK(call(&p,72,fd,1,0)==0);
    CHECK(call(&p,72,fd,2,1)==0 && call(&p,72,fd,1,0)==1);
    CHECK(call(&p,72,fd,2,2)==-22 && call(&p,72,fd,1,0)==1);
    CHECK(call(&q,72,fd,1,0)==-9);
    CHECK(call(&p,72,fd,3,0)==0);
    CHECK(call(&p,16,fd,0,0)==-25 && call(&p,16,16,0,0)==-9);
    CHECK(call(&p,20,1,UINT64_MAX,0)==0);
    CHECK(call(&p,20,1,0x400100,17)==-22);
    CHECK(call(&p,20,1,UINT64_MAX,1)==-14);
    memset(memory+512,0,32);
    memset(memory+512,255,8);
    memory[520]=1;
    CHECK(call(&p,20,1,0x400200,1)==-14);
    CHECK(p.output_bytes==0);

    CHECK(call(&p,0,fd,0x400100,2)==2 && memcmp(memory+256,"ab",2)==0);
    CHECK(call(&p,0,fd,0x400100,2)==1 && memory[256]=='c');
    CHECK(call(&p,0,fd,0x400100,2)==0);
    CHECK(call(&q,257,(uint64_t)-100,0x400000,0)==3);
    CHECK(call(&q,0,3,0x400100,3)==3 && memcmp(memory+256,"abc",3)==0);
    CHECK(call(&p,3,fd,0,0)==0);
    CHECK(call(&p,257,(uint64_t)-100,0x400000,0)==3);
    CHECK(call(&p,0,3,0x400100,1)==1 && memory[256]=='a');
    for(i=4;i<16;i++) CHECK(call(&p,257,(uint64_t)-100,0x400000,0)==i);
    CHECK(call(&p,257,(uint64_t)-100,0x400000,0)==-24);
    for(i=3;i<16;i++) CHECK(call(&p,3,i,0,0)==0);
    memcpy(memory,"output",7);
    CHECK(call(&p,257,(uint64_t)-100,0x400000,0)==-13);
    CHECK(call(&p,257,(uint64_t)-100,0x400000,513)==3);
    memset(memory+4096,42,4096);
    for(i=0;i<16;i++) CHECK(call(&p,1,3,0x401000,4096)==4096);
    CHECK(f.output_size==65536 && output[65535]==42);
    CHECK(call(&p,1,3,0x401000,1)==-28 && f.output_size==65536);
    CHECK(g.output_size==0 && other[0]==0);
    CHECK(call(&p,3,3,0,0)==0);
    CHECK(call(&p,257,(uint64_t)-100,0x400000,513)==3);
    CHECK(f.output_size==0 && output[65535]==0);
    CHECK(call(&p,0,3,0x401000,1)==-9);
    CHECK(call(&p,1,3,UINT64_MAX,1)==-14);
    CHECK(call(&p,1,3,0x401000,65537)==-22);
    p.write_output=sink;
    for(i=0;i<16;i++) CHECK(call(&p,1,1,0x401000,4096)==4096);
    CHECK(p.output_bytes==65536 && q.output_bytes==0);
    CHECK(call(&p,1,2,0x401000,1)==-28 && p.output_bytes==65536);
    f.output_size=10; memset(output,99,sizeof(output));
    CHECK(ryz_vm_run_file_elf((const unsigned char *)"bad",3,memory,sizeof(memory),&f,NULL,NULL,&result)==RYZ_VM_BAD_INPUT);
    CHECK(f.output_size==0 && output[0]==0 && output[65535]==0);
    f.input_size=65537;
    CHECK(ryz_vm_run_file_elf(NULL,0,memory,sizeof(memory),&f,NULL,NULL,&result)==RYZ_VM_BAD_INPUT);
    puts("FLEX_FILES_RESOURCE_TESTS_PASS");
    return 0;
}
