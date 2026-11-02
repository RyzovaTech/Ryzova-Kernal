/* SPDX-License-Identifier: AGPL-3.0-only */
/* An ordinary host C harness: real shared user-space Ryzova world,
 * independently identified Linux guest namespace/UID processes. */
#include "syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define BASE UINT64_C(0x400000)
#define CHECK(c) do{if(!(c)){fprintf(stderr,"PTY_ISOLATION_FAIL line=%d\n",__LINE__);return 1;}}while(0)

static void populate(RyzLinuxProcess *p,RyzLinuxWorld *world,
                     unsigned char *memory,unsigned int namespace_id,
                     unsigned int pid,unsigned int uid)
{
    if(ryz_linux_process_init(p,namespace_id,pid,uid,uid,BASE,memory,4096,NULL,NULL)!=0)abort();
    ryz_world_attach(p,world);
}
static int64_t invoke(RyzLinuxProcess *p,uint64_t nr,uint64_t a,uint64_t b,uint64_t c)
{
    RyzLinuxRegs r={0};r.rax=nr;r.rdi=a;r.rsi=b;r.rdx=c;
    return ryz_linux_syscall(p,&r);
}
static int64_t open_path(RyzLinuxProcess *p,unsigned char *memory,const char *path)
{
    strcpy((char *)memory,path);
    return invoke(p,257,(uint64_t)-100,BASE,2);
}
int main(void)
{
    RyzLinuxWorld *world=calloc(1,sizeof *world);
    RyzLinuxProcess *a=calloc(1,sizeof *a),*foreign=calloc(1,sizeof *foreign),*uid=calloc(1,sizeof *uid);
    unsigned char *ma=calloc(1,4096),*mf=calloc(1,4096),*mu=calloc(1,4096);
    int64_t master,slave;
    if(!world||!a||!foreign||!uid||!ma||!mf||!mu)return 2;
    populate(a,world,ma,10,100,1000);
    populate(foreign,world,mf,20,200,1000);
    populate(uid,world,mu,10,300,2000);
    master=open_path(a,ma,"/dev/ptmx");CHECK(master>=0);
    CHECK(open_path(a,ma,"/dev/pts/0")==-13); /* locked */
    memset(ma+256,0,4);
    CHECK(invoke(a,16,(uint64_t)master,0x40045431U,BASE+256)==0);
    CHECK(open_path(foreign,mf,"/dev/pts/0")==-13);
    CHECK(invoke(foreign,4,BASE,BASE+128,0)==-2); /* no stat metadata leak */
    CHECK(open_path(uid,mu,"/dev/pts/0")==-13);
    slave=open_path(a,ma,"/dev/pts/0");CHECK(slave>=0);
    CHECK(invoke(a,3,(uint64_t)slave,0,0)==0);
    CHECK(invoke(a,3,(uint64_t)master,0,0)==0);
    CHECK(open_path(a,ma,"/dev/pts/0")==-13); /* no stale authorization */
    master=open_path(foreign,mf,"/dev/ptmx");CHECK(master>=0);
    CHECK(open_path(a,ma,"/dev/pts/0")==-13);
    CHECK(invoke(foreign,3,(uint64_t)master,0,0)==0);
    ryz_world_close(a,0);ryz_world_close(foreign,0);ryz_world_close(uid,0);
    free(world);free(a);free(foreign);free(uid);
    free(ma);free(mf);free(mu);
    puts("CLX06_PTY_NAMESPACE_UID_DENIAL_PASS");
    return 0;
}
