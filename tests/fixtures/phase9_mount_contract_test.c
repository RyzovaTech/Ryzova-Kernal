/* SPDX-License-Identifier: AGPL-3.0-only */
#define _GNU_SOURCE
#include "syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include "resource_posix.h"
typedef struct Fixture {ResourceHost host;unsigned int fail,oversize,opens,closes;} Fixture;
static int64_t callback(void *context,RyzFsCall *call)
{
    Fixture *f=context;int64_t result;
    if(call->operation==f->fail)return -5;
    if(call->operation==RYZ_FS_READ_OP && f->oversize)return (int64_t)call->size+1;
    result=resource_host_call(&f->host,call);
    if(call->operation==RYZ_FS_OPEN && result>=0)f->opens++;
    if(call->operation==RYZ_FS_CLOSE)f->closes++;
    return result;
}
#define CHECK(x) do{if(!(x)){fprintf(stderr,"contract line %d\n",__LINE__);return 1;}}while(0)
static int64_t call(RyzLinuxProcess *p,uint64_t nr,uint64_t a,uint64_t b,uint64_t c)
{RyzLinuxRegs r;memset(&r,0,sizeof r);r.rax=nr;r.rdi=a;r.rsi=b;r.rdx=c;return ryz_linux_syscall(p,&r);}
int main(int argc,char **argv)
{
    RyzLinuxWorld *w=calloc(1,sizeof(*w));RyzLinuxProcess *p=calloc(1,sizeof(*p));unsigned char memory[4096];
    Fixture fixture;RyzFsMount mount;RyzFsResources resources;int64_t fd,alias;unsigned int i,used;
    CHECK(argc==2 && w && p);memset(&fixture,0,sizeof fixture);CHECK(resource_host_open(&fixture.host,argv[1],NULL));CHECK(resource_host_allowed(&fixture.host,1));
    memset(&mount,0,sizeof mount);mount.path="/home/share";mount.rights=3;mount.call=callback;mount.context=&fixture;
    memset(&resources,0,sizeof resources);resources.mounts=&mount;resources.count=1;w->root_tree=1;w->resources=&resources;CHECK(ryz_resources_install(w));
    memset(memory,0,sizeof memory);memcpy(memory,"/home/share/file",17);memcpy(memory+256,"BAD",3);
    CHECK(!ryz_linux_process_init(p,1,1000,1000,1000,0x100000,memory,sizeof memory,NULL,NULL));ryz_world_attach(p,w);
    fixture.fail=RYZ_FS_OPEN;CHECK(call(p,2,0x100000,2,0)==-5);used=0;
    for(i=0;i<RYZ_WORLD_DESCRIPTIONS;i++)used+=w->descriptions[i].used!=0;
    CHECK(used==3 && fixture.opens==0 && fixture.closes==0);fixture.fail=0;
    fd=call(p,2,0x100000,2,0);CHECK(fd>=0 && fixture.opens==1);alias=call(p,32,(uint64_t)fd,0,0);CHECK(alias>=0);
    fixture.fail=RYZ_FS_WRITE_OP;CHECK(call(p,1,(uint64_t)fd,0x100100,3)==-5 && p->fds[fd].offset==0);fixture.fail=0;
    fixture.oversize=1;CHECK(call(p,0,(uint64_t)fd,0x100200,3)==-5 && p->fds[fd].offset==0 && w->resource_bytes==0);fixture.oversize=0;
    CHECK(call(p,0,(uint64_t)fd,0x100200,3)==3 && !memcmp(memory+512,"ori",3) && p->fds[alias].offset==3);
    CHECK(!call(p,3,(uint64_t)fd,0,0) && fixture.closes==0);
    w->resource_calls=RYZ_FS_CALLS;CHECK(call(p,0,(uint64_t)alias,0x100200,3)==-28);
    CHECK(!call(p,3,(uint64_t)alias,0,0) && fixture.closes==1);
    ryz_world_close(p,0);CHECK(fixture.opens==fixture.closes);resource_host_close(&fixture.host);free(p);free(w);
    puts("FS_CALLBACK_CONTRACT_OK");return 0;
}
