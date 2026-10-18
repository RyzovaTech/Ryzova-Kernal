/* SPDX-License-Identifier: AGPL-3.0-only */
#include "../ryzova/compat/linux/syscall.h"
#include "../ryzova/compat/linux/namespace.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CHECK(cond) do { if (!(cond)) { \
    fprintf(stderr,"FAIL at %d: %s\n",__LINE__,#cond); return 1; \
} } while (0)
struct Output {
    unsigned char contents[128];
    size_t used;
    int last_fd;
};
static int64_t sink(void *opaque, int fd, const unsigned char *b, size_t n)
{
    struct Output *o=(struct Output *)opaque;
    if (n > sizeof(o->contents)-o->used)
        return -1;
    memcpy(o->contents+o->used,b,n);
    o->used+=n;
    o->last_fd=fd;
    return (int64_t)n;
}
static int64_t call(RyzLinuxProcess *p, uint64_t nr, uint64_t a,
                    uint64_t b, uint64_t c)
{
    RyzLinuxRegs r={0};
    r.rax=nr; r.rdi=a; r.rsi=b; r.rdx=c;
    return ryz_linux_syscall(p,&r);
}
int main(void)
{
    RyzLinuxProcess p, p2, bad;
    struct Output out={0};
    unsigned char guest[4096]={0}, other[1024]={0};
    enum RyzLinuxNode node=RYZ_NS_NONE;
    int64_t fd;
    unsigned int i;
    char longpath[300];

    CHECK(ryz_linux_process_init(NULL,1,2,0,0,0x400000,guest,sizeof(guest),sink,&out)==-22);
    CHECK(ryz_linux_process_init(&bad,0,2,0,0,0x400000,guest,sizeof(guest),sink,&out)==-22);
    CHECK(ryz_linux_process_init(&bad,1,0,0,0,0x400000,guest,sizeof(guest),sink,&out)==-22);
    CHECK(ryz_linux_process_init(&bad,1,2,0,0,UINT64_MAX,guest,sizeof(guest),sink,&out)==-22);
    CHECK(ryz_linux_process_init(&p,11,1234,1001,1002,0x400000,
                                 guest,sizeof(guest),sink,&out)==0);
    CHECK(p.ns.namespace_id==11 && p.ns.uid==1001);
    CHECK(call(&p,39,0,0,0)==1234);
    CHECK(call(&p,186,0,0,0)==1234);
    CHECK(call(&p,102,0,0,0)==1001);
    CHECK(call(&p,104,0,0,0)==1002);
    CHECK(call(&p,999999,0,0,0)==-38);

    CHECK(ryz_linux_ns_resolve(&p.ns,"/dev/null",sizeof("/dev/null"),&node)==0);
    CHECK(node==RYZ_NS_DEV_NULL);
    CHECK(ryz_linux_ns_resolve(&p.ns,"/compat/linux/dev/zero",
            sizeof("/compat/linux/dev/zero"),&node)==0);
    CHECK(node==RYZ_NS_DEV_ZERO);
    CHECK(ryz_linux_ns_resolve(&p.ns,"/compat/linux/./proc/self",
            sizeof("/compat/linux/./proc/self"),&node)==0);
    CHECK(node==RYZ_NS_PROC_SELF);
    CHECK(ryz_linux_ns_resolve(&p.ns,"/tmp",sizeof("/tmp"),&node)==0);
    CHECK(node==RYZ_NS_TMP);
    CHECK(ryz_linux_ns_resolve(&p.ns,"/etc/passwd",sizeof("/etc/passwd"),&node)==-2);
    CHECK(ryz_linux_ns_resolve(&p.ns,"/tmp/../../dev/null",
            sizeof("/tmp/../../dev/null"),&node)==-13);
    CHECK(ryz_linux_ns_resolve(&p.ns,"/compat/linux/../dev/null",
            sizeof("/compat/linux/../dev/null"),&node)==-13);
    CHECK(ryz_linux_ns_resolve(&p.ns,"dev/null",sizeof("dev/null"),&node)==-13);
    CHECK(ryz_linux_ns_resolve(&p.ns,"/compat/linux",sizeof("/compat/linux"),&node)==-2);
    memset(longpath,'a',sizeof(longpath));
    longpath[0]='/';longpath[sizeof(longpath)-1]='\0';
    CHECK(ryz_linux_ns_resolve(&p.ns,longpath,sizeof(longpath),&node)==-36);
    CHECK(ryz_linux_ns_resolve(&p.ns,NULL,0,&node)==-22);

    memcpy(guest+512,"hello",5);
    CHECK(call(&p,1,1,0x400200,5)==5);
    CHECK(out.used==5 && memcmp(out.contents,"hello",5)==0 && out.last_fd==1);
    CHECK(call(&p,1,2,0x400200,5)==5 && out.last_fd==2);
    CHECK(call(&p,1,1,0x3fffff,5)==-14);
    CHECK(call(&p,1,1,UINT64_MAX-3,16)==-14);
    CHECK(call(&p,1,1,0x400000,65537)==-22);
    CHECK(call(&p,1,42,0x400200,5)==-9);
    CHECK(call(&p,0,1,0x400200,3)==-9);
    CHECK(call(&p,0,0,0x400200,3)==0);

    memcpy(guest,"/compat/linux/dev/zero",sizeof("/compat/linux/dev/zero"));
    fd=call(&p,257,(uint64_t)-100,0x400000,0);
    CHECK(fd==3);
    memset(guest+256,0xAA,16);
    CHECK(call(&p,0,(uint64_t)fd,0x400100,16)==16);
    for(i=0;i<16;++i) CHECK(guest[256+i]==0);
    CHECK(call(&p,1,(uint64_t)fd,0x400200,5)==-9);
    CHECK(call(&p,3,(uint64_t)fd,0,0)==0);
    CHECK(call(&p,0,(uint64_t)fd,0x400100,16)==-9);
    CHECK(call(&p,3,(uint64_t)fd,0,0)==-9);

    memcpy(guest,"/dev/null",sizeof("/dev/null"));
    fd=call(&p,257,(uint64_t)-100,0x400000,1);
    CHECK(fd==3);
    CHECK(call(&p,1,(uint64_t)fd,0x400200,5)==5);
    CHECK(call(&p,0,(uint64_t)fd,0x400100,5)==-9);
    CHECK(call(&p,3,(uint64_t)fd,0,0)==0);
    fd=call(&p,257,(uint64_t)-100,0x400000,0);
    CHECK(fd==3);
    CHECK(call(&p,0,(uint64_t)fd,0x400100,5)==0);
    CHECK(call(&p,3,(uint64_t)fd,0,0)==0);

    CHECK(call(&p,257,(uint64_t)-100,0x400000,2)==-22);
    CHECK(call(&p,257,(uint64_t)-100,0x400000,0x40)==-22);
    CHECK(call(&p,257,1,0x400000,0)==-22);
    CHECK(call(&p,257,(uint64_t)-100,0x3ffffe,0)==-14);
    memset(guest+4090,'a',6);
    CHECK(call(&p,257,(uint64_t)-100,0x400ffa,0)==-14);
    memcpy(guest,"/etc/shadow",sizeof("/etc/shadow"));
    CHECK(call(&p,257,(uint64_t)-100,0x400000,0)==-2);
    memcpy(guest,"/proc/self",sizeof("/proc/self"));
    CHECK(call(&p,257,(uint64_t)-100,0x400000,0)==-1);

    memcpy(guest,"/dev/zero",sizeof("/dev/zero"));
    for(i=0;i<RYZ_LINUX_FD_MAX-3;++i)
        CHECK(call(&p,257,(uint64_t)-100,0x400000,0)==(int64_t)i+3);
    CHECK(call(&p,257,(uint64_t)-100,0x400000,0)==-24);
    CHECK(ryz_linux_process_init(&p2,22,555,2000,2000,
                                 0x600000,other,sizeof(other),NULL,NULL)==0);
    CHECK(p2.ns.namespace_id!=p.ns.namespace_id);
    CHECK(call(&p2,39,0,0,0)==555);
    CHECK(call(&p2,0,3,0x600000,1)==-9);
    CHECK(call(&p2,1,1,0x600000,1)==-5);
    CHECK(call(&p,231,258,0,0)==0);
    CHECK(p.exited==1 && p.exit_status==2);
    CHECK(call(&p,39,0,0,0)==-1);
    CHECK(call(&p2,60,17,0,0)==0 && p2.exit_status==17);
    printf("PHASE5_2_3_VIRTUAL_RUNTIME_ALL_TESTS_PASS\n");
    return 0;
}
