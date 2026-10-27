/* SPDX-License-Identifier: AGPL-3.0-only */
/* Balance core allocations, including every allocation failure on exec paths. */
#include "../ryzova/compat/linux/jobs.h"
#include <stdio.h>
#include <stdlib.h>
void *__real_malloc(size_t);
void __real_free(void *);
static void *live[64];
static size_t active,calls,fail_at;
static unsigned char output[65536];
void *__wrap_malloc(size_t n)
{
    void *p;unsigned int i;
    calls++;if(fail_at && calls==fail_at)return NULL;
    p=__real_malloc(n);if(!p)return NULL;
    for(i=0;i<64;i++)if(!live[i]){live[i]=p;active++;return p;}
    abort();
}
void __wrap_free(void *p)
{
    unsigned int i;if(!p)return;
    for(i=0;i<64;i++)if(live[i]==p){live[i]=NULL;active--;__real_free(p);return;}
    fprintf(stderr,"free without live allocation\n");abort();
}
static int64_t sink(void *context,int fd,const unsigned char *bytes,size_t size)
{
    (void)context;(void)fd;(void)bytes;return (int64_t)size;
}
int main(int argc,char **argv)
{
    FILE *in;long length;unsigned char *image,*arena;size_t i,k,baseline,start,total;
    RyzProcessArgs args;RyzJobConfig config;RyzLinuxExec grant;RyzLinuxFiles files;RyzVmResult result;
    const char *av[]={"/job",NULL,"allocation-check"},*ev[]={"FLEX_MODE=test"};
    const char *modes[]={"private","vfork","pipe","exec","vfork-exec","descriptions","identity","quota","exec-quota","deadlock","nonblock","denied","capacity","io-quota","console","offset","wait-errors","fault-child"};
    if(argc!=2)return 64;
    in=fopen(argv[1],"rb");if(!in || fseek(in,0,SEEK_END))return 65;
    length=ftell(in);if(length<=0 || fseek(in,0,SEEK_SET))return 65;
    image=malloc((size_t)length);arena=malloc(RYZ_PROCESS_MAX_SPAN);if(!image || !arena)return 65;
    if(fread(image,1,(size_t)length,in)!=(size_t)length)return 65;
    fclose(in);grant.path="/job";grant.image=image;grant.size=(size_t)length;config.execs=&grant;config.exec_count=1;
    args.argv=av;args.argc=3;args.envp=ev;args.envc=1;
    memset(&files,0,sizeof(files));files.input=(const unsigned char *)"abcdefgh\n";files.input_size=9;files.output=output;files.output_capacity=sizeof(output);
    baseline=active;
    for(i=0;i<sizeof(modes)/sizeof(modes[0]);i++){
        av[1]=modes[i];start=calls;
        ryz_vm_run_jobs_elf(image,(size_t)length,arena,RYZ_PROCESS_MAX_SPAN,&files,&args,&config,sink,NULL,&result);
        if(active!=baseline){fprintf(stderr,"allocation leak after %s\n",modes[i]);return 1;}
        total=calls-start;
        if(strcmp(modes[i],"exec")!=0 && strcmp(modes[i],"vfork-exec")!=0 && strcmp(modes[i],"private")!=0)continue;
        for(k=1;k<=total;k++){
            fail_at=calls+k;
            ryz_vm_run_jobs_elf(image,(size_t)length,arena,RYZ_PROCESS_MAX_SPAN,&files,&args,&config,sink,NULL,&result);
            fail_at=0;
            if(active!=baseline){fprintf(stderr,"allocation leak after failed %s allocation %lu\n",modes[i],(unsigned long)k);return 1;}
        }
    }
    free(image);free(arena);if(active)return 1;
    puts("FLEX_JOBS_ALLOCATION_BALANCE_PASS");return 0;
}
